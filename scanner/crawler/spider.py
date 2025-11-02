"""
Web Spider/Crawler implementation
"""

import asyncio
import logging
from typing import Dict, List, Set, Any, Optional
from urllib.parse import urljoin, urlparse
import time
import re

from bs4 import BeautifulSoup
import aiohttp
from playwright.async_api import async_playwright, Browser, Page

from scanner.core.interfaces import ICrawler, HttpRequest, HttpMethod
from scanner.core.config import CrawlerConfig
from scanner.core.storage import Storage

logger = logging.getLogger(__name__)


class WebSpider(ICrawler):
    """Web spider implementation with SPA support"""
    
    def __init__(self, config: Optional[CrawlerConfig] = None, storage: Optional[Storage] = None):
        self.config = config or CrawlerConfig()
        self.storage = storage
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.browser: Optional[Browser] = None
        self.playwright = None
    
    async def _init_browser(self):
        """Initialize headless browser if needed"""
        if self.config.use_headless_browser:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)
    
    async def _close_browser(self):
        """Close browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    def crawl(self, start_url: str, max_depth: int = None) -> Dict[str, Any]:
        """Crawl starting from start_url (synchronous wrapper)"""
        max_depth = max_depth or self.config.max_depth
        return asyncio.run(self._crawl_async(start_url, max_depth))
    
    async def _crawl_async(self, start_url: str, max_depth: int) -> Dict[str, Any]:
        """Async crawl implementation"""
        await self._init_browser()
        
        try:
            queue: List[tuple[str, int]] = [(start_url, 0)]  # (url, depth)
            
            while queue and len(self.visited_urls) < self.config.max_pages:
                url, depth = queue.pop(0)
                
                if depth > max_depth:
                    continue
                
                if url in self.visited_urls:
                    continue
                
                if not self._should_crawl(url):
                    continue
                
                try:
                    logger.info(f"Crawling {url} (depth: {depth})")
                    
                    # Fetch page
                    if self.config.use_headless_browser:
                        endpoints, links = await self._crawl_with_browser(url)
                    else:
                        endpoints, links = await self._crawl_http(url)
                    
                    self.visited_urls.add(url)
                    self.discovered_endpoints.add(url)
                    self.discovered_endpoints.update(endpoints)
                    
                    # Add discovered links to queue
                    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    for link in links:
                        absolute_link = urljoin(base_url, link)
                        if self._should_follow_link(absolute_link, start_url):
                            queue.append((absolute_link, depth + 1))
                    
                    # Rate limiting
                    await asyncio.sleep(self.config.delay_between_requests)
                
                except Exception as e:
                    logger.error(f"Error crawling {url}: {e}")
            
            return {
                "visited_urls": list(self.visited_urls),
                "discovered_endpoints": list(self.discovered_endpoints),
                "total_pages": len(self.visited_urls),
            }
        
        finally:
            await self._close_browser()
    
    async def _crawl_http(self, url: str) -> tuple[List[str], List[str]]:
        """Crawl using HTTP requests"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent}
        
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url) as response:
                text = await response.text()
                return self._extract_endpoints_and_links(text, url)
    
    async def _crawl_with_browser(self, url: str) -> tuple[List[str], List[str]]:
        """Crawl using headless browser (for SPAs)"""
        if not self.browser:
            await self._init_browser()
        
        page = await self.browser.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.config.timeout * 1000)
            
            # Wait for SPA to load if configured
            if self.config.wait_for_spa:
                await asyncio.sleep(self.config.spa_wait_time / 1000)
            
            # Get page content and JavaScript
            html = await page.content()
            endpoints, links = self._extract_endpoints_and_links(html, url)
            
            # Extract endpoints from JavaScript
            js_endpoints = await self._extract_js_endpoints(page)
            endpoints.extend(js_endpoints)
            
            return endpoints, links
        
        finally:
            await page.close()
    
    def _extract_endpoints_and_links(self, html: str, base_url: str) -> tuple[List[str], List[str]]:
        """Extract endpoints and links from HTML"""
        soup = BeautifulSoup(html, 'lxml')
        endpoints = []
        links = []
        
        # Extract links
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            if href.startswith('http://') or href.startswith('https://'):
                links.append(href)
            elif href.startswith('/'):
                links.append(href)
            elif not href.startswith('#') and not href.startswith('javascript:'):
                links.append(href)
        
        # Extract form actions
        for form in soup.find_all('form', action=True):
            endpoints.append(form['action'])
        
        # Extract API endpoints from data attributes
        for tag in soup.find_all(attrs={'data-api': True}):
            endpoints.append(tag['data-api'])
        
        # Extract from script tags (inline)
        for script in soup.find_all('script'):
            if script.string:
                endpoints.extend(self._extract_urls_from_text(script.string))
        
        return endpoints, links
    
    async def _extract_js_endpoints(self, page: Page) -> List[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = []
        
        try:
            # Inject script to extract fetch/XHR calls
            js_code = """
            () => {
                const endpoints = new Set();
                const originalFetch = window.fetch;
                window.fetch = function(...args) {
                    endpoints.add(args[0]);
                    return originalFetch.apply(this, args);
                };
                const originalXHR = window.XMLHttpRequest.prototype.open;
                window.XMLHttpRequest.prototype.open = function(method, url) {
                    endpoints.add(url);
                    return originalXHR.apply(this, arguments);
                };
                return Array.from(endpoints);
            }
            """
            js_endpoints = await page.evaluate(js_code)
            endpoints.extend(js_endpoints)
        
        except Exception as e:
            logger.debug(f"Error extracting JS endpoints: {e}")
        
        return endpoints
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text using regex"""
        # Common URL patterns
        patterns = [
            r'https?://[^\s\'"<>]+',
            r'/api/[^\s\'"<>]+',
            r'["\']([^"\']*\/api\/[^"\']*)["\']',
        ]
        
        urls = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            urls.extend(matches)
        
        return urls
    
    def _should_crawl(self, url: str) -> bool:
        """Check if URL should be crawled"""
        parsed = urlparse(url)
        
        # Check robots.txt (simplified)
        if self.config.respect_robots_txt:
            # TODO: Implement robots.txt checking
            pass
        
        # Skip non-HTTP(S) URLs
        if parsed.scheme not in ['http', 'https']:
            return False
        
        return True
    
    def _should_follow_link(self, url: str, start_url: str) -> bool:
        """Check if link should be followed"""
        parsed = urlparse(url)
        start_parsed = urlparse(start_url)
        
        # Don't follow external links if configured
        if not self.config.follow_external_links:
            if parsed.netloc != start_parsed.netloc:
                return False
        
        # Skip common non-content URLs
        skip_extensions = ['.pdf', '.jpg', '.png', '.gif', '.css', '.js', '.ico']
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        return True
    
    def discover_endpoints(self, url: str) -> List[str]:
        """Discover endpoints from a URL"""
        result = self.crawl(url, max_depth=1)
        return result.get("discovered_endpoints", [])

