"""
Run the web application
"""

from scanner.web.app import create_app
import os

if __name__ == '__main__':
    app = create_app()
    
    # Configuration
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    print(f"""
    ╔════════════════════════════════════════════╗
    ║   WebSecV - Web Vulnerability Scanner     ║
    ╚════════════════════════════════════════════╝
    
    Starting web application...
    Server: http://{host}:{port}
    Debug: {debug}
    
    Press Ctrl+C to stop
    """)
    
    app.run(host=host, port=port, debug=debug)

