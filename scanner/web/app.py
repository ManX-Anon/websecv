"""
Flask web application
"""

from flask import Flask, render_template
from flask_cors import CORS
from scanner.database.connection import init_db
from scanner.database.models import db
from .routes import api_bp
import os

def create_app(config=None):
    """Create Flask application"""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///scanner.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # CORS
    CORS(app)
    
    # Initialize database
    db.init_app(app)
    with app.app_context():
        db.create_all()
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Main routes
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/scans')
    def scans():
        return render_template('scans.html')
    
    @app.route('/scan/<int:scan_id>')
    def scan_detail(scan_id):
        return render_template('scan_detail.html', scan_id=scan_id)
    
    @app.route('/vulnerabilities')
    def vulnerabilities():
        return render_template('vulnerabilities.html')
    
    @app.route('/proxy')
    def proxy():
        return render_template('proxy.html')
    
    @app.route('/repeater')
    def repeater():
        return render_template('repeater.html')
    
    @app.route('/intruder')
    def intruder():
        return render_template('intruder.html')
    
    return app

