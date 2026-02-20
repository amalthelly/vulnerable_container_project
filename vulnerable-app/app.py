from flask import Flask, request, jsonify
import os
import logging
import yaml

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load secrets from environment variables
API_KEY = os.environ.get('API_KEY', '')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')

if not API_KEY or not DB_PASSWORD:
    logger.error("Required environment variables not set!")

@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "version": "2.0.0"
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200

@app.route('/api/search')
def search():
    # Fixed: Input validation, no shell execution
    query = request.args.get('q', '')
    
    # Validate input
    if not query.isalnum():
        return jsonify({"error": "Invalid query"}), 400
    
    # Safe processing without shell
    return jsonify({"query": query, "results": []})

@app.route('/api/config')
def get_config():
    # Fixed: Never expose secrets
    return jsonify({
        "database": {
            "host": "db.internal"
            # Password not exposed
        },
        "version": "2.0.0"
    })

@app.route('/api/yaml')
def parse_yaml():
    # Fixed: Use SafeLoader
    data = request.args.get('data', '')
    try:
        parsed = yaml.load(data, Loader=yaml.SafeLoader)
        return jsonify(parsed)
    except yaml.YAMLError as e:
        return jsonify({"error": "Invalid YAML"}), 400

if __name__ == '__main__':
    # Fixed: Not running in debug mode
    # Use proper WSGI server in production
    app.run(host='0.0.0.0', port=5000, debug=False)