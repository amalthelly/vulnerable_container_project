from flask import flask, request, jsonify
import os
import subprocess
import yaml

app = flask(__name__)

# Hardcoded secret (vulnerability!)

API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
DB_PASSWORD = "admin123"


@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "version": "1.0.0"
    })

@app.route('/api/search')
def search():
    # Command injection vulnerability!
    query = request.args.get('q', '')
    result = subprocess.check_output(f'echo {query}', shell=True)
    return result

@app.route('/api/config')
def get_config():
    # Exposing sensitive info
    return jsonify({
        "api_key": API_KEY,
        "database": {
            "host": "db.internal",
            "password": DB_PASSWORD
        }
    })

@app.route('/api/yaml')
def parse_yaml():
    # Unsafe YAML parsing (deserialization vulnerability)
    data = request.args.get('data', '')
    parsed = yaml.load(data, Loader=yaml.Loader)
    return jsonify(parsed)

if __name__ == '__main__':
    # Running on all interfaces (security issue)
    # Debug mode enabled in production (security issue)
    app.run(host='0.0.0.0', port=5000, debug=True)



