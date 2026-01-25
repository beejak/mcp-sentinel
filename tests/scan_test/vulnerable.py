
import os
from flask import Flask

app = Flask(__name__)

# Vulnerability: Hardcoded secret
SECRET_KEY = "12345"

@app.route('/')
def index():
    return "Hello World"

if __name__ == '__main__':
    # Vulnerability: Debug mode enabled
    app.run(debug=True)
