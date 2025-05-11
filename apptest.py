# fake_server.py
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/login', methods=['POST', 'GET'])
def login():
    print('Login request:', request.form)
    return jsonify(status="ok", message="Login accepted")

app.run(host='0.0.0.0', port=8888)

