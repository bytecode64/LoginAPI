from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import requests
from flask_cors import CORS  # Importing CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

app.config['SECRET_KEY'] = 'supersecretkey'

# Base URL for the API
BASE_URL = 'https://6787c081c4a42c9161081811.mockapi.io/api/v1/users/accounts'

# Register route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    # Fetch all users from the mock API and check if the username already exists
    response = requests.get(BASE_URL)
    
    if response.status_code == 200:
        users = response.json()
        # Check if the username already exists by iterating through users
        for user in users:
            if user['name'] == username:
                return jsonify({'message': 'User already exists!'}), 409
    
    # If the username does not exist, create a new user and store in the API
    hashed_password = generate_password_hash(password)
    user_data = {'name': username, 'password': hashed_password}
    
    # Make the POST request to the API to register the new user
    response = requests.post(BASE_URL, json=user_data)

    if response.status_code == 201:
        return jsonify({'message': 'User registered successfully!'}), 201
    else:
        return jsonify({'message': 'Failed to register user!'}), 500

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    # Fetch all users from the mock API
    response = requests.get(BASE_URL)
    if response.status_code != 200:
        return jsonify({'message': 'Failed to fetch users!'}), 500
    
    users = response.json()

    # Check if the username exists in the fetched users
    user = next((user for user in users if user['name'] == username), None)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Generate JWT token
    token = jwt.encode(
        {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return jsonify({'message': 'Login successful!', 'token': token}), 200

# Protected route (example)
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 403

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': f'Welcome {data["username"]}!'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)
