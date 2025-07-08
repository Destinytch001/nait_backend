import bcrypt
import os
from flask import Flask, request, jsonify, session
from flask_cors import CORS, cross_origin
from datetime import datetime, date, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv
from functools import wraps
from flask_socketio import SocketIO, emit

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Configure CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize SocketIO with threading (most compatible)
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='threading',
                   logger=False,
                   engineio_logger=False)

# MongoDB setup
client = MongoClient(os.getenv('MONGO_URI'))
db = client['naits_db']
users = db.users
logins = db.user_logins
sessions = db.sessions

# Authentication helpers
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_current_user_id():
    return session.get('user_id')

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        try:
            sessions.update_one(
                {'user_id': ObjectId(session['user_id'])},
                {'$set': {
                    'socket_id': request.sid,
                    'connected': True,
                    'last_active': datetime.now()
                }},
                upsert=True
            )
        except Exception as e:
            print(f"Socket connection error: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        try:
            sessions.delete_one({'socket_id': request.sid})
        except Exception as e:
            print(f"Socket disconnection error: {str(e)}")

# API Routes
@app.route('/register', methods=['POST'])
@cross_origin()
def register():
    data = request.get_json() or {}
    required = ['firstName', 'lastName', 'whatsapp', 'nickname', 'level', 'department', 'password']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'status': 'error', 'message': f'Missing: {", ".join(missing)}'}), 400

    if users.find_one({'$or': [{'nickname': data['nickname']}, {'whatsapp': data['whatsapp']}]}):
        return jsonify({'status': 'error', 'message': 'Already registered'}), 409

    pw_hash = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    user = {
        'first_name': data['firstName'],
        'last_name': data['lastName'],
        'whatsapp': data['whatsapp'],
        'nickname': data['nickname'],
        'level': data['level'],
        'department': data['department'],
        'password': pw_hash,
        'created_at': datetime.now(),
        'last_login': None,
        'last_logout': None
    }
    users.insert_one(user)
    return jsonify({'status': 'success', 'message': 'Registered'})

@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    data = request.get_json() or {}
    user = users.find_one({'nickname': data.get('nickname')})

    if user and bcrypt.checkpw(data.get('password', '').encode(), user['password'].encode()):
        now = datetime.now()
        users.update_one({'_id': user['_id']}, {'$set': {'last_login': now}})
        logins.insert_one({
            'user_id': user['_id'],
            'login_time': now
        })
        
        session['user_id'] = str(user['_id'])
        return jsonify({
            'status': 'success',
            'user': {
                'id': str(user['_id']),
                'nickname': user['nickname'],
                'last_login': now.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@cross_origin()
@login_required
def logout():
    user_id = get_current_user_id()
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({'status': 'error', 'message': 'Invalid user ID'}), 400

    now = datetime.now()
    users.update_one({'_id': user_oid}, {'$set': {'last_logout': now}})
    session.pop('user_id', None)
    return jsonify({'status': 'success', 'message': 'Logged out'})

@app.route('/api/current-user', methods=['GET'])
@cross_origin()
@login_required
def get_current_user():
    user_id = get_current_user_id()
    try:
        user = users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        user['id'] = str(user['_id'])
        return jsonify(user)
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400
# ... (keep all your previous imports and setup code the same)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    # Development mode (for local testing)
    socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)
