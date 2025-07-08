import bcrypt
import os
from dateutil.relativedelta import relativedelta
from flask import Flask, request, jsonify, session, url_for, render_template, send_from_directory
from flask_cors import CORS, cross_origin
from datetime import datetime, date, timedelta
import requests
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
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

# Initialize SocketIO with production settings
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='eventlet',
                   engineio_logger=False,
                   logger=False)

# File upload configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp4', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# MongoDB setup
client = MongoClient(os.getenv('MONGO_URI'))
db = client['naits_db']
users = db.users
logins = db.user_logins
sessions = db.sessions  # For tracking active sessions
announcements = db.announcements
ads = db.ads
resources = db.resources
messages = db.messages

# Security headers
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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

@app.route('/users', methods=['GET'])
@cross_origin()
@login_required
def get_users():
    user_list = []
    for user in users.find({}, {'password': 0}):
        user['id'] = str(user['_id'])
        user['created_at'] = user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        user['last_login'] = user['last_login'].strftime('%Y-%m-%d %H:%M:%S') if user.get('last_login') else ''
        del user['_id']
        user_list.append(user)
    return jsonify(user_list)

@app.route('/update_user', methods=['PUT'])
@cross_origin()
@login_required
def update_user():
    data = request.get_json() or {}
    orig = data.get('nickname')
    new_nick = data.get('nicknameNew')

    user = users.find_one({'nickname': orig})
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    update_data = {}
    mapping = {
        'firstName': 'first_name',
        'lastName': 'last_name',
        'whatsapp': 'whatsapp',
        'level': 'level',
        'department': 'department'
    }

    for k, col in mapping.items():
        if data.get(k):
            update_data[col] = data[k]

    if new_nick:
        update_data['nickname'] = new_nick

    if data.get('password'):
        pwd_h = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
        update_data['password'] = pwd_h

    users.update_one({'_id': user['_id']}, {'$set': update_data})
    return jsonify({'status': 'success', 'message': 'User updated'})

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
        
        # Store session in database
        sessions.insert_one({
            'user_id': user['_id'],
            'session_id': session.sid,
            'socket_id': request.sid,
            'created_at': now,
            'connected': True
        })
        
        # Set Flask session
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
    
    # Remove session tracking
    sessions.delete_one({'session_id': session.sid})
    
    # Clear session
    session.pop('user_id', None)
    
    return jsonify({'status': 'success', 'message': 'Logged out'})

@app.route('/api/current-user', methods=['GET'])
@cross_origin()
@login_required
def get_current_user():
    user_id = get_current_user_id()
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({'status': 'error', 'message': 'Invalid user ID'}), 400

    user = users.find_one({'_id': user_oid}, {'password': 0})
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    user['id'] = str(user['_id'])
    user['created_at'] = user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    user['last_login'] = user['last_login'].strftime('%Y-%m-%d %H:%M:%S') if user.get('last_login') else ''
    del user['_id']
    
    return jsonify(user)

@app.route('/delete_account', methods=['POST'])
@cross_origin()
@login_required
def delete_account():
    data = request.get_json() or {}
    nick = data.get('nickname')
    if not nick:
        return jsonify({'status': 'error', 'message': 'Nickname required'}), 400

    user = users.find_one({'nickname': nick})
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    try:
        # Get all active sessions for this user
        active_sessions = list(sessions.find({'user_id': user['_id'], 'connected': True}))
        
        # Delete user data
        users.delete_one({'_id': user['_id']})
        logins.delete_many({'user_id': user['_id']})
        sessions.delete_many({'user_id': user['_id']})
        
        # Notify all active sessions via WebSocket
        for sess in active_sessions:
            if sess.get('socket_id'):
                socketio.emit('account_deleted', {
                    'user_id': str(user['_id']),
                    'message': 'Your account has been deleted by admin'
                }, room=sess['socket_id'])
        
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/dashboard_stats', methods=['GET'])
@cross_origin()

def dashboard_stats():
    today = datetime.combine(date.today(), datetime.min.time())
    tomorrow = today + timedelta(days=1)

    stats = {
        'total_users': users.count_documents({}),
        'logins_today': logins.count_documents({'login_time': {'$gte': today, '$lt': tomorrow}}),
        'failed_logins_today': 0,  # Not implemented in original
        'signups_today': users.count_documents({'created_at': {'$gte': today, '$lt': tomorrow}}),
        'active_users': users.count_documents({
            'last_login': {'$ne': None},
            '$or': [
                {'last_logout': None},
                {'$expr': {'$gt': ['$last_login', '$last_logout']}}
            ]
        }),
        'message_count': messages.count_documents({}),
        'ad_count': ads.count_documents({}),
        'resource_count': resources.count_documents({}),
        'announcement_count': announcements.count_documents({}),
        'department_counts': {},
        'level_counts': {},
        'recent_events': [],
        'last_updated': datetime.utcnow().isoformat() + 'Z'
    }

    # Department counts
    dept_counts = users.aggregate([
        {'$group': {'_id': '$department', 'count': {'$sum': 1}}}
    ])
    for dept in dept_counts:
        stats['department_counts'][dept['_id']] = dept['count']

    # Level counts
    level_counts = users.aggregate([
        {'$group': {'_id': '$level', 'count': {'$sum': 1}}}
    ])
    for level in level_counts:
        stats['level_counts'][level['_id']] = level['count']

    # Recent events
    recent_logins = logins.aggregate([
        {'$lookup': {
            'from': 'users',
            'localField': 'user_id',
            'foreignField': '_id',
            'as': 'user'
        }},
        {'$unwind': '$user'},
        {'$sort': {'login_time': -1}},
        {'$limit': 10},
        {'$project': {
            'nickname': '$user.nickname',
            'login_time': 1
        }}
    ])

    stats['recent_events'] = [
        {
            'timestamp': login['login_time'].strftime('%Y-%m-%d %H:%M:%S'),
            'description': f"{login['nickname']} logged in"
        }
        for login in recent_logins
    ]

    return jsonify(stats)

@app.route('/logins_timeseries')
@cross_origin()

def logins_timeseries():
    days = int(request.args.get('days', 7))
    labels = []
    counts = []

    for i in range(days-1, -1, -1):
        day = date.today() - timedelta(days=i)
        start = datetime.combine(day, datetime.min.time())
        end = start + timedelta(days=1)
        
        count = logins.count_documents({
            'login_time': {'$gte': start, '$lt': end}
        })
        
        labels.append(day.strftime('%Y-%m-%d'))
        counts.append(count)

    return jsonify({'dates': labels, 'counts': counts})

@app.route('/add_announcement', methods=['POST'])
@cross_origin()

def add_announcement():
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    message = data.get('message', '').strip()

    if not title or not message:
        return jsonify({
            'status': 'error',
            'message': 'Title and message are required'
        }), 400

    announcements.insert_one({
        'title': title,
        'message': message,
        'date_posted': datetime.now(),
        'is_new': False
    })

    return jsonify({
        'status': 'success',
        'message': 'Announcement posted'
    })

@app.route('/announcements', methods=['GET'])
@cross_origin()

def get_announcements():
    announcement_list = []
    for ann in announcements.find().sort('date_posted', -1):
        ann['id'] = str(ann['_id'])
        ann['date'] = ann['date_posted'].strftime('%B %d, %Y')
        ann['created_at'] = ann['date_posted'].strftime('%Y-%m-%d %H:%M:%S')
        del ann['_id']
        announcement_list.append(ann)
    return jsonify(announcement_list)

@app.route('/api/announcements', methods=['GET'])
@cross_origin()

def api_list_announcements():
    announcement_list = []
    for ann in announcements.find().sort('date_posted', -1):
        ann['id'] = str(ann['_id'])
        ann['date'] = ann['date_posted'].strftime('%B %d, %Y')
        del ann['_id']
        announcement_list.append(ann)
    return jsonify(announcement_list)

@app.route('/api/announcements', methods=['POST'])
@cross_origin()

def api_create_announcement():
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    message = data.get('message', '').strip()
    is_new = bool(data.get('isNew'))

    if not (title and message):
        return jsonify({'status': 'error', 'message': 'Title and message are required'}), 400

    announcements.insert_one({
        'title': title,
        'message': message,
        'date_posted': datetime.now(),
        'is_new': is_new
    })
    return jsonify({'status': 'success'}), 201

@app.route('/api/announcements/<ann_id>', methods=['GET'])
@cross_origin()

def api_get_announcement(ann_id):
    try:
        ann = announcements.find_one({'_id': ObjectId(ann_id)})
        if not ann:
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        
        ann['id'] = str(ann['_id'])
        ann['date'] = ann['date_posted'].strftime('%B %d, %Y')
        del ann['_id']
        return jsonify(ann), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/announcements/<ann_id>', methods=['DELETE'])
@cross_origin()

def api_delete_announcement(ann_id):
    try:
        result = announcements.delete_one({'_id': ObjectId(ann_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        return jsonify({'status': 'success'})
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/announcements/<ann_id>', methods=['PUT'])
@cross_origin()

def api_update_announcement(ann_id):
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    message = data.get('message', '').strip()
    
    if not title or not message:
        return jsonify({'status': 'error', 'message': 'Title and message are required'}), 400

    update_data = {
        'title': title,
        'message': message
    }

    if 'isNew' in data:
        update_data['is_new'] = bool(data['isNew'])

    try:
        result = announcements.update_one(
            {'_id': ObjectId(ann_id)},
            {'$set': update_data}
        )
        
        if result.matched_count == 0:
            return jsonify({'status': 'error', 'message': 'Announcement not found'}), 404
            
        return jsonify({'status': 'success', 'message': 'Announcement updated'}), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

def cleanup_expired_ads():
    now = datetime.now()
    result = ads.delete_many({'expires_at': {'$lte': now}})
    return result.deleted_count

@app.route('/api/ads', methods=['POST'])
@cross_origin()

def api_create_ad():
    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
    link_url = request.form.get('link_url', '').strip()
    badge = request.form.get('badge_label', '').strip()
    price = request.form.get('price', '').strip()
    posted_by = request.form.get('posted_by', '').strip()
    image_file = request.files.get('image')
    value_raw = request.form.get('duration_value', '').strip()
    unit = request.form.get('duration_unit', '').strip()

    missing = [f for f in ('title', 'message', 'link_url', 'price', 'posted_by') if not locals()[f]]
    if not image_file or image_file.filename == '':
        missing.append('image')
    if not value_raw or not unit:
        missing.append('duration')
    if missing:
        return jsonify({'status': 'error', 'message': f"Missing: {', '.join(missing)}"}), 400

    try:
        value = int(value_raw)
        if value < 1:
            raise ValueError
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid duration value; must be a positive integer'}), 400

    if not allowed_file(image_file.filename):
        return jsonify({'status': 'error', 'message': 'Invalid image type'}), 400

    upload_result = cloudinary.uploader.upload(
        image_file,
        resource_type='auto',
        folder='ads'
    )
    image_url = upload_result['secure_url']

    now = datetime.utcnow()
    if unit == 'seconds':
        expires_at = now + timedelta(seconds=value)
    elif unit == 'minutes':
        expires_at = now + timedelta(minutes=value)
    elif unit == 'hours':
        expires_at = now + timedelta(hours=value)
    elif unit == 'days':
        expires_at = now + timedelta(days=value)
    elif unit == 'years':
        expires_at = now + relativedelta(years=value)
    else:
        return jsonify({'status': 'error', 'message': 'Invalid duration unit'}), 400

    ad = {
        'title': title,
        'message': message,
        'image_url': image_url,
        'link_url': link_url,
        'badge_label': badge,
        'price': price,
        'posted_by': posted_by,
        'date_posted': now,
        'expires_at': expires_at
    }
    result = ads.insert_one(ad)
    return jsonify({'status': 'success', 'id': str(result.inserted_id)}), 201

@app.route('/api/ads/<ad_id>', methods=['PUT'])
@cross_origin()

def api_update_ad(ad_id):
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    message = data.get('message', '').strip()
    link_url = data.get('link_url', '').strip()
    badge = data.get('badge_label', '').strip()
    price = data.get('price', '').strip()
    posted_by = data.get('posted_by', '').strip()

    expires_at = None
    if 'duration_value' in data and 'duration_unit' in data:
        try:
            value = int(data['duration_value'])
            if value < 1:
                raise ValueError
        except ValueError:
            return jsonify({'error': 'Invalid duration value'}), 400

        unit = data['duration_unit']
        now = datetime.utcnow()
        if unit == 'seconds':
            expires_at = now + timedelta(seconds=value)
        elif unit == 'minutes':
            expires_at = now + timedelta(minutes=value)
        elif unit == 'hours':
            expires_at = now + timedelta(hours=value)
        elif unit == 'days':
            expires_at = now + timedelta(days=value)
        elif unit == 'years':
            expires_at = now + relativedelta(years=value)
        else:
            return jsonify({'error': 'Invalid duration unit'}), 400

    if not all([title, message, link_url, price, posted_by]):
        return jsonify({'error': 'Missing required fields'}), 400

    update_data = {
        'title': title,
        'message': message,
        'link_url': link_url,
        'badge_label': badge,
        'price': price,
        'posted_by': posted_by
    }

    if expires_at:
        update_data['expires_at'] = expires_at

    try:
        result = ads.update_one(
            {'_id': ObjectId(ad_id)},
            {'$set': update_data}
        )
        if result.matched_count == 0:
            return jsonify({'status': 'error', 'message': 'Ad not found'}), 404
        return jsonify({'status': 'updated'}), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/ads', methods=['GET'])
@cross_origin()

def api_get_ads():
    cleanup_expired_ads()
    now = datetime.utcnow()
    ad_list = []
    for ad in ads.find({'expires_at': {'$gt': now}}).sort('date_posted', -1):
        ad['id'] = str(ad['_id'])
        ad['date_posted'] = ad['date_posted'].isoformat()
        ad['expires_at'] = ad['expires_at'].isoformat()
        del ad['_id']
        ad_list.append(ad)
    return jsonify(ad_list), 200

@app.route('/api/ads/<ad_id>', methods=['GET'])
@cross_origin()

def api_get_ad(ad_id):
    cleanup_expired_ads()
    try:
        ad = ads.find_one({'_id': ObjectId(ad_id)})
        if not ad:
            return jsonify({'error': 'Not found'}), 404
        
        ad['id'] = str(ad['_id'])
        ad['date_posted'] = ad['date_posted'].isoformat()
        ad['expires_at'] = ad['expires_at'].isoformat()
        del ad['_id']
        return jsonify(ad), 200
    except:
        return jsonify({'error': 'Invalid ID'}), 400

@app.route('/api/ads/<ad_id>', methods=['DELETE'])
@cross_origin()

def api_delete_ad(ad_id):
    cleanup_expired_ads()
    try:
        result = ads.delete_one({'_id': ObjectId(ad_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Ad not found'}), 404
        return jsonify({'status': 'deleted'}), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/resources', methods=['POST'])
@cross_origin()

def api_create_resource():
    resource_type = request.form.get('resource_type')
    level = request.form.get('level')
    department = request.form.get('department')
    course_code = request.form.get('course_code', '').strip()
    course_title = request.form.get('course_title', '').strip()
    link_text = request.form.get('link_text', 'View').strip()
    file = request.files.get('file')

    missing = [f for f in ('resource_type', 'level', 'department', 'course_code', 'course_title') if not locals()[f]]
    if not file or file.filename == '':
        missing.append('file')
    if missing:
        return jsonify({'status': 'error', 'message': f"Missing: {', '.join(missing)}"}), 400

    if not allowed_file(file.filename):
        return jsonify({'status': 'error', 'message': 'Invalid file type'}), 400

    upload_result = cloudinary.uploader.upload(
        file,
        resource_type='auto',
        folder='resources'
    )
    file_url = upload_result['secure_url']

    resource = {
        'resource_type': resource_type,
        'level': level,
        'department': department,
        'course_code': course_code,
        'course_title': course_title,
        'link_text': link_text,
        'file_url': file_url,
        'uploaded_at': datetime.now()
    }
    result = resources.insert_one(resource)
    return jsonify({'status': 'success', 'id': str(result.inserted_id)}), 201

@app.route('/api/resources', methods=['GET'])
@cross_origin()

def api_list_resources():
    resource_type = request.args.get('resource_type')
    level = request.args.get('level')
    department = request.args.get('department')

    query = {}
    if resource_type:
        query['resource_type'] = resource_type
    if level:
        query['level'] = level
    if department:
        query['department'] = department

    resource_list = []
    for res in resources.find(query).sort('uploaded_at', -1):
        res['id'] = str(res['_id'])
        del res['_id']
        resource_list.append(res)
    return jsonify(resource_list)

@app.route('/api/resources/<rid>', methods=['PUT'])
@cross_origin()

def api_update_resource(rid):
    data = request.get_json() or {}
    fields = {}
    mapping = {
        'resource_type': 'resource_type',
        'level': 'level',
        'department': 'department',
        'course_code': 'course_code',
        'course_title': 'course_title',
        'link_text': 'link_text'
    }

    for k, col in mapping.items():
        if k in data:
            fields[col] = data[k]

    if not fields:
        return jsonify({'status': 'error', 'message': 'No fields to update'}), 400

    try:
        result = resources.update_one(
            {'_id': ObjectId(rid)},
            {'$set': fields}
        )
        if result.matched_count == 0:
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        return jsonify({'status': 'success'}), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/resources/<rid>', methods=['DELETE'])
@cross_origin()

def api_delete_resource(rid):
    try:
        result = resources.delete_one({'_id': ObjectId(rid)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        return jsonify({'status': 'success'}), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/messages', methods=['POST'])
@cross_origin()

def api_create_message():
    data = request.get_json() or {}
    required = ['firstName', 'lastName', 'messageType', 'message']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'status': 'error', 'message': f"Missing fields: {', '.join(missing)}"}), 400

    message = {
        'first_name': data['firstName'].strip(),
        'last_name': data['lastName'].strip(),
        'whatsapp': data.get('whatsapp', '').strip(),
        'nickname': data.get('nickname', '').strip(),
        'level': data.get('level', '').strip(),
        'department': data.get('department', '').strip(),
        'message_type': data['messageType'],
        'message': data['message'].strip(),
        'created_at': datetime.now(),
        'replied': False,
        'replied_at': None
    }
    result = messages.insert_one(message)
    return jsonify({'status': 'success', 'message': 'Message sent..you will be replied shortly'}), 201

@app.route('/api/messages', methods=['GET'])
@cross_origin()

def api_get_messages():
    message_list = []
    for msg in messages.find().sort('created_at', -1):
        msg['id'] = str(msg['_id'])
        msg['created_at'] = msg['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        msg['replied_at'] = msg['replied_at'].strftime('%Y-%m-%d %H:%M:%S') if msg.get('replied_at') else None
        del msg['_id']
        message_list.append(msg)
    return jsonify(message_list), 200

@app.route('/api/messages/<msg_id>/replied', methods=['PUT'])
@cross_origin()

def mark_message_replied(msg_id):
    try:
        result = messages.update_one(
            {'_id': ObjectId(msg_id)},
            {'$set': {
                'replied': True,
                'replied_at': datetime.now()
            }}
        )
        if result.matched_count == 0:
            return jsonify({'status': 'error', 'message': 'Message not found'}), 404
        return jsonify({'status': 'success', 'message': 'Marked as replied'}), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/messages/<msg_id>', methods=['DELETE'])
def api_delete_message(msg_id):
    try:
        result = messages.delete_one({'_id': ObjectId(msg_id)})
        if result.deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'Message not found'}), 404
        return jsonify({'status': 'success', 'message': 'Deleted'}), 200
    except:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 400

@app.route('/api/messages/count', methods=['GET'])
@cross_origin()

def api_get_message_count():
    count = messages.count_documents({})
    return jsonify({'message_count': count}), 200

@app.route('/', defaults={'page': 'index'})
@app.route('/<page>')
def serve_page(page):
    html_path = os.path.join(BASE_DIR, f"{page}.html")
    if os.path.isfile(html_path):
        return send_from_directory(BASE_DIR, f"{page}.html")
    return send_from_directory(BASE_DIR, '404.html'), 404
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)
