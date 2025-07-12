from functools import wraps
import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from bson import ObjectId
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import re
from flask_cors import CORS
import jwt
import cloudinary
import cloudinary.uploader
import cloudinary.api



# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Configure CORS
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-jwt-secret')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION = timedelta(hours=12)

# config.py (add to .gitignore)
CLOUDINARY_CLOUD_NAME = 'dhndd1msa'
CLOUDINARY_API_KEY = '673133626476232'
CLOUDINARY_API_SECRET = 'gMSBAFELYFlEQIGTTDYziYbytsA'



# Get current UTC time (corrects system time issues)
correct_time = int(datetime.utcnow().timestamp())
try:
    cloudinary.config(
        cloud_name="dhndd1msa",          # Replace with your cloud name
        api_key="673133626476232",       # Replace with your API key
        api_secret="gMSBAFELYFlEQIGTTDYziYbytsA",  # Replace with your API secret
        secure=True, # Enforce HTTPS
        timestamp=correct_time,
    )
    
    # Test connection
    account_details = cloudinary.api.ping()
    print("✅ Cloudinary connection successful")
    print(f"Cloud Name: {account_details.get('cloud_name')}")
except Exception as e:
    print(f"❌ Cloudinary connection failed: {e}")
# MongoDB connection
try:
    client = MongoClient(
        os.environ.get('MONGODB_URI'),
        retryWrites=True,
        appName="naits_app"
    )
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

    db = client.get_database('naits_db')
    users_collection = db.users
    announcements_collection = db.announcements
    client.admin.command('ping')
    print("✅ MongoDB connection successful")
    
    # Create indexes
    announcements_collection.create_index([("target.type", 1)])
    announcements_collection.create_index([("target.value", 1)])
    announcements_collection.create_index([("created_at", -1)])
    
except Exception as e:
    print(f"❌ MongoDB connection failed: {str(e)}")
    raise

# Helper functions
def _build_cors_preflight_response():
    response = jsonify({'status': 'preflight'})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Allow-Methods", "*")
    return response

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception('Token expired')
    except jwt.InvalidTokenError:
        raise Exception('Invalid token')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'success': False, 'error': 'Authorization required'}), 401
        
        try:
            token = token.replace('Bearer ', '')
            payload = verify_token(token)
            request.user_id = payload['user_id']
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated

def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'success': False, 'error': 'Authorization required'}), 401
        
        try:
            token = token.replace('Bearer ', '')
            payload = verify_token(token)
            user = users_collection.find_one({'_id': ObjectId(payload['user_id'])})
            
            if not user or user.get('role') != 'admin':
                return jsonify({'success': False, 'error': 'Admin access required'}), 403
                
            request.user = user
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated

def validate_signup_data(data):
    errors = []
    required_fields = {
        'first_name': 'First name is required',
        'last_name': 'Last name is required',
        'birthday': 'Birthday is required (MM-DD format)',
        'nickname': 'Nickname is required',
        'department': 'Department is required',
        'level': 'Level is required',
        'whatsapp': 'WhatsApp number is required (11 digits)',
        'password': 'Password is required (min 10 characters)'
    }
    
    for field, message in required_fields.items():
        if not data.get(field):
            errors.append(message)

    if data.get('birthday') and not re.match(r'^\d{2}-\d{2}$', data['birthday']):
        errors.append('Birthday must be in MM-DD format')

    if data.get('whatsapp') and not re.match(r'^\d{11}$', data['whatsapp']):
        errors.append('WhatsApp number must be 11 digits')

    if data.get('password') and len(data['password']) < 10:
        errors.append('Password must be at least 10 characters')

    return errors

def user_exists(nickname, whatsapp):
    return users_collection.find_one({
        '$or': [
            {'nickname': nickname.lower()},
            {'whatsapp': whatsapp}
        ]
    })

def create_user(data):
    user = {
        'first_name': data['first_name'].strip(),
        'last_name': data['last_name'].strip(),
        'birthday': data['birthday'],
        'nickname': data['nickname'].strip().lower(),
        'department': data['department'].upper(),
        'level': data['level'].upper(),
        'whatsapp': data['whatsapp'],
        'email': data.get('email', '').strip().lower(),
        'password': generate_password_hash(data['password']),
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow(),
        'last_login': None,
        'status': 'active',
        'last_seen': None,
          'last_notification_check': datetime.min
    }
    result = users_collection.insert_one(user)
    return result.inserted_id

def generate_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': datetime.utcnow() + JWT_EXPIRATION
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def authenticate_user(nickname, department, password):
    user = users_collection.find_one({
        'nickname': nickname.strip().lower(),
        'department': department.upper()
    })
    
    if user and check_password_hash(user['password'], password):
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {
                'last_login': datetime.utcnow(),
                'status': 'online',
                'last_seen': datetime.utcnow()
            }}
        )
        return user
    return None

def sanitize_user_data(user):
    return {
        'id': str(user['_id']),
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'nickname': user['nickname'],
        'department': user['department'],
        'level': user['level'],
        'email': user.get('email', ''),
        'last_login': user.get('last_login'),
        'status': user.get('status', 'active')
    }

def validate_announcement_data(data):
    errors = []
    required_fields = {
        'title': 'Title is required',
        'content': 'Content is required',
        'badge': 'Badge type is required',
        'target': 'Target audience is required'
    }
    
    for field, message in required_fields.items():
        if not data.get(field):
            errors.append(message)
    
    valid_badges = ['notice', 'warning', 'new', 'important', 'event']
    if data.get('badge') and data['badge'] not in valid_badges:
        errors.append(f'Invalid badge type. Must be one of: {", ".join(valid_badges)}')
    
    valid_target_types = ['all', 'department', 'level', 'user']
    if data.get('target') and data['target'].get('type') not in valid_target_types:
        errors.append(f'Invalid target type. Must be one of: {", ".join(valid_target_types)}')
    
    return errors

def ensure_admin_exists():
    """Ensure the admin account exists in database"""
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    
    if not admin_email or not admin_password:
        raise ValueError("Admin credentials not configured in environment variables")
    
    admin = users_collection.find_one({'email': admin_email})
    
    if not admin:
        # Create the admin account if it doesn't exist
        admin_data = {
            'first_name': os.environ.get('ADMIN_FIRST_NAME', 'Admin'),
            'last_name': os.environ.get('ADMIN_LAST_NAME', 'User'),
            'email': admin_email,
            'password': generate_password_hash(admin_password),
            'role': 'admin',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'last_login': None,
            'status': 'active'
        }
        users_collection.insert_one(admin_data)
        print("✅ Admin account created")
    else:
        # Update password if it has changed in .env
        if not check_password_hash(admin['password'], admin_password):
            users_collection.update_one(
                {'email': admin_email},
                {'$set': {
                    'password': generate_password_hash(admin_password),
                    'updated_at': datetime.utcnow()
                }}
            )
            print("✅ Admin password updated")

def authenticate_admin(email, password):
    """Authenticate the predefined admin user"""
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    
    # Verify it's our predefined admin
    if email.strip().lower() != admin_email.lower():
        return None
    
    # Verify password matches .env
    if not check_password_hash(users_collection.find_one({'email': admin_email})['password'], admin_password):
        return None
    
    # Get or create admin record
    admin = users_collection.find_one({'email': admin_email})
    
    if not admin:
        ensure_admin_exists()
        admin = users_collection.find_one({'email': admin_email})
    
    # Update last login
    users_collection.update_one(
        {'_id': admin['_id']},
        {'$set': {
            'last_login': datetime.utcnow(),
            'status': 'online'
        }}
    )
    
    return admin

# Routes
@app.route('/')
def home():
    return jsonify({"status": "NAITS Backend Running"})

@app.route('/api/auth/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        errors = validate_signup_data(data)
        if errors:
            return jsonify({'success': False, 'error': 'Validation failed', 'details': errors}), 400

        if user_exists(data['nickname'], data['whatsapp']):
            return jsonify({'success': False, 'error': 'User already exists'}), 400

        user_id = create_user(data)
        user = users_collection.find_one({'_id': user_id})
        token = generate_token(user_id)
        
        return jsonify({
            'success': True,
            'token': token,
            'user': sanitize_user_data(user),
            'message': 'Registration successful'
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/signin', methods=['POST', 'OPTIONS'])
def signin():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        if not all(k in data for k in ['nickname', 'department', 'password']):
            return jsonify({'success': False, 'error': 'Missing fields'}), 400
        
        data['nickname'] = data['nickname'].strip().lower()
        data['department'] = data['department'].upper()

        user = authenticate_user(data['nickname'], data['department'], data['password'])
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        token = generate_token(user['_id'])

        return jsonify({
            'success': True,
            'token': token,
            'user': sanitize_user_data(user),
            'message': 'Login successful'
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@requires_auth
def user_logout():
    try:
        users_collection.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$set': {
                'status': 'offline',
                'last_seen': datetime.utcnow()
            }}
        )
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/heartbeat', methods=['POST'])
@requires_auth
def user_heartbeat():
    try:
        users_collection.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$set': {
                'last_seen': datetime.utcnow(),
                'status': 'online'
            }}
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/status/<user_id>', methods=['GET'])
@requires_auth
def get_user_status(user_id):
    try:
        user = users_collection.find_one(
            {'_id': ObjectId(user_id)},
            {'status': 1, 'last_seen': 1, 'first_name': 1, 'department': 1}
        )
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Determine status based on last seen time if status is online
        status = user.get('status', 'offline')
        if status == 'online':
            last_seen = user.get('last_seen')
            if last_seen and (datetime.utcnow() - last_seen) > timedelta(minutes=5):
                status = 'offline'
                users_collection.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': {'status': 'offline'}}
                )
        
        return jsonify({
            'success': True,
            'status': status,
            'last_seen': user.get('last_seen'),
            'first_name': user.get('first_name'),
            'department': user.get('department')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Admin routes
@app.route('/api/admin/auth/signin', methods=['POST', 'OPTIONS'])
def admin_signin():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        if not all(k in data for k in ['email', 'password']):
            return jsonify({'success': False, 'error': 'Missing email or password'}), 400
        
        email = data['email'].strip().lower()
        password = data['password']

        admin = authenticate_admin(email, password)
        if not admin:
            return jsonify({'success': False, 'error': 'Invalid admin credentials'}), 401

        token = generate_token(admin['_id'])

        return jsonify({
            'success': True,
            'token': token,
            'admin': {
                'id': str(admin['_id']),
                'first_name': admin.get('first_name', 'Admin'),
                'last_name': admin.get('last_name', 'User'),
                'email': admin['email'],
                'role': 'admin'
            },
            'message': 'Admin login successful'
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/validate', methods=['GET'])
@requires_auth
def validate_admin_token():
    try:
        admin = users_collection.find_one({'_id': ObjectId(request.user_id)})
        
        if not admin or admin.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
            
        return jsonify({
            'success': True,
            'admin': {
                'id': str(admin['_id']),
                'first_name': admin.get('first_name', 'Admin'),
                'last_name': admin.get('last_name', 'User'),
                'email': admin['email'],
                'role': 'admin'
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/check-admin', methods=['GET'])
@requires_auth
def check_admin():
    try:
        admin = users_collection.find_one({'_id': ObjectId(request.user_id)})
        
        if not admin or admin.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        return jsonify({'success': True, 'is_admin': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# File Upload Routes
@app.route('/api/upload', methods=['POST'])
@requires_admin
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No selected file'}), 400
        
        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(
            file,
            folder="naits_announcements",
            resource_type="auto"  # Automatically detects if it's image or video
        )
        
        return jsonify({
            'success': True,
            'url': upload_result['secure_url'],
            'public_id': upload_result['public_id'],
            'resource_type': upload_result['resource_type']
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/upload', methods=['DELETE'])
@requires_admin
def delete_upload():
    try:
        # Verify Cloudinary is configured
        if not hasattr(cloudinary, 'config') or not cloudinary.config().cloud_name:
            return jsonify({
                'success': False,
                'error': 'Cloudinary not configured'
            }), 500

        data = request.get_json()
        if not data or not data.get('public_id'):
            return jsonify({
                'success': False,
                'error': 'Public ID required'
            }), 400
        
        # Delete from Cloudinary
        result = cloudinary.uploader.destroy(data['public_id'])
        
        if result.get('result') == 'ok':
            return jsonify({
                'success': True,
                'message': 'File deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('message', 'Failed to delete file')
            }), 400
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Cloudinary deletion error'
        }), 500

# Announcement Routes
@app.route('/api/announcements', methods=['GET'])
@requires_auth
def get_announcements():
    try:
        user = users_collection.find_one({'_id': ObjectId(request.user_id)})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # For admins, show all announcements
        if user.get('role') == 'admin':
            filter_query = {}
        else:
            # For regular users, filter based on their department/level
            filter_query = {
                '$or': [
                    {'target.type': 'all'},
                    {'target.type': 'department', 'target.value': {'$in': [user['department']]}},
                    {'target.type': 'level', 'target.value': {'$in': [user['level']]}},
                    {'target.type': 'user', 'target.value': {'$in': [user['nickname']]}},
        # Also handle direct equality (non-array values)
        {'target.type': 'department', 'target.value': user['department']},
        {'target.type': 'level', 'target.value': user['level']},
        {'target.type': 'user', 'target.value': user['nickname']}
    ]
}
        
        # Get pagination parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit
        
        # Get total count for pagination
        total = announcements_collection.count_documents(filter_query)
        total_pages = (total + limit - 1) // limit  # Ceiling division
        
        # Get paginated results
        announcements = list(announcements_collection.find(filter_query)
            .sort('created_at', -1)
            .skip(skip)
            .limit(limit))
        
        # Convert MongoDB objects to JSON-serializable format
        serialized_announcements = []
        for announcement in announcements:
            serialized = {
                '_id': str(announcement['_id']),
                'title': announcement['title'],
                'content': announcement['content'],
                'badge': announcement.get('badge', 'general'),
                'created_at': announcement['created_at'].isoformat(),
                'created_by': announcement['created_by'],
                'has_read': check_read_status(announcement['_id'], request.user_id)
            }
            
            # Add optional fields
            if 'expires_at' in announcement and announcement['expires_at']:
                serialized['expires_at'] = announcement['expires_at'].isoformat()
            if 'image_url' in announcement:
                serialized['image_url'] = announcement['image_url']
            if 'priority' in announcement:
                serialized['priority'] = announcement['priority']
            
            serialized_announcements.append(serialized)
        
        return jsonify({
            'success': True,
            'announcements': serialized_announcements,
            'totalPages': total_pages,
            'currentPage': page,
            'totalAnnouncements': total
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# In your Flask app (app.py)

@app.route('/api/announcements', methods=['POST'])
@requires_admin
def create_announcement():
    try:
        data = request.get_json()
        errors = validate_announcement_data(data)
        if errors:
            return jsonify({'success': False, 'error': 'Validation failed', 'details': errors}), 400
        
        # Set default target if not provided
        if 'target' not in data:
            data['target'] = {'type': 'all', 'value': 'all'}
        # Get admin user from the request (set by requires_admin decorator)
        admin_user = request.user
        
        # Handle target value
        target_value = process_target_value(data['target']['type'], data['target']['value'])
        
        announcement = {
            'title': data['title'],
            'content': data['content'],
            'badge': data['badge'],
            'target': {
                'type': data['target']['type'],
                'value': target_value
            },
            'created_by': {
                'user_id': str(admin_user['_id']),
                'name': f"{admin_user['first_name']} {admin_user['last_name']}",
                'nickname': admin_user.get('nickname', 'admin')
            },
            'created_at': datetime.utcnow(),
            'expires_at': parse_datetime(data.get('expires_at')),
            'priority': data.get('priority', 'normal')
        }
        
        # Add media if provided
        if data.get('image_url'):
            announcement.update({
                'image_url': data['image_url'],
                'image_public_id': data.get('image_public_id', '')
            })
        
        result = announcements_collection.insert_one(announcement)
        announcement['_id'] = str(result.inserted_id)
        
        return jsonify({'success': True, 'announcement': announcement}), 201
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/announcements/<announcement_id>', methods=['PUT'])
@requires_admin
def update_announcement(announcement_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        errors = validate_announcement_data(data)
        if errors:
            return jsonify({'success': False, 'error': 'Validation failed', 'details': errors}), 400
        
        # Check if announcement exists
        existing = announcements_collection.find_one({'_id': ObjectId(announcement_id)})
        if not existing:
            return jsonify({'success': False, 'error': 'Announcement not found'}), 404
        
        # Process target value
        target_value = 'all'  # default
        if 'target' in data:
            target_value = process_target_value(
                data['target'].get('type', 'all'),
                data['target'].get('value', 'all')
            )
        
        # Prepare update data
        update_data = {
            'title': data.get('title', existing['title']),
            'content': data.get('content', existing['content']),
            'badge': data.get('badge', existing.get('badge', 'notice')),
            'target': {
                'type': data.get('target', {}).get('type', existing['target']['type']),
                'value': target_value
            },
            'updated_at': datetime.utcnow(),
            'priority': data.get('priority', existing.get('priority', 'normal'))
        }
        
        # Handle expiration date if provided
        if 'expires_at' in data:
            update_data['expires_at'] = parse_datetime(data['expires_at'])
        
        # Handle image updates
        update_data = handle_image_update(update_data, data, existing)
        
        # Perform the update
        result = announcements_collection.update_one(
            {'_id': ObjectId(announcement_id)},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': True, 'message': 'No changes detected'})
            
        # Return the updated announcement
        updated = announcements_collection.find_one({'_id': ObjectId(announcement_id)})
        updated['_id'] = str(updated['_id'])  # Convert ObjectId to string
        
        return jsonify({
            'success': True,
            'message': 'Announcement updated',
            'announcement': updated
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to update announcement'
        }), 500

@app.route('/api/announcements/<announcement_id>', methods=['DELETE'])
@requires_admin
def delete_announcement(announcement_id):
    try:
        announcement = announcements_collection.find_one({'_id': ObjectId(announcement_id)})
        if not announcement:
            return jsonify({'success': False, 'error': 'Announcement not found'}), 404
        
        # Delete associated media
        if announcement.get('image_public_id'):
            cloudinary.uploader.destroy(announcement['image_public_id'])
        
        # Delete from database
        result = announcements_collection.delete_one({'_id': ObjectId(announcement_id)})
        
        if result.deleted_count == 0:
            return jsonify({'success': False, 'error': 'Deletion failed'}), 500
        
        return jsonify({'success': True, 'message': 'Announcement deleted'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/announcements/<announcement_id>/read', methods=['POST'])
@requires_auth
def mark_as_read(announcement_id):
    try:
        # Implement read status tracking here
        # This would typically update a separate collection tracking which users have read which announcements
        return jsonify({'success': True, 'message': 'Marked as read'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
def validate_announcement_data(data):
    """Validate announcement data"""
    errors = {}
    if 'title' in data and not data['title'].strip():
        errors['title'] = 'Title is required'
    if 'content' in data and not data['content'].strip():
        errors['content'] = 'Content is required'
    return errors

def process_target_value(target_type, target_value):
    """Process target value based on type"""
    if target_type == 'all':
        return 'all'
    
    # Handle case where target_value might be None or empty
    if not target_value:
        return 'all' if target_type == 'all' else []
    
    if isinstance(target_value, str):
        if target_value.lower() == 'all':
            return 'all'
        return [target_value.upper()] if target_type in ['department', 'level'] else [target_value]
    
    # Handle array values
    if isinstance(target_value, list):
        if not target_value:  # Empty list
            return []
        return [v.upper() if target_type in ['department', 'level'] else v for v in target_value]
    
    return []
def parse_datetime(datetime_str):
    """Parse datetime string to datetime object"""
    if not datetime_str:
        return None
    try:
        return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
    except ValueError:
        return None

def handle_image_update(update_data, new_data, existing_data):
    """Handle image updates and deletions"""
    if 'image_url' in new_data:
        if new_data['image_url']:  # New image provided
            update_data['image_url'] = new_data['image_url']
            update_data['image_public_id'] = new_data.get('image_public_id', '')
            
            # Delete old image if it exists
            if existing_data.get('image_public_id'):
                cloudinary.uploader.destroy(existing_data['image_public_id'])
        else:  # Image removed
            if existing_data.get('image_public_id'):
                cloudinary.uploader.destroy(existing_data['image_public_id'])
            update_data['image_url'] = None
            update_data['image_public_id'] = None
    
    return update_data
def check_read_status(announcement_id, user_id):
    # Implement your logic to check if user has read this announcement
    # This would typically query a separate collection tracking read status
    return False


@app.route('/api/announcements/unread-count', methods=['GET'])
@requires_auth
def get_unread_count():
    try:
        user = users_collection.find_one({'_id': ObjectId(request.user_id)})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        # Get user's last notification check time (default to epoch if not set)
        last_check = user.get('last_notification_check', datetime.min)

        # Base filter for unread announcements
        filter_query = {
            'created_at': {'$gt': last_check},
            '$or': [
                {'target.type': 'all'},
                {'target.type': 'department', 'target.value': {'$in': [user['department']]}},
                {'target.type': 'level', 'target.value': {'$in': [user['level']]}},
                {'target.type': 'user', 'target.value': {'$in': [user['nickname']]}},
                # Handle direct equality (non-array values)
                {'target.type': 'department', 'target.value': user['department']},
                {'target.type': 'level', 'target.value': user['level']},
                {'target.type': 'user', 'target.value': user['nickname']}
            ]
        }

        # For admins, show all unread announcements except their own
        if user.get('role') == 'admin':
            filter_query['created_by.id'] = {'$ne': request.user_id}

        # Count matching announcements
        count = announcements_collection.count_documents(filter_query)

        return jsonify({
            'success': True,
            'count': count
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/announcements/mark-read', methods=['POST'])
@requires_auth
def mark_all_read():
    try:
        # Update user's last notification check time
        users_collection.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$set': {'last_notification_check': datetime.utcnow()}}
        )
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500






@app.route('/api/users', methods=['GET'])
@requires_admin
def get_users():
    try:
        users = list(users_collection.find({}, {'_id': 1, 'nickname': 1, 'department': 1, 'level': 1}))
        # Convert ObjectId and ensure all required fields exist
        serialized_users = []
        for user in users:
            if not user.get('_id'):
                continue
            serialized_users.append({
                '_id': str(user['_id']),
                'nickname': user.get('nickname', 'Unknown'),
                'department': user.get('department', ''),
                'level': user.get('level', '')
            })
        return jsonify({'success': True, 'users': serialized_users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
# Initialize admin account when starting the app
ensure_admin_exists()

if __name__ == '__main__':
    app.run(
        host=os.environ.get('HOST', '0.0.0.0'),
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_ENV') == 'development'
    )
