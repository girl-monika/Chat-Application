from flask import Flask, Response
from flask import render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from flask import Blueprint
from werkzeug.utils import secure_filename
from pymongo import MongoClient
import os
import uuid
from datetime import datetime, timedelta
from functools import wraps
from bson.objectid import ObjectId
import pytz
import gridfs

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # For session management

# MongoDB Atlas connection (replace with your URI)
MONGO_URI = 'mongodb+srv://monika_anisetty:143mon@monika.wgpzo2k.mongodb.net/?retryWrites=true&w=majority&appName=Monika'
client = MongoClient(MONGO_URI)
db = client['secure-docs']
fs = gridfs.GridFS(db)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Blueprints
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)
dashboard_bp = Blueprint('dashboard', __name__)
documents_bp = Blueprint('documents', __name__)
chat_bp = Blueprint('chat', __name__)
shared_links_bp = Blueprint('shared_links', __name__)

# Home route
@app.route('/')
def home():
    return render_template('home.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if db.users.find_one({'email': email}):
            flash('Email already exists.', 'error')
            return render_template('signup.html')
        db.users.insert_one({'name': name, 'email': email, 'password': password})
        session['user_email'] = email
        session['user_name'] = name
        return redirect(url_for('dashboard.dashboard'))
    return render_template('signup.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = db.users.find_one({'email': email, 'password': password})
        if user:
            session['user_email'] = user['email']
            session['user_name'] = user['name']
            return redirect(url_for('dashboard.dashboard'))
        else:
            flash('Invalid credentials.', 'error')
            return render_template('login.html')
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@dashboard_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user_name=session.get('user_name'))

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt', 'xlsx', 'pptx'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@documents_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Save file to GridFS instead of local storage
            file_id = fs.put(file, filename=filename, uploader_email=session['user_email'])
            db.documents.insert_one({
                'filename': filename,
                'uploader_email': session['user_email'],
                'upload_time': datetime.utcnow(),
                'file_id': file_id
            })
            return redirect(url_for('documents.documents'))
        else:
            flash('Invalid file type.', 'error')
    return render_template('upload.html')

@documents_bp.route('/documents')
@login_required
def documents():
    user_email = session['user_email']
    docs = list(db.documents.find({'uploader_email': user_email}))
    share_url = session.pop('share_url', None)
    return render_template('documents.html', documents=docs, share_url=share_url)

@documents_bp.route('/view/<doc_id>')
@login_required
def view_document(doc_id):
    doc = db.documents.find_one({'_id': ObjectId(doc_id), 'uploader_email': session['user_email']})
    if not doc:
        return 'Document not found or access denied.', 404
    file_id = doc.get('file_id')
    if not file_id:
        return 'File not found in database.', 404
    file_data = fs.get(file_id)
    return Response(file_data.read(), mimetype='application/octet-stream', headers={"Content-Disposition": f"inline;filename={doc['filename']}"})

@documents_bp.route('/delete/<doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = db.documents.find_one({'_id': ObjectId(doc_id), 'uploader_email': session['user_email']})
    if not doc:
        flash('Document not found or access denied.', 'error')
        return redirect(url_for('documents.documents'))
    try:
        # Remove from GridFS if file_id exists
        if 'file_id' in doc:
            fs.delete(doc['file_id'])
    except Exception:
        pass
    db.documents.delete_one({'_id': ObjectId(doc_id)})
    flash('Document deleted.', 'success')
    return redirect(url_for('documents.documents'))

@documents_bp.route('/share', methods=['POST'])
@login_required
def share_document():
    doc_id = request.form['doc_id']
    expiry_datetime_str = request.form['expiry_datetime']
    # Convert local (IST) time to UTC before saving
    ist = pytz.timezone('Asia/Kolkata')
    local_dt = ist.localize(datetime.strptime(expiry_datetime_str, '%Y-%m-%dT%H:%M'))
    utc_dt = local_dt.astimezone(pytz.utc)
    expiry_datetime_utc = utc_dt.strftime('%Y-%m-%dT%H:%M')
    unique_link = str(uuid.uuid4())
    share_url = f"{request.host_url}shared/{unique_link}"
    db.shared_links.insert_one({
        'doc_id': doc_id,
        'sender_email': session['user_email'],
        'expiry_datetime': expiry_datetime_utc,
        'unique_link': unique_link
    })
    # Add expiry info to chat message (show in IST for chat)
    expiry_str_ist = local_dt.strftime('%Y-%m-%d %H:%M')
    db.chats.insert_one({
        'sender_email': session['user_email'],
        'receiver_email': None,
        'message': f"Shared a document: {share_url} (Expires: {expiry_str_ist} IST)",
        'timestamp': datetime.utcnow()
    })
    session['share_url'] = share_url
    return redirect(url_for('documents.documents'))

@shared_links_bp.route('/shared/<unique_link>')
def access_shared_link(unique_link):
    link = db.shared_links.find_one({'unique_link': unique_link})
    if not link:
        return render_template('shared_view.html', expired=True)
    expiry = datetime.strptime(link['expiry_datetime'], '%Y-%m-%dT%H:%M')
    if datetime.utcnow() > expiry:
        return render_template('shared_view.html', expired=True)
    doc = db.documents.find_one({'_id': ObjectId(link['doc_id'])})
    if not doc:
        return render_template('shared_view.html', expired=True)
    return render_template('shared_view.html', expired=False, filename=doc['filename'], file_url=url_for('shared_links.download_shared_file', unique_link=unique_link), expiry_datetime=link['expiry_datetime'])

@shared_links_bp.route('/shared/<unique_link>/download')
def download_shared_file(unique_link):
    link = db.shared_links.find_one({'unique_link': unique_link})
    if not link:
        return 'Link expired or invalid.', 404
    expiry = datetime.strptime(link['expiry_datetime'], '%Y-%m-%dT%H:%M')
    if datetime.utcnow() > expiry:
        return 'Link expired.', 403
    doc = db.documents.find_one({'_id': ObjectId(link['doc_id'])})
    if not doc:
        return 'Document not found.', 404
    file_id = doc.get('file_id')
    if not file_id:
        return 'File not found in database.', 404
    file_data = fs.get(file_id)
    return Response(file_data.read(), mimetype='application/octet-stream', headers={"Content-Disposition": f"attachment;filename={doc['filename']}"})

@chat_bp.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    search_results = []
    user_email = session['user_email']
    # Find all unique chat partners
    chat_partners = set()
    for chat in db.chats.find({'$or': [
        {'sender_email': user_email},
        {'receiver_email': user_email}
    ]}):
        if chat['sender_email'] != user_email:
            chat_partners.add(chat['sender_email'])
        if chat['receiver_email'] != user_email:
            chat_partners.add(chat['receiver_email'])
    chat_partners = list(chat_partners)
    chat_partner_users = list(db.users.find({'email': {'$in': chat_partners}})) if chat_partners else []
    if request.method == 'POST':
        email_query = request.form['email']
        search_results = list(db.users.find({'email': {'$regex': email_query, '$ne': user_email}}))
    return render_template('chat.html', search_results=search_results, chat_partners=chat_partner_users)

@chat_bp.route('/chat/<receiver_email>', methods=['GET', 'POST'])
@login_required
def chat_conversation(receiver_email):
    sender_email = session['user_email']
    if request.method == 'POST':
        message = request.form['message']
        db.chats.insert_one({
            'sender_email': sender_email,
            'receiver_email': receiver_email,
            'message': message,
            'timestamp': datetime.utcnow()
        })
    # Fetch chat history (both directions)
    chat_history = list(db.chats.find({
        '$or': [
            {'sender_email': sender_email, 'receiver_email': receiver_email},
            {'sender_email': receiver_email, 'receiver_email': sender_email}
        ]
    }).sort('timestamp', 1))
    receiver = db.users.find_one({'email': receiver_email})
    return render_template('chat_conversation.html', chat_history=chat_history, receiver=receiver)

# Register Blueprints (must be after all routes are defined)
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(documents_bp)
app.register_blueprint(chat_bp)
app.register_blueprint(shared_links_bp)

if __name__ == '__main__':
    app.run(debug=True) 