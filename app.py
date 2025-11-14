import os
import uuid
import io
import base64
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, jsonify,
    send_from_directory, make_response, abort, session
)
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import datetime
import qrcode


# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')

# Config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '467894658605fghdfgdfgdfg')
app.config['MONGO_URI'] = os.environ.get('MONGO_URI',
                    'mongodb+srv://nfcure:NFC123@cluster0.nhdsx2a.mongodb.net/nfcureDB?appName=Cluster0')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['ADMIN_KEY'] = os.environ.get('ADMIN_KEY', 'admin123')
app.config['ADMIN_KEY'] = "admin123"
app.secret_key = "43ifkljsdf90843jfklsdfj"


mongo = PyMongo(app)


# -----------------------------
# Utility Functions
# -----------------------------
def generate_public_token():
    return uuid.uuid4().hex


def generate_qr_base64(url):
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    return base64.b64encode(buf.read()).decode('ascii')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = request.cookies.get('user_id')
        if not user_id:
            return redirect(url_for('login', next=request.path))

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            resp = make_response(redirect(url_for('login')))
            resp.delete_cookie('user_id')
            return resp

        return f(user, *args, **kwargs)
    return decorated


@app.context_processor
def inject_datetime():
    return dict(datetime=datetime)


# -----------------------------
# ROUTES
# -----------------------------
@app.route('/')
def index():
    return render_template('index.html')

# -------------------------------
# Static Pages Routes
# -------------------------------

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/faq')
def faq():
    return render_template('faq.html')


@app.route('/mission')
def mission():
    return render_template('mission.html')



# -----------------------------
# SIGNUP
# -----------------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')

        if not name or not email or not password:
            return render_template('signup.html', error="Please fill required fields.")

        if mongo.db.users.find_one({'email': email}):
            return render_template('signup.html', error="Email already registered.")

        password_hash = generate_password_hash(password)
        public_token = generate_public_token()

        user = {
            'name': name,
            'email': email,
            'phone': phone,
            'password_hash': password_hash,
            'plan': 'free',
            'public_token': public_token,
            'medical_data': {},
            'pdf_files': [],
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        mongo.db.users.insert_one(user)
        return redirect(url_for('login'))

    return render_template('signup.html')


# -----------------------------
# LOGIN
# -----------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = mongo.db.users.find_one({'email': email})
        if not user or not check_password_hash(user['password_hash'], password):
            return render_template('login.html', error="Invalid credentials.")

        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie('user_id', str(user['_id']),
                        max_age=7 * 24 * 3600, samesite='Lax')
        return resp

    return render_template('login.html')


# -----------------------------
# LOGOUT
# -----------------------------
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie('user_id')
    return resp


# -----------------------------
# DASHBOARD
# -----------------------------
@app.route('/dashboard')
@login_required
def dashboard(user):
    public_url = request.host_url.rstrip('/') + \
                 url_for('emergency_view', public_token=user['public_token'])

    qr_base64 = generate_qr_base64(public_url)

    logs = list(
        mongo.db.access_logs.find({'user_id': user['_id']})
        .sort('viewed_at', -1)
        .limit(5)
    )

    return render_template('dashboard.html',
                           user=user,
                           qr_base64=qr_base64,
                           public_url=public_url,
                           logs=logs)


# -----------------------------
# EDIT PROFILE / MEDICAL DATA
# -----------------------------
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit(user):
    if request.method == 'POST':

        blood_group = request.form.get('blood_group', '').strip()
        allergies = [x.strip() for x in request.form.get('allergies', '').split(',') if x.strip()]
        conditions = [x.strip() for x in request.form.get('conditions', '').split(',') if x.strip()]
        medications = [x.strip() for x in request.form.get('medications', '').split(',') if x.strip()]
        surgeries = [x.strip() for x in request.form.get('surgeries', '').split(',') if x.strip()]

        contacts = []
        for i in range(1, 5 + 1):
            c_name = request.form.get(f'contact_{i}_name', '').strip()
            c_phone = request.form.get(f'contact_{i}_phone', '').strip()
            if c_name and c_phone:
                contacts.append({'name': c_name, 'phone': c_phone})

        medical_data = {
            'blood_group': blood_group,
            'allergies': allergies,
            'conditions': conditions,
            'medications': medications,
            'surgeries': surgeries,
            'emergency_contacts': contacts
        }

        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': {
                'medical_data': medical_data,
                'updated_at': datetime.utcnow()
            }}
        )

        return redirect(url_for('dashboard'))

    return render_template('profile_edit.html', user=user)


# -----------------------------
# PDF UPLOAD
# -----------------------------
@app.route('/upload_pdf', methods=['POST'])
@login_required
def upload_pdf(user):
    if 'pdf' not in request.files:
        return redirect(url_for('dashboard'))

    f = request.files['pdf']
    if f.filename == '':
        return redirect(url_for('dashboard'))

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    fname = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    f.save(save_path)

    mongo.db.users.update_one(
        {'_id': user['_id']},
        {'$push': {'pdf_files': {'filename': fname, 'uploaded_at': datetime.utcnow()}}}
    )

    return redirect(url_for('dashboard'))


# -----------------------------
# SERVE UPLOADED PDF
# -----------------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# -----------------------------
# EMERGENCY PUBLIC VIEW
# -----------------------------
@app.route('/emergency/<public_token>')
def emergency_view(public_token):
    user = mongo.db.users.find_one({'public_token': public_token})
    if not user:
        abort(404)

    public_data = {
        'name': user.get('name'),
        'blood_group': user.get('medical_data', {}).get('blood_group'),
        'allergies': user.get('medical_data', {}).get('allergies', []),
        'conditions': user.get('medical_data', {}).get('conditions', []),
        'medications': user.get('medical_data', {}).get('medications', []),
        'emergency_contacts': user.get('medical_data', {}).get('emergency_contacts', [])
    }

    try:
        mongo.db.access_logs.insert_one({
            'user_id': user['_id'],
            'viewed_at': datetime.utcnow(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        })
    except:
        pass

    return render_template('emergency_view.html', public_data=public_data)


# -----------------------------
# ADMIN PANEL
# -----------------------------
@app.route('/admin')
def admin_dashboard():
    # Check if admin is logged in
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    # Fetch data
    users = list(mongo.db.users.find().sort('created_at', -1))
    
    # Access logs for QR code views / emergency scans
    logs = list(mongo.db.access_logs.find().sort('viewed_at', -1).limit(200))

    # Dashboard statistics
    total_users = mongo.db.users.count_documents({})
    total_scans = mongo.db.access_logs.count_documents({})
    total_alerts = mongo.db.emergency_alerts.count_documents({}) if "emergency_alerts" in mongo.db.list_collection_names() else 0

    return render_template(
        'admin_dashboard.html',
        users=users,
        logs=logs,
        total_users=total_users,
        total_scans=total_scans,
        total_alerts=total_alerts
    )

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == "POST":
        key = request.form.get("admin_key", "admin123")

        if key == app.config['ADMIN_KEY']:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            error = "Invalid admin key"

    return render_template("admin_login.html", error=error)

@app.route('/admin/logout')
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


# -----------------------------
# API — ACCESS LOGS
# -----------------------------
@app.route('/api/logs')
@login_required
def api_logs(user):
    logs = list(
        mongo.db.access_logs.find({'user_id': user['_id']})
        .sort('viewed_at', -1)
        .limit(200)
    )

    for log in logs:
        log['_id'] = str(log['_id'])
        log['user_id'] = str(log['user_id'])
        log['viewed_at'] = log['viewed_at'].isoformat()

    return jsonify({'logs': logs})


# -----------------------------
# RUN APP
# -----------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT'))
    app.run(debug=True, host='0.0.0.0', port=port)
