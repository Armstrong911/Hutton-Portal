import os, resend
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'hutton-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
NOTIFY_EMAIL   = os.environ.get('NOTIFY_EMAIL', 'admin@huttonstrata.com')
ALLOWED_EXT    = {'pdf'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ── Models ──────────────────────────────────────────────────────────────────

building_users = db.Table('building_users',
    db.Column('user_id',     db.Integer, db.ForeignKey('user.id')),
    db.Column('building_id', db.Integer, db.ForeignKey('building.id'))
)

class User(UserMixin, db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    email        = db.Column(db.String(150), unique=True, nullable=False)
    password     = db.Column(db.String(256), nullable=False)
    name         = db.Column(db.String(100))
    role         = db.Column(db.String(20), default='viewer')  # admin, editor, viewer, contractor
    buildings    = db.relationship('Building', secondary=building_users, backref='users')
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

class Building(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(150), nullable=False)
    address   = db.Column(db.String(200))
    documents = db.relationship('Document', backref='building', lazy=True)
    notices   = db.relationship('Notice', backref='building', lazy=True)

class Document(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    filename    = db.Column(db.String(200), nullable=False)
    label       = db.Column(db.String(200))
    building_id = db.Column(db.Integer, db.ForeignKey('building.id'), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notice(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    body        = db.Column(db.Text)
    building_id = db.Column(db.Integer, db.ForeignKey('building.id'), nullable=False)
    created_by  = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at  = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

# ── Helpers ──────────────────────────────────────────────────────────────────

def allowed(f): return '.' in f and f.rsplit('.',1)[1].lower() in ALLOWED_EXT

def send_notice_email(notice, building):
    if not RESEND_API_KEY: return
    try:
        resend.api_key = RESEND_API_KEY
        recipients = [u.email for u in building.users if u.email]
        if recipients:
            resend.Emails.send({
                "from": "noreply@huttonstrata.com",
                "to": recipients,
                "subject": f"Work Notice — {building.name}: {notice.title}",
                "text": f"A work notice has been posted for {building.name}.\n\n{notice.title}\n\n{notice.body or ''}\n\nThis notice will be removed after 45 days.\n\nHutton Property Management"
            })
    except Exception as e:
        app.logger.warning(f"Email failed: {e}")

def purge_expired_notices():
    Notice.query.filter(Notice.expires_at < datetime.utcnow()).delete()
    db.session.commit()

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email'].strip().lower()).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    purge_expired_notices()
    if current_user.role == 'admin':
        buildings = Building.query.all()
    else:
        buildings = current_user.buildings
    return render_template('dashboard.html', buildings=buildings)

# ── Buildings ─────────────────────────────────────────────────────────────────

@app.route('/building/<int:bid>')
@login_required
def building(bid):
    purge_expired_notices()
    b = Building.query.get_or_404(bid)
    if current_user.role != 'admin' and b not in current_user.buildings:
        abort(403)
    return render_template('building.html', building=b)

# ── Documents ─────────────────────────────────────────────────────────────────

@app.route('/building/<int:bid>/upload', methods=['POST'])
@login_required
def upload(bid):
    if current_user.role not in ('admin','editor'): abort(403)
    b = Building.query.get_or_404(bid)
    f = request.files.get('file')
    if not f or not allowed(f.filename): flash('PDF files only.'); return redirect(url_for('building', bid=bid))
    fname = secure_filename(f.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
    doc = Document(filename=fname, label=request.form.get('label','').strip() or fname, building_id=bid, uploaded_by=current_user.id)
    db.session.add(doc); db.session.commit()
    return redirect(url_for('building', bid=bid))

@app.route('/doc/<int:did>')
@login_required
def view_doc(did):
    doc = Document.query.get_or_404(did)
    b   = Building.query.get(doc.building_id)
    if current_user.role != 'admin' and b not in current_user.buildings: abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename)

@app.route('/doc/<int:did>/delete', methods=['POST'])
@login_required
def delete_doc(did):
    if current_user.role not in ('admin','editor'): abort(403)
    doc = Document.query.get_or_404(did)
    try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], doc.filename))
    except: pass
    db.session.delete(doc); db.session.commit()
    return redirect(url_for('building', bid=doc.building_id))

# ── Notices ───────────────────────────────────────────────────────────────────

@app.route('/building/<int:bid>/notice', methods=['POST'])
@login_required
def add_notice(bid):
    if current_user.role not in ('admin','editor','contractor'): abort(403)
    b = Building.query.get_or_404(bid)
    if current_user.role != 'admin' and b not in current_user.buildings: abort(403)
    n = Notice(
        title       = request.form['title'].strip(),
        body        = request.form.get('body','').strip(),
        building_id = bid,
        created_by  = current_user.id,
        expires_at  = datetime.utcnow() + timedelta(days=45)
    )
    db.session.add(n); db.session.commit()
    send_notice_email(n, b)
    return redirect(url_for('building', bid=bid))

@app.route('/notice/<int:nid>/delete', methods=['POST'])
@login_required
def delete_notice(nid):
    if current_user.role not in ('admin','editor'): abort(403)
    n = Notice.query.get_or_404(nid)
    db.session.delete(n); db.session.commit()
    return redirect(url_for('building', bid=n.building_id))

# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin': abort(403)
    return render_template('admin.html', users=User.query.all(), buildings=Building.query.all())

@app.route('/admin/user/add', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin': abort(403)
    email = request.form['email'].strip().lower()
    if not User.query.filter_by(email=email).first():
        u = User(email=email, name=request.form.get('name',''), role=request.form.get('role','viewer'),
                 password=generate_password_hash(request.form['password']))
        db.session.add(u); db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/user/<int:uid>/delete', methods=['POST'])
@login_required
def delete_user(uid):
    if current_user.role != 'admin': abort(403)
    u = User.query.get_or_404(uid)
    db.session.delete(u); db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/building/add', methods=['POST'])
@login_required
def add_building():
    if current_user.role != 'admin': abort(403)
    b = Building(name=request.form['name'].strip(), address=request.form.get('address','').strip())
    db.session.add(b); db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/building/<int:bid>/delete', methods=['POST'])
@login_required
def delete_building(bid):
    if current_user.role != 'admin': abort(403)
    b = Building.query.get_or_404(bid)
    db.session.delete(b); db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/assign', methods=['POST'])
@login_required
def assign_building():
    if current_user.role != 'admin': abort(403)
    u = User.query.get_or_404(int(request.form['user_id']))
    b = Building.query.get_or_404(int(request.form['building_id']))
    if b not in u.buildings: u.buildings.append(b)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/unassign', methods=['POST'])
@login_required
def unassign_building():
    if current_user.role != 'admin': abort(403)
    u = User.query.get_or_404(int(request.form['user_id']))
    b = Building.query.get_or_404(int(request.form['building_id']))
    if b in u.buildings: u.buildings.remove(b)
    db.session.commit()
    return redirect(url_for('admin'))

# ── Init ──────────────────────────────────────────────────────────────────────

def init_db():
    db.create_all()
    if not User.query.filter_by(email='admin@huttonstrata.com').first():
        admin = User(email='admin@huttonstrata.com', name='Admin', role='admin',
                     password=generate_password_hash('hutton2024'))
        db.session.add(admin); db.session.commit()

with app.app_context(): init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
