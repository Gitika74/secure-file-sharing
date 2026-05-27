import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

try:
    from config import DATABASE_URL as CONFIG_DB_URL
except ImportError:
    CONFIG_DB_URL = None

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', secrets.token_hex(32))

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', 'csv', 'ppt', 'pptx', 'mp4', 'mp3'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    db_url = os.environ.get('DATABASE_URL') or CONFIG_DB_URL
    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            full_name VARCHAR(120) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            original_filename VARCHAR(255) NOT NULL,
            file_size BIGINT NOT NULL,
            file_type VARCHAR(50),
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            description TEXT,
            is_public BOOLEAN DEFAULT FALSE
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS share_links (
            id SERIAL PRIMARY KEY,
            file_id INTEGER REFERENCES files(id) ON DELETE CASCADE,
            share_token VARCHAR(64) UNIQUE NOT NULL,
            created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            max_downloads INTEGER,
            download_count INTEGER DEFAULT 0,
            password_hash VARCHAR(256),
            is_active BOOLEAN DEFAULT TRUE
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS file_shares (
            id SERIAL PRIMARY KEY,
            file_id INTEGER REFERENCES files(id) ON DELETE CASCADE,
            shared_with INTEGER REFERENCES users(id) ON DELETE CASCADE,
            shared_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
            permission VARCHAR(20) DEFAULT 'view',
            shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(file_id, shared_with)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            action VARCHAR(50) NOT NULL,
            file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.close()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def log_activity(user_id, action, file_id=None, details=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO activity_log (user_id, action, file_id, details) VALUES (%s, %s, %s, %s)',
        (user_id, action, file_id, details)
    )
    cur.close()
    conn.close()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def format_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


@app.template_filter('filesize')
def filesize_filter(size):
    return format_file_size(size)


@app.template_filter('timeago')
def timeago_filter(dt):
    if dt is None:
        return ''
    now = datetime.now()
    diff = now - dt
    if diff.days > 30:
        return dt.strftime('%b %d, %Y')
    elif diff.days > 0:
        return f"{diff.days}d ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600}h ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60}m ago"
    else:
        return "Just now"


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()

        if not all([username, email, password, confirm_password, full_name]):
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')

        conn = get_db()
        cur = conn.cursor()

        cur.execute('SELECT id FROM users WHERE username = %s OR email = %s', (username, email))
        if cur.fetchone():
            flash('Username or email already exists.', 'error')
            cur.close()
            conn.close()
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        cur.execute(
            'INSERT INTO users (username, email, password_hash, full_name) VALUES (%s, %s, %s, %s) RETURNING id',
            (username, email, password_hash, full_name)
        )
        user_id = cur.fetchone()[0]
        cur.close()
        conn.close()

        log_activity(user_id, 'register', details='Account created')
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            log_activity(user['id'], 'login', details='User logged in')
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'logout', details='User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute('SELECT COUNT(*) FROM files WHERE owner_id = %s', (session['user_id'],))
    total_files = cur.fetchone()[0]

    cur.execute('SELECT COALESCE(SUM(file_size), 0) FROM files WHERE owner_id = %s', (session['user_id'],))
    total_size = cur.fetchone()[0]

    cur.execute('SELECT COUNT(*) FROM file_shares WHERE shared_with = %s', (session['user_id'],))
    shared_with_me = cur.fetchone()[0]

    cur.execute('SELECT COUNT(*) FROM share_links WHERE created_by = %s AND is_active = TRUE', (session['user_id'],))
    active_links = cur.fetchone()[0]

    cur.execute('''
        SELECT f.*, u.username as owner_name 
        FROM files f JOIN users u ON f.owner_id = u.id 
        WHERE f.owner_id = %s 
        ORDER BY f.upload_date DESC LIMIT 5
    ''', (session['user_id'],))
    recent_files = cur.fetchall()

    cur.execute('''
        SELECT a.*, f.original_filename 
        FROM activity_log a LEFT JOIN files f ON a.file_id = f.id 
        WHERE a.user_id = %s 
        ORDER BY a.created_at DESC LIMIT 10
    ''', (session['user_id'],))
    activities = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('dashboard.html',
        total_files=total_files,
        total_size=format_file_size(total_size),
        shared_with_me=shared_with_me,
        active_links=active_links,
        recent_files=recent_files,
        activities=activities
    )


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            file_ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
            unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
            description = request.form.get('description', '')

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            file_size = os.path.getsize(filepath)

            conn = get_db()
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO files (filename, original_filename, file_size, file_type, owner_id, description)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            ''', (unique_filename, original_filename, file_size, file_ext, session['user_id'], description))
            file_id = cur.fetchone()[0]
            cur.close()
            conn.close()

            log_activity(session['user_id'], 'upload', file_id, f'Uploaded {original_filename}')
            flash(f'File "{original_filename}" uploaded successfully!', 'success')
            return redirect(url_for('my_files'))
        else:
            flash('File type not allowed.', 'error')

    return render_template('upload.html', allowed_extensions=ALLOWED_EXTENSIONS)


@app.route('/my-files')
@login_required
def my_files():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('''
        SELECT f.*, 
               (SELECT COUNT(*) FROM share_links sl WHERE sl.file_id = f.id AND sl.is_active = TRUE) as link_count,
               (SELECT COUNT(*) FROM file_shares fs WHERE fs.file_id = f.id) as share_count
        FROM files f 
        WHERE f.owner_id = %s 
        ORDER BY f.upload_date DESC
    ''', (session['user_id'],))
    files = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('my_files.html', files=files)


@app.route('/shared-with-me')
@login_required
def shared_with_me():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('''
        SELECT f.*, u.username as owner_name, fs.permission, fs.shared_at
        FROM file_shares fs
        JOIN files f ON fs.file_id = f.id
        JOIN users u ON f.owner_id = u.id
        WHERE fs.shared_with = %s
        ORDER BY fs.shared_at DESC
    ''', (session['user_id'],))
    files = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('shared_with_me.html', files=files)


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('SELECT * FROM files WHERE id = %s', (file_id,))
    file = cur.fetchone()

    if not file:
        abort(404)

    has_access = file['owner_id'] == session['user_id']
    if not has_access:
        cur.execute('SELECT id FROM file_shares WHERE file_id = %s AND shared_with = %s',
                    (file_id, session['user_id']))
        has_access = cur.fetchone() is not None

    cur.close()
    conn.close()

    if not has_access:
        abort(403)

    log_activity(session['user_id'], 'download', file_id, f'Downloaded {file["original_filename"]}')
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        file['filename'],
        as_attachment=True,
        download_name=file['original_filename']
    )


@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('SELECT * FROM files WHERE id = %s AND owner_id = %s', (file_id, session['user_id']))
    file = cur.fetchone()

    if not file:
        abort(404)

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    if os.path.exists(filepath):
        os.remove(filepath)

    cur.execute('DELETE FROM files WHERE id = %s', (file_id,))
    log_activity(session['user_id'], 'delete', None, f'Deleted {file["original_filename"]}')

    cur.close()
    conn.close()

    flash(f'File "{file["original_filename"]}" deleted.', 'success')
    return redirect(url_for('my_files'))


@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('SELECT * FROM files WHERE id = %s AND owner_id = %s', (file_id, session['user_id']))
    file = cur.fetchone()

    if not file:
        cur.close()
        conn.close()
        abort(404)

    if request.method == 'POST':
        share_type = request.form.get('share_type')

        if share_type == 'user':
            target_username = request.form.get('username', '').strip()
            permission = request.form.get('permission', 'view')

            cur.execute('SELECT id FROM users WHERE username = %s', (target_username,))
            target_user = cur.fetchone()

            if not target_user:
                flash('User not found.', 'error')
            elif target_user['id'] == session['user_id']:
                flash('You cannot share with yourself.', 'error')
            else:
                try:
                    cur.execute('''
                        INSERT INTO file_shares (file_id, shared_with, shared_by, permission)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (file_id, shared_with) DO UPDATE SET permission = %s
                    ''', (file_id, target_user['id'], session['user_id'], permission, permission))
                    log_activity(session['user_id'], 'share', file_id,
                                f'Shared with {target_username} ({permission})')
                    flash(f'File shared with {target_username}.', 'success')
                except Exception:
                    flash('Error sharing file.', 'error')

        elif share_type == 'link':
            share_token = secrets.token_urlsafe(32)
            expires_hours = request.form.get('expires_hours', '')
            max_downloads = request.form.get('max_downloads', '')
            link_password = request.form.get('link_password', '')

            expires_at = None
            if expires_hours:
                expires_at = datetime.now() + timedelta(hours=int(expires_hours))

            max_dl = None
            if max_downloads:
                max_dl = int(max_downloads)

            pwd_hash = None
            if link_password:
                pwd_hash = generate_password_hash(link_password)

            cur.execute('''
                INSERT INTO share_links (file_id, share_token, created_by, expires_at, max_downloads, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (file_id, share_token, session['user_id'], expires_at, max_dl, pwd_hash))

            log_activity(session['user_id'], 'create_link', file_id, 'Created share link')
            share_url = request.host_url.rstrip('/') + url_for('access_shared', token=share_token)
            flash(f'Share link created: {share_url}', 'success')

    cur.execute('''
        SELECT fs.*, u.username as shared_with_name
        FROM file_shares fs JOIN users u ON fs.shared_with = u.id
        WHERE fs.file_id = %s
    ''', (file_id,))
    shares = cur.fetchall()

    cur.execute('SELECT * FROM share_links WHERE file_id = %s ORDER BY created_at DESC', (file_id,))
    links = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('share.html', file=file, shares=shares, links=links)


@app.route('/shared/<token>', methods=['GET', 'POST'])
def access_shared(token):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute('''
        SELECT sl.*, f.original_filename, f.filename, f.file_size, f.file_type, u.username as owner_name
        FROM share_links sl
        JOIN files f ON sl.file_id = f.id
        JOIN users u ON sl.created_by = u.id
        WHERE sl.share_token = %s AND sl.is_active = TRUE
    ''', (token,))
    link = cur.fetchone()

    if not link:
        cur.close()
        conn.close()
        abort(404)

    if link['expires_at'] and datetime.now() > link['expires_at']:
        cur.close()
        conn.close()
        flash('This share link has expired.', 'error')
        return render_template('shared_expired.html')

    if link['max_downloads'] and link['download_count'] >= link['max_downloads']:
        cur.close()
        conn.close()
        flash('This share link has reached its download limit.', 'error')
        return render_template('shared_expired.html')

    if link['password_hash']:
        if request.method == 'POST':
            entered_password = request.form.get('password', '')
            if check_password_hash(link['password_hash'], entered_password):
                cur.execute('UPDATE share_links SET download_count = download_count + 1 WHERE id = %s', (link['id'],))
                cur.close()
                conn.close()
                return send_from_directory(
                    app.config['UPLOAD_FOLDER'],
                    link['filename'],
                    as_attachment=True,
                    download_name=link['original_filename']
                )
            else:
                flash('Incorrect password.', 'error')
        cur.close()
        conn.close()
        return render_template('shared_password.html', token=token, link=link)

    if request.method == 'POST' or request.args.get('download'):
        cur.execute('UPDATE share_links SET download_count = download_count + 1 WHERE id = %s', (link['id'],))
        cur.close()
        conn.close()
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            link['filename'],
            as_attachment=True,
            download_name=link['original_filename']
        )

    cur.close()
    conn.close()
    return render_template('shared_download.html', link=link, token=token)


@app.route('/revoke-link/<int:link_id>', methods=['POST'])
@login_required
def revoke_link(link_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE share_links SET is_active = FALSE WHERE id = %s AND created_by = %s',
                (link_id, session['user_id']))
    cur.close()
    conn.close()
    flash('Share link revoked.', 'success')
    return redirect(request.referrer or url_for('my_files'))


@app.route('/remove-share/<int:share_id>', methods=['POST'])
@login_required
def remove_share(share_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM file_shares WHERE id = %s AND shared_by = %s', (share_id, session['user_id']))
    cur.close()
    conn.close()
    flash('Share removed.', 'success')
    return redirect(request.referrer or url_for('my_files'))


@app.route('/profile')
@login_required
def profile():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()

    cur.execute('SELECT COUNT(*) FROM files WHERE owner_id = %s', (session['user_id'],))
    file_count = cur.fetchone()[0]

    cur.execute('SELECT COALESCE(SUM(file_size), 0) FROM files WHERE owner_id = %s', (session['user_id'],))
    total_size = cur.fetchone()[0]

    cur.close()
    conn.close()

    return render_template('profile.html', user=user, file_count=file_count,
                         total_size=format_file_size(total_size))


with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
