from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import sqlite3
import os
import re
import unicodedata

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['DATABASE'] = 'news.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def create_slug(text):
    """Create URL-friendly slug from text"""
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = re.sub(r'[^\w\s-]', '', text.lower())
    return re.sub(r'[-\s]+', '-', text).strip('-')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied', 'error')
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Public routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/article/<slug>')
def article_detail(slug):
    return render_template('article.html', slug=slug)

@app.route('/category/<slug>')
def category_page(slug):
    return render_template('category.html', slug=slug)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid credentials', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


@app.route('/admin/categories')
@admin_required
def admin_categories():
    db = get_db()
    
    # Get all categories with article counts
    categories = db.execute('''
        SELECT c.*, COUNT(a.id) as article_count
        FROM categories c
        LEFT JOIN articles a ON c.id = a.category_id
        GROUP BY c.id
        ORDER BY c.name
    ''').fetchall()
    
    # Calculate stats
    total_categories = len(categories)
    empty_categories = len([c for c in categories if c['article_count'] == 0])
    total_articles = sum(c['article_count'] for c in categories)
    
    # Find most used category
    most_used = max(categories, key=lambda x: x['article_count']) if categories else None
    
    stats = {
        'total': total_categories,
        'empty': empty_categories,
        'total_articles': total_articles,
        'most_used': most_used
    }
    
    db.close()
    return render_template('admin_categories.html', categories=categories, stats=stats)

@app.route('/admin/categories/<int:category_id>')
@admin_required
def admin_get_category(category_id):
    db = get_db()
    category = db.execute('SELECT * FROM categories WHERE id = ?', (category_id,)).fetchone()
    db.close()
    
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    
    return jsonify({
        'id': category['id'],
        'name': category['name'],
        'slug': category['slug'],
        'description': category['description'],
        'icon': category['icon'],
        'color': category['color']
    })

@app.route('/admin/categories/create', methods=['POST'])
@admin_required
def admin_create_category():
    data = request.get_json()
    
    # Validate required fields
    if not data.get('name') or not data.get('slug') or not data.get('icon') or not data.get('color'):
        return jsonify({'error': 'Name, slug, icon, and color are required'}), 400
    
    db = get_db()
    
    # Check if slug already exists
    existing = db.execute('SELECT id FROM categories WHERE slug = ?', (data['slug'],)).fetchone()
    if existing:
        db.close()
        return jsonify({'error': 'A category with this slug already exists'}), 400
    
    # Check if name already exists
    existing = db.execute('SELECT id FROM categories WHERE name = ?', (data['name'],)).fetchone()
    if existing:
        db.close()
        return jsonify({'error': 'A category with this name already exists'}), 400
    
    try:
        db.execute('''
            INSERT INTO categories (name, slug, icon, color, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data['name'],
            data['slug'],
            data['icon'],
            data['color'],
            data.get('description', '')
        ))
        db.commit()
        db.close()
        
        flash(f'Category "{data["name"]}" created successfully!', 'success')
        return jsonify({'success': True}), 200
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/categories/<int:category_id>/update', methods=['POST'])
@admin_required
def admin_update_category(category_id):
    data = request.get_json()
    
    db = get_db()
    
    # Check if category exists
    category = db.execute('SELECT * FROM categories WHERE id = ?', (category_id,)).fetchone()
    if not category:
        db.close()
        return jsonify({'error': 'Category not found'}), 404
    
    # Check if new slug conflicts with another category
    if data.get('slug') != category['slug']:
        existing = db.execute('SELECT id FROM categories WHERE slug = ? AND id != ?', 
                            (data['slug'], category_id)).fetchone()
        if existing:
            db.close()
            return jsonify({'error': 'A category with this slug already exists'}), 400
    
    # Check if new name conflicts with another category
    if data.get('name') != category['name']:
        existing = db.execute('SELECT id FROM categories WHERE name = ? AND id != ?', 
                            (data['name'], category_id)).fetchone()
        if existing:
            db.close()
            return jsonify({'error': 'A category with this name already exists'}), 400
    
    try:
        db.execute('''
            UPDATE categories 
            SET name = ?, slug = ?, icon = ?, color = ?, description = ?
            WHERE id = ?
        ''', (
            data.get('name', category['name']),
            data.get('slug', category['slug']),
            data.get('icon', category['icon']),
            data.get('color', category['color']),
            data.get('description', category['description']),
            category_id
        ))
        db.commit()
        db.close()
        
        flash(f'Category "{data["name"]}" updated successfully!', 'success')
        return jsonify({'success': True}), 200
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/categories/<int:category_id>/delete', methods=['POST'])
@admin_required
def admin_delete_category(category_id):
    db = get_db()
    
    # Check if category exists
    category = db.execute('SELECT * FROM categories WHERE id = ?', (category_id,)).fetchone()
    if not category:
        db.close()
        return jsonify({'error': 'Category not found'}), 404
    
    # Check if category has articles
    article_count = db.execute('SELECT COUNT(*) as count FROM articles WHERE category_id = ?', 
                               (category_id,)).fetchone()['count']
    
    if article_count > 0:
        db.close()
        return jsonify({'error': f'Cannot delete category with {article_count} article(s). Please move or delete the articles first.'}), 400
    
    try:
        db.execute('DELETE FROM categories WHERE id = ?', (category_id,))
        db.commit()
        db.close()
        
        flash(f'Category "{category["name"]}" deleted successfully!', 'success')
        return jsonify({'success': True}), 200
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

@app.route('/admin')
@login_required
def admin_dashboard():
    db = get_db()
    
    # Basic stats
    stats = {
        'total_articles': db.execute('SELECT COUNT(*) as count FROM articles').fetchone()['count'],
        'published': db.execute('SELECT COUNT(*) as count FROM articles WHERE status = "published"').fetchone()['count'],
        'drafts': db.execute('SELECT COUNT(*) as count FROM articles WHERE status = "draft"').fetchone()['count'],
        'total_views': db.execute('SELECT SUM(view_count) as total FROM articles').fetchone()['total'] or 0,
        'total_comments': db.execute('SELECT COUNT(*) as count FROM comments').fetchone()['count'],
        'subscribers': db.execute('SELECT COUNT(*) as count FROM newsletter').fetchone()['count'],
        'total_categories': db.execute('SELECT COUNT(*) as count FROM categories').fetchone()['count']
    }
    
    # Add pending count for admins
    if session.get('role') == 'admin':
        stats['pending'] = db.execute('SELECT COUNT(*) as count FROM articles WHERE status = "pending"').fetchone()['count']
    
    # Recent articles (last 5)
    recent_articles = db.execute('''
        SELECT a.*, c.name as category_name, u.full_name as author_name
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        LEFT JOIN users u ON a.author_id = u.id
        ORDER BY a.created_at DESC LIMIT 5
    ''').fetchall()
    
    # Top performing articles (by views)
    top_articles = db.execute('''
        SELECT a.id, a.title, a.cover_image, a.view_count as views, a.created_at,
               c.name as category_name,
               (SELECT COUNT(*) FROM comments WHERE article_id = a.id) as comment_count
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        WHERE a.status = "published"
        ORDER BY a.view_count DESC LIMIT 10
    ''').fetchall()
    
    db.close()
    
    return render_template('admin_dashboard.html', 
                         stats=stats, 
                         recent_articles=recent_articles,
                         top_articles=top_articles)

@app.route('/admin/articles')
@login_required
def admin_articles():
    db = get_db()
    
    status = request.args.get('status', 'all')
    query = '''
        SELECT a.*, c.name as category_name, u.full_name as author_name
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        LEFT JOIN users u ON a.author_id = u.id
    '''
    
    if status != 'all':
        query += f" WHERE a.status = '{status}'"
    
    if session.get('role') == 'writer':
        query += f" {'WHERE' if status == 'all' else 'AND'} a.author_id = {session['user_id']}"
    
    query += ' ORDER BY a.created_at DESC'
    
    articles = db.execute(query).fetchall()
    db.close()
    
    return render_template('admin_articles.html', articles=articles, current_status=status)

@app.route('/admin/articles/new', methods=['GET', 'POST'])
@login_required
def admin_new_article():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        excerpt = request.form.get('excerpt')
        category_id = request.form.get('category_id')
        status = request.form.get('status', 'draft')
        featured = 1 if request.form.get('featured') else 0
        breaking = 1 if request.form.get('breaking') else 0
        cover_image = request.form.get('cover_image')
        meta_description = request.form.get('meta_description') or excerpt[:160]
        meta_keywords = request.form.get('meta_keywords', '')
        
        # Writers can only save as draft or submit for review (pending)
        if session.get('role') == 'writer':
            if status not in ['draft', 'pending']:
                status = 'pending'  # Force to pending if writer tries to publish
            featured = 0  # Writers cannot set featured
            breaking = 0  # Writers cannot set breaking
        
        # Generate slug
        base_slug = create_slug(title)
        slug = base_slug
        counter = 1
        
        db = get_db()
        while db.execute('SELECT id FROM articles WHERE slug = ?', (slug,)).fetchone():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        # Calculate reading time (average 200 words per minute)
        words = len(re.sub(r'<[^>]+>', '', content).split())
        reading_time = max(1, round(words / 200))
        
        published_at = datetime.now().isoformat() if status == 'published' else None
        
        db.execute('''
            INSERT INTO articles (title, slug, content, excerpt, cover_image, meta_description, meta_keywords,
                                status, featured, breaking, reading_time, author_id, category_id, published_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, slug, content, excerpt, cover_image, meta_description, meta_keywords,
              status, featured, breaking, reading_time, session['user_id'], category_id, published_at))
        
        article_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Handle tags
        tag_ids = request.form.getlist('tags')
        for tag_id in tag_ids:
            db.execute('INSERT INTO article_tags (article_id, tag_id) VALUES (?, ?)', (article_id, tag_id))
        
        db.commit()
        db.close()
        
        if status == 'pending':
            flash('Article submitted for review! An admin will review and publish it.', 'success')
        else:
            flash('Article created successfully!', 'success')
        return redirect(url_for('admin_articles'))
    
    db = get_db()
    categories = db.execute('SELECT * FROM categories').fetchall()
    tags = db.execute('SELECT * FROM tags').fetchall()
    db.close()
    
    return render_template('admin_article_form.html', categories=categories, tags=tags, article=None)

@app.route('/admin/articles/<int:article_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_article(article_id):
    db = get_db()
    article = db.execute('SELECT * FROM articles WHERE id = ?', (article_id,)).fetchone()
    
    if not article:
        flash('Article not found', 'error')
        return redirect(url_for('admin_articles'))
    
    if session.get('role') == 'writer' and article['author_id'] != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('admin_articles'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        excerpt = request.form.get('excerpt')
        category_id = request.form.get('category_id')
        status = request.form.get('status')
        featured = 1 if request.form.get('featured') else 0
        breaking = 1 if request.form.get('breaking') else 0
        cover_image = request.form.get('cover_image')
        meta_description = request.form.get('meta_description') or excerpt[:160]
        meta_keywords = request.form.get('meta_keywords', '')
        
        # Writers can only save as draft or submit for review (pending)
        if session.get('role') == 'writer':
            if status not in ['draft', 'pending']:
                status = 'pending'  # Force to pending if writer tries to publish
            featured = 0  # Writers cannot change featured
            breaking = 0  # Writers cannot change breaking
        
        words = len(re.sub(r'<[^>]+>', '', content).split())
        reading_time = max(1, round(words / 200))
        
        published_at = article['published_at']
        # Only admins can set published_at
        if status == 'published' and not published_at and session.get('role') == 'admin':
            published_at = datetime.now().isoformat()
        
        db.execute('''
            UPDATE articles SET title = ?, content = ?, excerpt = ?, cover_image = ?,
                              meta_description = ?, meta_keywords = ?, status = ?, featured = ?, 
                              breaking = ?, reading_time = ?, category_id = ?, published_at = ?, 
                              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (title, content, excerpt, cover_image, meta_description, meta_keywords, status, 
              featured, breaking, reading_time, category_id, published_at, article_id))
        
        # Update tags
        db.execute('DELETE FROM article_tags WHERE article_id = ?', (article_id,))
        tag_ids = request.form.getlist('tags')
        for tag_id in tag_ids:
            db.execute('INSERT INTO article_tags (article_id, tag_id) VALUES (?, ?)', (article_id, tag_id))
        
        db.commit()
        db.close()
        
        if status == 'pending' and session.get('role') == 'writer':
            flash('Article submitted for review! An admin will review and publish it.', 'success')
        else:
            flash('Article updated successfully!', 'success')
        return redirect(url_for('admin_articles'))
    
    categories = db.execute('SELECT * FROM categories').fetchall()
    tags = db.execute('SELECT * FROM tags').fetchall()
    article_tags = [row['tag_id'] for row in db.execute(
        'SELECT tag_id FROM article_tags WHERE article_id = ?', (article_id,)
    ).fetchall()]
    db.close()
    
    return render_template('admin_article_form.html', categories=categories, tags=tags, 
                         article=article, article_tags=article_tags)

@app.route('/admin/articles/<int:article_id>/delete', methods=['POST'])
@login_required
def admin_delete_article(article_id):
    db = get_db()
    article = db.execute('SELECT * FROM articles WHERE id = ?', (article_id,)).fetchone()
    
    if not article:
        flash('Article not found', 'error')
    elif session.get('role') == 'writer' and article['author_id'] != session['user_id']:
        flash('Access denied', 'error')
    else:
        db.execute('DELETE FROM articles WHERE id = ?', (article_id,))
        db.commit()
        flash('Article deleted successfully!', 'success')
    
    db.close()
    return redirect(url_for('admin_articles'))

@app.route('/admin/upload', methods=['POST'])
@login_required
def admin_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400
    
    filename = secure_filename(file.filename)
    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    return jsonify({'url': f"/static/uploads/{filename}"}), 200

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    db = get_db()
    
    if request.method == 'POST':
        db.execute('''
            UPDATE settings SET site_name = ?, tagline = ?, description = ?, breaking_news = ?,
                              contact_email = ?, contact_phone = ?, address = ?,
                              twitter_url = ?, facebook_url = ?, instagram_url = ?, 
                              youtube_url = ?, linkedin_url = ?
            WHERE id = 1
        ''', (request.form.get('site_name'), request.form.get('tagline'),
              request.form.get('description'), request.form.get('breaking_news'),
              request.form.get('contact_email'), request.form.get('contact_phone'), 
              request.form.get('address'), request.form.get('twitter_url'), 
              request.form.get('facebook_url'), request.form.get('instagram_url'), 
              request.form.get('youtube_url'), request.form.get('linkedin_url')))
        
        db.commit()
        flash('Settings updated successfully!', 'success')
    
    settings = db.execute('SELECT * FROM settings LIMIT 1').fetchone()
    db.close()
    
    return render_template('admin_settings.html', settings=settings)

# Newsletter Management Routes
@app.route('/admin/newsletter')
@login_required
def admin_newsletter():
    db = get_db()
    
    # Get all subscribers
    subscribers = db.execute('''
        SELECT * FROM newsletter 
        ORDER BY subscribed_at DESC
    ''').fetchall()
    
    # Calculate stats
    from datetime import datetime, timedelta
    today = datetime.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)
    
    stats = {
        'total': len(subscribers),
        'today': len([s for s in subscribers if s['subscribed_at'][:10] == today.strftime('%Y-%m-%d')]),
        'this_week': len([s for s in subscribers if s['subscribed_at'][:10] >= week_ago.strftime('%Y-%m-%d')]),
        'this_month': len([s for s in subscribers if s['subscribed_at'][:10] >= month_ago.strftime('%Y-%m-%d')])
    }
    
    db.close()
    return render_template('admin_newsletter.html', subscribers=subscribers, stats=stats)

@app.route('/admin/newsletter/<int:subscriber_id>/delete', methods=['POST'])
@login_required
def admin_delete_subscriber(subscriber_id):
    db = get_db()
    db.execute('DELETE FROM newsletter WHERE id = ?', (subscriber_id,))
    db.commit()
    db.close()
    return jsonify({'success': True}), 200

@app.route('/admin/newsletter/bulk-delete', methods=['POST'])
@login_required
def admin_bulk_delete_subscribers():
    data = request.get_json()
    ids = data.get('ids', [])
    
    if not ids:
        return jsonify({'error': 'No IDs provided'}), 400
    
    db = get_db()
    placeholders = ','.join('?' * len(ids))
    db.execute(f'DELETE FROM newsletter WHERE id IN ({placeholders})', ids)
    db.commit()
    db.close()
    
    return jsonify({'success': True}), 200

@app.route('/admin/newsletter/export')
@login_required
def admin_export_subscribers():
    import csv
    from io import StringIO
    from flask import make_response
    
    db = get_db()
    subscribers = db.execute('SELECT email, subscribed_at FROM newsletter ORDER BY subscribed_at DESC').fetchall()
    db.close()
    
    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Email', 'Subscribed Date'])
    
    for sub in subscribers:
        writer.writerow([sub['email'], sub['subscribed_at']])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=newsletter_subscribers.csv"
    output.headers["Content-type"] = "text/csv"
    
    return output

# User Management Routes
@app.route('/admin/users')
@admin_required
def admin_users():
    role_filter = request.args.get('role', 'all')
    
    db = get_db()
    
    # Build query based on role filter
    if role_filter == 'all':
        query = '''
            SELECT u.*, COUNT(a.id) as article_count
            FROM users u
            LEFT JOIN articles a ON u.id = a.author_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        '''
        users = db.execute(query).fetchall()
    else:
        query = '''
            SELECT u.*, COUNT(a.id) as article_count
            FROM users u
            LEFT JOIN articles a ON u.id = a.author_id
            WHERE u.role = ?
            GROUP BY u.id
            ORDER BY u.created_at DESC
        '''
        users = db.execute(query, (role_filter,)).fetchall()
    
    # Calculate stats
    from datetime import datetime, timedelta
    month_ago = datetime.now() - timedelta(days=30)
    
    stats = {
        'total': db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count'],
        'admins': db.execute('SELECT COUNT(*) as count FROM users WHERE role = "admin"').fetchone()['count'],
        'writers': db.execute('SELECT COUNT(*) as count FROM users WHERE role = "writer"').fetchone()['count'],
        'active_month': db.execute('SELECT COUNT(DISTINCT author_id) as count FROM articles WHERE created_at >= ?', (month_ago,)).fetchone()['count']
    }
    
    db.close()
    return render_template('admin_users.html', users=users, stats=stats, current_role=role_filter)

@app.route('/admin/users/<int:user_id>')
@admin_required
def admin_get_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'full_name': user['full_name'],
        'email': user['email'],
        'role': user['role'],
        'bio': user['bio']
    })

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.get_json()
    
    # Validate required fields
    if not data.get('username') or not data.get('full_name') or not data.get('password'):
        return jsonify({'error': 'Username, full name, and password are required'}), 400
    
    db = get_db()
    
    # Check if username already exists
    existing = db.execute('SELECT id FROM users WHERE username = ?', (data['username'],)).fetchone()
    if existing:
        db.close()
        return jsonify({'error': 'Username already exists'}), 400
    
    # Hash password
    from werkzeug.security import generate_password_hash
    hashed_password = generate_password_hash(data['password'])
    
    # Insert new user
    try:
        db.execute('''
            INSERT INTO users (username, password, full_name, email, role, bio, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        ''', (
            data['username'],
            hashed_password,
            data['full_name'],
            data.get('email', ''),
            data.get('role', 'writer'),
            data.get('bio', '')
        ))
        db.commit()
        db.close()
        
        flash(f'User {data["full_name"]} created successfully!', 'success')
        return jsonify({'success': True}), 200
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    data = request.get_json()
    
    db = get_db()
    
    # Check if user exists
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404
    
    # Check if new username conflicts with another user
    if data.get('username') != user['username']:
        existing = db.execute('SELECT id FROM users WHERE username = ? AND id != ?', 
                            (data['username'], user_id)).fetchone()
        if existing:
            db.close()
            return jsonify({'error': 'Username already exists'}), 400
    
    # Build update query
    if data.get('password'):
        from werkzeug.security import generate_password_hash
        hashed_password = generate_password_hash(data['password'])
        db.execute('''
            UPDATE users 
            SET username = ?, full_name = ?, email = ?, role = ?, bio = ?, password = ?
            WHERE id = ?
        ''', (
            data.get('username', user['username']),
            data.get('full_name', user['full_name']),
            data.get('email', user['email']),
            data.get('role', user['role']),
            data.get('bio', user['bio']),
            hashed_password,
            user_id
        ))
    else:
        db.execute('''
            UPDATE users 
            SET username = ?, full_name = ?, email = ?, role = ?, bio = ?
            WHERE id = ?
        ''', (
            data.get('username', user['username']),
            data.get('full_name', user['full_name']),
            data.get('email', user['email']),
            data.get('role', user['role']),
            data.get('bio', user['bio']),
            user_id
        ))
    
    db.commit()
    db.close()
    
    flash('User updated successfully!', 'success')
    return jsonify({'success': True}), 200

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    # Prevent deleting yourself
    if user_id == session.get('user_id'):
        return jsonify({'error': 'You cannot delete your own account'}), 400
    
    db = get_db()
    
    # Check if user exists
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404
    
    # Delete user (articles will remain but show as deleted user)
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    db.close()
    
    flash(f'User {user["full_name"]} deleted successfully!', 'success')
    return jsonify({'success': True}), 200



# API routes
@app.route('/api/settings')
def get_settings():
    db = get_db()
    settings = db.execute('SELECT * FROM settings LIMIT 1').fetchone()
    db.close()
    return jsonify(dict(settings)) if settings else jsonify({})

@app.route('/api/categories')
def get_categories():
    db = get_db()
    categories = db.execute('SELECT * FROM categories ORDER BY name').fetchall()
    db.close()
    return jsonify([dict(cat) for cat in categories])

@app.route('/api/tags')
def get_tags():
    db = get_db()
    tags = db.execute('SELECT * FROM tags ORDER BY name LIMIT 20').fetchall()
    db.close()
    return jsonify([dict(tag) for tag in tags])

@app.route('/api/articles/featured')
def get_featured_articles():
    db = get_db()
    articles = db.execute('''
        SELECT a.*, c.name as category_name, c.slug as category_slug, c.color as category_color,
               u.full_name as author_name, u.profile_image as author_avatar, u.bio as author_bio
        FROM articles a
        JOIN categories c ON a.category_id = c.id
        JOIN users u ON a.author_id = u.id
        WHERE a.status = 'published' AND a.featured = 1
        ORDER BY a.published_at DESC LIMIT 3
    ''').fetchall()
    db.close()
    
    result = []
    for a in articles:
        result.append({
            'id': a['id'], 'title': a['title'], 'slug': a['slug'], 'excerpt': a['excerpt'],
            'image_url': a['cover_image'], 'read_time': f"{a['reading_time']} min read",
            'views': a['view_count'], 'featured': bool(a['featured']), 'breaking': bool(a['breaking']),
            'date': datetime.fromisoformat(a['published_at']).strftime('%B %d, %Y'),
            'date_iso': datetime.fromisoformat(a['published_at']).strftime('%Y-%m-%d'),
            'category': {
                'name': a['category_name'], 
                'slug': a['category_slug'],
                'color': a['category_color']
            },
            'author': {
                'full_name': a['author_name'],
                'avatar_url': a['author_avatar'] or f"https://ui-avatars.com/api/?name={a['author_name']}&background=random",
                'bio': a['author_bio']
            }
        })
    return jsonify(result)

@app.route('/api/articles/trending')
def get_trending_articles():
    limit = request.args.get('limit', 5, type=int)
    db = get_db()
    articles = db.execute('''
        SELECT id, title, slug, view_count as views, published_at, cover_image
        FROM articles WHERE status = 'published'
        ORDER BY view_count DESC LIMIT ?
    ''', (limit,)).fetchall()
    db.close()
    
    return jsonify([{
        'id': a['id'], 'title': a['title'], 'slug': a['slug'],
        'views': a['views'], 'image_url': a['cover_image'],
        'date_iso': datetime.fromisoformat(a['published_at']).strftime('%Y-%m-%d')
    } for a in articles])

@app.route('/api/articles')
def get_articles():
    category = request.args.get('category', 'All')
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 8, type=int)
    
    db = get_db()
    query = '''
        SELECT a.*, c.name as category_name, c.slug as category_slug, c.color as category_color,
               u.full_name as author_name, u.profile_image as author_avatar
        FROM articles a
        JOIN categories c ON a.category_id = c.id
        JOIN users u ON a.author_id = u.id
        WHERE a.status = 'published'
    '''
    params = []
    
    if category != 'All':
        query += ' AND c.slug = ?'
        params.append(category)
    
    query += ' ORDER BY a.published_at DESC LIMIT ? OFFSET ?'
    params.extend([limit + 1, (page - 1) * limit])
    
    articles = db.execute(query, params).fetchall()
    db.close()
    
    has_next = len(articles) > limit
    articles = articles[:limit]
    
    result = []
    for a in articles:
        result.append({
            'id': a['id'], 'title': a['title'], 'slug': a['slug'], 'excerpt': a['excerpt'],
            'image_url': a['cover_image'], 'read_time': f"{a['reading_time']} min read",
            'views': a['view_count'], 'featured': bool(a['featured']), 'breaking': bool(a['breaking']),
            'date': datetime.fromisoformat(a['published_at']).strftime('%B %d, %Y'),
            'date_iso': datetime.fromisoformat(a['published_at']).strftime('%Y-%m-%d'),
            'category': {
                'name': a['category_name'],
                'slug': a['category_slug'],
                'color': a['category_color']
            },
            'author': {
                'full_name': a['author_name'],
                'avatar_url': a['author_avatar'] or f"https://ui-avatars.com/api/?name={a['author_name']}&background=random"
            }
        })
    
    return jsonify({'articles': result, 'has_next': has_next})

@app.route('/api/article/<slug>')
def get_article_by_slug(slug):
    db = get_db()
    article = db.execute('''
        SELECT a.*, c.name as category_name, c.slug as category_slug, c.color as category_color,
               u.full_name as author_name, u.profile_image as author_avatar, u.bio as author_bio
        FROM articles a
        JOIN categories c ON a.category_id = c.id
        JOIN users u ON a.author_id = u.id
        WHERE a.slug = ? AND a.status = 'published'
    ''', (slug,)).fetchone()
    
    if not article:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    
    comments = db.execute('''
        SELECT * FROM comments 
        WHERE article_id = ? AND status = "approved"
        ORDER BY created_at DESC
    ''', (article['id'],)).fetchall()
    
    tags = db.execute('''
        SELECT t.name, t.slug FROM tags t 
        JOIN article_tags at ON t.id = at.tag_id 
        WHERE at.article_id = ?
    ''', (article['id'],)).fetchall()
    
    # Get related articles (same category, exclude current)
    related = db.execute('''
        SELECT a.id, a.title, a.slug, a.cover_image, a.excerpt, a.reading_time,
               c.name as category_name, c.color as category_color
        FROM articles a
        JOIN categories c ON a.category_id = c.id
        WHERE a.category_id = ? AND a.id != ? AND a.status = 'published'
        ORDER BY a.published_at DESC LIMIT 3
    ''', (article['category_id'], article['id'])).fetchall()
    
    # Update view count
    db.execute('UPDATE articles SET view_count = view_count + 1 WHERE id = ?', (article['id'],))
    db.commit()
    db.close()
    
    # Build canonical URL
    canonical_url = f"{request.host_url}article/{article['slug']}"
    
    return jsonify({
        'id': article['id'], 
        'title': article['title'], 
        'slug': article['slug'],
        'content': article['content'],
        'excerpt': article['excerpt'], 
        'image_url': article['cover_image'],
        'meta_description': article['meta_description'],
        'meta_keywords': article['meta_keywords'],
        'canonical_url': canonical_url,
        'read_time': f"{article['reading_time']} min read", 
        'views': article['view_count'] + 1,
        'date': datetime.fromisoformat(article['published_at']).strftime('%B %d, %Y'),
        'date_iso': datetime.fromisoformat(article['published_at']).strftime('%Y-%m-%d'),
        'updated_at': article['updated_at'],
        'category': {
            'name': article['category_name'],
            'slug': article['category_slug'],
            'color': article['category_color']
        },
        'author': {
            'full_name': article['author_name'],
            'avatar_url': article['author_avatar'] or f"https://ui-avatars.com/api/?name={article['author_name']}&background=random",
            'bio': article['author_bio']
        },
        'tags': [{'name': t['name'], 'slug': t['slug']} for t in tags],
        'comments': [{
            'author_name': c['author_name'], 
            'content': c['content'],
            'created_at': datetime.fromisoformat(c['created_at']).strftime('%B %d, %Y at %I:%M %p')
        } for c in comments],
        'related': [{
            'id': r['id'],
            'title': r['title'],
            'slug': r['slug'],
            'image_url': r['cover_image'],
            'excerpt': r['excerpt'],
            'read_time': f"{r['reading_time']} min read",
            'category': {
                'name': r['category_name'],
                'color': r['category_color']
            }
        } for r in related]
    })

@app.route('/api/search')
def search_articles():
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    
    db = get_db()
    articles = db.execute('''
        SELECT a.id, a.title, a.slug, a.published_at, a.cover_image, a.excerpt,
               c.name as category_name, c.slug as category_slug, c.color as category_color
        FROM articles a 
        JOIN categories c ON a.category_id = c.id
        WHERE a.status = 'published' AND (a.title LIKE ? OR a.excerpt LIKE ? OR a.content LIKE ?) 
        ORDER BY a.published_at DESC
        LIMIT 10
    ''', (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
    db.close()
    
    return jsonify([{
        'id': a['id'], 
        'title': a['title'],
        'slug': a['slug'],
        'excerpt': a['excerpt'][:100] + '...' if a['excerpt'] else '',
        'image_url': a['cover_image'],
        'date_iso': datetime.fromisoformat(a['published_at']).strftime('%Y-%m-%d'),
        'category': {
            'name': a['category_name'],
            'slug': a['category_slug'],
            'color': a['category_color']
        }
    } for a in articles])

@app.route('/api/comment', methods=['POST'])
def create_comment():
    data = request.get_json()
    
    if not data.get('article_id') or not data.get('content'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    db = get_db()
    db.execute('''
        INSERT INTO comments (article_id, author_name, author_email, content, status) 
        VALUES (?, ?, ?, ?, 'pending')
    ''', (data['article_id'], 
          data.get('author_name', 'Anonymous'),
          data.get('author_email', 'anon@example.com'), 
          data['content']))
    db.commit()
    db.close()
    
    return jsonify({'message': 'Comment submitted for moderation'}), 201

@app.route('/api/newsletter', methods=['POST'])
def subscribe_newsletter():
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({'error': 'Email required'}), 400
    
    db = get_db()
    try:
        db.execute('INSERT INTO newsletter (email) VALUES (?)', (data['email'],))
        db.commit()
        msg = 'Successfully subscribed to our newsletter!'
    except:
        msg = 'You are already subscribed!'
    db.close()
    
    return jsonify({'message': msg})

if __name__ == '__main__':
    print("\n🚀 Eastern Star News Platform")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)