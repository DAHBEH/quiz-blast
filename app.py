from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import sqlite3
import os
import json
import csv
import io
from functools import wraps

# Admin secret key for direct admin access (change this!)
ADMIN_SECRET_KEY = 'G3 Capstone'

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xlsx', 'xls', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'gif'}

# make sure na yung upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect('quiz_app.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Create version tracking table for migrations
    c.execute('''CREATE TABLE IF NOT EXISTS db_version (
        version INTEGER PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get current version
    c.execute('SELECT MAX(version) FROM db_version')
    current_version = c.fetchone()[0] or 0
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        actual_password TEXT NOT NULL,
        role TEXT NOT NULL,
        section TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Classrooms table
    c.execute('''CREATE TABLE IF NOT EXISTS classrooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        teacher_id INTEGER NOT NULL,
        description TEXT,
        password TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (teacher_id) REFERENCES users(id)
    )''')
    
    # Add password column if it doesn't exist (for existing databases)
    try:
        c.execute('ALTER TABLE classrooms ADD COLUMN password TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Student enrollment
    c.execute('''CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        classroom_id INTEGER NOT NULL,
        section TEXT,
        enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (classroom_id) REFERENCES classrooms(id),
        UNIQUE(student_id, classroom_id)
    )''')
    
    # Make section column nullable in existing databases
    try:
        c.execute('ALTER TABLE enrollments ADD COLUMN section_temp TEXT')
        c.execute('UPDATE enrollments SET section_temp = section WHERE section IS NOT NULL')
        c.execute('ALTER TABLE enrollments RENAME TO enrollments_old')
        c.execute('''CREATE TABLE enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            classroom_id INTEGER NOT NULL,
            section TEXT,
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (classroom_id) REFERENCES classrooms(id),
            UNIQUE(student_id, classroom_id)
        )''')
        c.execute('INSERT INTO enrollments (id, student_id, classroom_id, section, enrolled_at) SELECT id, student_id, classroom_id, section_temp, enrolled_at FROM enrollments_old')
        c.execute('DROP TABLE enrollments_old')
    except sqlite3.OperationalError:
        pass  # Table already has nullable section
    
    # Quizzes table
    c.execute('''CREATE TABLE IF NOT EXISTS quizzes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        classroom_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        instructions TEXT,
        quiz_type TEXT NOT NULL,
        deadline TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (classroom_id) REFERENCES classrooms(id)
    )''')
    
    # Quiz questions
    c.execute('''CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        quiz_id INTEGER NOT NULL,
        question_text TEXT NOT NULL,
        question_type TEXT NOT NULL,
        correct_answer TEXT NOT NULL,
        options TEXT,
        question_order INTEGER,
        image_path TEXT,
        FOREIGN KEY (quiz_id) REFERENCES quizzes(id)
    )''')
    
    # Add image_path column if it doesn't exist (for existing databases)
    try:
        c.execute('ALTER TABLE questions ADD COLUMN image_path TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    #  answers ng students
    c.execute('''CREATE TABLE IF NOT EXISTS answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        quiz_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        answer TEXT NOT NULL,
        is_correct BOOLEAN,
        answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (quiz_id) REFERENCES quizzes(id),
        FOREIGN KEY (question_id) REFERENCES questions(id)
    )''')
    
    # ipakita ang result ng quiz
    c.execute('''CREATE TABLE IF NOT EXISTS quiz_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        quiz_id INTEGER NOT NULL,
        score INTEGER,
        total_questions INTEGER,
        percentage REAL,
        is_late BOOLEAN DEFAULT 0,
        completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (quiz_id) REFERENCES quizzes(id),
        UNIQUE(student_id, quiz_id)
    )''')
    
    # Add is_late column if it doesn't exist (for existing databases)
    try:
        c.execute('ALTER TABLE quiz_results ADD COLUMN is_late BOOLEAN DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        classroom_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        custom_name TEXT NOT NULL,
        title TEXT,
        instructions TEXT,
        deadline TIMESTAMP,
        uploaded_by INTEGER NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (classroom_id) REFERENCES classrooms(id),
        FOREIGN KEY (uploaded_by) REFERENCES users(id)
    )''')
    
    # Announcements table
    c.execute('''CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        classroom_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (classroom_id) REFERENCES classrooms(id),
        FOREIGN KEY (created_by) REFERENCES users(id)
    )''')
    
    conn.commit()
    
    # Create indexes for better query performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_classrooms_teacher ON classrooms(teacher_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_enrollments_student ON enrollments(student_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_enrollments_classroom ON enrollments(classroom_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_quizzes_classroom ON quizzes(classroom_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_questions_quiz ON questions(quiz_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_answers_student ON answers(student_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_answers_quiz ON answers(quiz_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_answers_question ON answers(question_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_quiz_results_student ON quiz_results(student_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_quiz_results_quiz ON quiz_results(quiz_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_files_classroom ON files(classroom_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_announcements_classroom ON announcements(classroom_id)')
    
    # Record database version
    DB_VERSION = 1
    if current_version < DB_VERSION:
        c.execute('INSERT OR IGNORE INTO db_version (version) VALUES (?)', (DB_VERSION,))
    
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # Verify user still exists in database
        conn = get_db()
        user = conn.execute('SELECT id FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        # Handle case where user no longer exists in database
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        if user['role'] != 'teacher':
            return redirect(url_for('student_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        # Handle case where user no longer exists in database
        if user is None:
            session.clear()
            return redirect(url_for('login'))
        if user['role'] == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        section = data.get('section')
        
        if not all([username, email, password, role]):
            return jsonify({'error': 'All fields are required'}), 400
        
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, email, password, actual_password, role, section) VALUES (?, ?, ?, ?, ?, ?)',
                        (username, email, generate_password_hash(password), password, role, section))
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Account created successfully'}), 201
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username or email already exists'}), 400
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        conn = get_db()
        user = conn.execute('SELECT id, password, role FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            return jsonify({'success': True, 'role': user['role']}), 200
        
        return jsonify({'error': 'Invalid username or password'}), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/teacher/dashboard')
@teacher_required
def teacher_dashboard():
    return render_template('teacher_dashboard.html')

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    conn = get_db()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    if user['role'] == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    
    return render_template('student_dashboard.html')

@app.route('/api/user-info')
@login_required
def get_user_info():
    conn = get_db()
    user = conn.execute('SELECT id, username, email, role, section FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'section': user['section']
    })

@app.route('/api/classrooms', methods=['GET', 'POST'])
@login_required
def handle_classrooms():
    conn = get_db()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    if request.method == 'POST':
        if user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can create classrooms'}), 403
        
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        password = data.get('password', '')
        
        if not name:
            return jsonify({'error': 'Classroom name is required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if classroom with same name already exists for this teacher
        existing = conn.execute('SELECT id FROM classrooms WHERE name = ? AND teacher_id = ?', 
                              (name, session['user_id'])).fetchone()
        if existing:
            conn.close()
            return jsonify({'error': 'This grade and section already exists. Please create a new one.'}), 400
        
        c.execute('INSERT INTO classrooms (name, teacher_id, description, password) VALUES (?, ?, ?, ?)',
                 (name, session['user_id'], description, password))
        conn.commit()
        classroom_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'id': classroom_id}), 201
    
    
    search_query = request.args.get('search', '')
    
    conn = get_db()
    if user['role'] == 'teacher':
        classrooms = conn.execute(
            'SELECT * FROM classrooms WHERE teacher_id = ? AND name LIKE ?',
            (session['user_id'], f'%{search_query}%')
        ).fetchall()
    else:
        classrooms = conn.execute(
            'SELECT c.* FROM classrooms c JOIN enrollments e ON c.id = e.classroom_id WHERE e.student_id = ? AND c.name LIKE ?',
            (session['user_id'], f'%{search_query}%')
        ).fetchall()
    conn.close()
    
    return jsonify([dict(c) for c in classrooms])

@app.route('/api/classrooms/<int:classroom_id>')
@login_required
def get_classroom(classroom_id):
    conn = get_db()
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    # i Check yung kung may access
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] == 'teacher' and classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    if user['role'] == 'student':
        enrollment = conn.execute('SELECT * FROM enrollments WHERE student_id = ? AND classroom_id = ?',
                                 (session['user_id'], classroom_id)).fetchone()
        if not enrollment:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
    
    conn.close()
    return jsonify(dict(classroom))

@app.route('/api/classrooms/<int:classroom_id>', methods=['PUT', 'DELETE'])
@login_required
def modify_classroom(classroom_id):
    conn = get_db()
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    if request.method == 'DELETE':
        # Delete related data first
        conn.execute('DELETE FROM answers WHERE quiz_id IN (SELECT id FROM quizzes WHERE classroom_id = ?)', (classroom_id,))
        conn.execute('DELETE FROM quiz_results WHERE quiz_id IN (SELECT id FROM quizzes WHERE classroom_id = ?)', (classroom_id,))
        conn.execute('DELETE FROM questions WHERE quiz_id IN (SELECT id FROM quizzes WHERE classroom_id = ?)', (classroom_id,))
        conn.execute('DELETE FROM quizzes WHERE classroom_id = ?', (classroom_id,))
        conn.execute('DELETE FROM enrollments WHERE classroom_id = ?', (classroom_id,))
        conn.execute('DELETE FROM classrooms WHERE id = ?', (classroom_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    
    if request.method == 'PUT':
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        password = data.get('password', '')
        
        if not name:
            conn.close()
            return jsonify({'error': 'Classroom name is required'}), 400
        
        # Handle password: if empty string is passed, keep it empty (removes password)
        # otherwise use the provided password
        conn.execute('UPDATE classrooms SET name = ?, description = ?, password = ? WHERE id = ?',
                    (name, description, password, classroom_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200

@app.route('/api/classrooms/<int:classroom_id>/students')
@login_required
def get_enrolled_students(classroom_id):
    conn = get_db()
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    students = conn.execute('''
        SELECT u.id, u.username, u.email, e.section, e.enrolled_at
        FROM users u
        JOIN enrollments e ON u.id = e.student_id
        WHERE e.classroom_id = ?
        ORDER BY e.enrolled_at DESC
    ''', (classroom_id,)).fetchall()
    
    conn.close()
    return jsonify([dict(s) for s in students])

@app.route('/api/classrooms/<int:classroom_id>/students/<int:student_id>', methods=['DELETE'])
@login_required
def remove_student(classroom_id, student_id):
    conn = get_db()
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    # Delete student's quiz results and answers for this classroom
    conn.execute('DELETE FROM answers WHERE student_id = ? AND quiz_id IN (SELECT id FROM quizzes WHERE classroom_id = ?)', 
                (student_id, classroom_id))
    conn.execute('DELETE FROM quiz_results WHERE student_id = ? AND quiz_id IN (SELECT id FROM quizzes WHERE classroom_id = ?)', 
                (student_id, classroom_id))
    
    # Remove enrollment
    conn.execute('DELETE FROM enrollments WHERE student_id = ? AND classroom_id = ?', 
                (student_id, classroom_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True}), 200

@app.route('/api/classrooms/<int:classroom_id>/join', methods=['POST'])
@login_required
def join_classroom(classroom_id):
    conn = get_db()
    user = conn.execute('SELECT role, section FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'student':
        conn.close()
        return jsonify({'error': 'Only students can join classrooms'}), 403
    
    data = request.get_json()
    password = data.get('password', '') or ''
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    # Check classroom password if set (not empty and not None)
    classroom_password = classroom['password'] or ''
    if classroom_password:  # If password is set, require it
        if classroom_password != password:
            conn.close()
            return jsonify({'error': 'Invalid classroom password'}), 401
    
    try:
        conn.execute('INSERT INTO enrollments (student_id, classroom_id, section) VALUES (?, ?, ?)',
                    (session['user_id'], classroom_id, user['section']))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Already enrolled in this classroom'}), 400

@app.route('/api/classrooms/search', methods=['GET'])
@login_required
def search_classrooms():
    search_query = request.args.get('q', '')
    
    conn = get_db()
    classrooms = conn.execute(
        'SELECT * FROM classrooms WHERE name LIKE ? LIMIT 10',
        (f'%{search_query}%',)
    ).fetchall()
    conn.close()
    
    return jsonify([dict(c) for c in classrooms])

@app.route('/api/classrooms/<int:classroom_id>/quizzes', methods=['GET', 'POST'])
@login_required
def handle_quizzes(classroom_id):
    conn = get_db()
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    if request.method == 'POST':
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions', '')
        quiz_type = data.get('quiz_type')
        deadline = data.get('deadline')
        questions = data.get('questions', [])
        
        if not all([title, quiz_type, questions]):
            conn.close()
            return jsonify({'error': 'Missing required fields'}), 400
        
        c = conn.cursor()
        c.execute('INSERT INTO quizzes (classroom_id, title, instructions, quiz_type, deadline) VALUES (?, ?, ?, ?, ?)',
                 (classroom_id, title, instructions, quiz_type, deadline))
        quiz_id = c.lastrowid
        
        for idx, q in enumerate(questions):
            options = json.dumps(q.get('options', [])) if 'options' in q else None
            image_path = q.get('image_path', None) if 'image_path' in q else None
            c.execute('INSERT INTO questions (quiz_id, question_text, question_type, correct_answer, options, question_order, image_path) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (quiz_id, q['question'], q.get('type', quiz_type), q['correct_answer'], options, idx, image_path))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'id': quiz_id}), 201
    
    # get ang request - check if student has completed each quiz
    quizzes = conn.execute('SELECT * FROM quizzes WHERE classroom_id = ?', (classroom_id,)).fetchall()
    
    quizzes_list = []
    for quiz in quizzes:
        quiz_dict = dict(quiz)
        # Check if student has already completed this quiz
        result = conn.execute(
            'SELECT id, score, total_questions, percentage FROM quiz_results WHERE student_id = ? AND quiz_id = ?',
            (session['user_id'], quiz['id'])
        ).fetchone()
        quiz_dict['completed'] = result is not None
        if result:
            quiz_dict['previous_score'] = result['score']
            quiz_dict['previous_total'] = result['total_questions']
            quiz_dict['previous_percentage'] = result['percentage']
        quizzes_list.append(quiz_dict)
    
    conn.close()
    
    return jsonify(quizzes_list)

@app.route('/api/quizzes/<int:quiz_id>', methods=['PUT', 'DELETE'])
@login_required
def modify_quiz(quiz_id):
    conn = get_db()
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    
    if not quiz:
        conn.close()
        return jsonify({'error': 'Quiz not found'}), 404
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (quiz['classroom_id'],)).fetchone()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    if request.method == 'DELETE':
        conn.execute('DELETE FROM answers WHERE quiz_id = ?', (quiz_id,))
        conn.execute('DELETE FROM quiz_results WHERE quiz_id = ?', (quiz_id,))
        conn.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz_id,))
        conn.execute('DELETE FROM quizzes WHERE id = ?', (quiz_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    
    if request.method == 'PUT':
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions', '')
        quiz_type = data.get('quiz_type')
        deadline = data.get('deadline')
        questions = data.get('questions', [])
        
        if not all([title, quiz_type, questions]):
            conn.close()
            return jsonify({'error': 'Missing required fields'}), 400
            
        c = conn.cursor()
        c.execute('UPDATE quizzes SET title = ?, instructions = ?, quiz_type = ?, deadline = ? WHERE id = ?',
                 (title, instructions, quiz_type, deadline, quiz_id))
        
        c.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz_id,))
        for idx, q in enumerate(questions):
            options = json.dumps(q.get('options', [])) if 'options' in q else None
            image_path = q.get('image_path', None) if 'image_path' in q else None
            c.execute('INSERT INTO questions (quiz_id, question_text, question_type, correct_answer, options, question_order, image_path) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (quiz_id, q['question'], q.get('type', quiz_type), q['correct_answer'], options, idx, image_path))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200


@app.route('/api/quizzes/<int:quiz_id>/deadline', methods=['PUT'])
@login_required
def update_quiz_deadline(quiz_id):
    conn = get_db()
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    
    if not quiz:
        conn.close()
        return jsonify({'error': 'Quiz not found'}), 404
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (quiz['classroom_id'],)).fetchone()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    deadline = data.get('deadline')
    
    conn.execute('UPDATE quizzes SET deadline = ? WHERE id = ?', (deadline, quiz_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True}), 200

@app.route('/api/quizzes/<int:quiz_id>')
@login_required
def get_quiz(quiz_id):
    conn = get_db()
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    
    if not quiz:
        conn.close()
        return jsonify({'error': 'Quiz not found'}), 404
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (quiz['classroom_id'],)).fetchone()
    
    # Check ang access ng user access
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] == 'teacher' and classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    if user['role'] == 'student':
        enrollment = conn.execute('SELECT * FROM enrollments WHERE student_id = ? AND classroom_id = ?',
                                 (session['user_id'], quiz['classroom_id'])).fetchone()
        if not enrollment:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
    
    questions = conn.execute('SELECT * FROM questions WHERE quiz_id = ? ORDER BY question_order', (quiz_id,)).fetchall()
    
    quiz_data = dict(quiz)
    quiz_data['questions'] = []
    
    for q in questions:
        q_dict = dict(q)
        if q_dict['options']:
            q_dict['options'] = json.loads(q_dict['options'])
        else:
            q_dict['options'] = []
        
        if user['role'] == 'teacher':
            quiz_data['questions'].append(q_dict)
        else:
            q_dict.pop('correct_answer', None)
            quiz_data['questions'].append(q_dict)
    
    conn.close()
    return jsonify(quiz_data)

@app.route('/api/quizzes/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    conn = get_db()
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    
    if not quiz:
        conn.close()
        return jsonify({'error': 'Quiz not found'}), 404
    
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'student':
        conn.close()
        return jsonify({'error': 'Only students can submit quizzes'}), 403
    
    # Check if student has already submitted this quiz
    existing_result = conn.execute('SELECT * FROM quiz_results WHERE student_id = ? AND quiz_id = ?',
                                  (session['user_id'], quiz_id)).fetchone()
    if existing_result:
        conn.close()
        return jsonify({'error': 'You have already submitted this quiz. You can only submit once.'}), 400
    
    data = request.get_json()
    answers = data.get('answers', {})
    
    questions = conn.execute('SELECT * FROM questions WHERE quiz_id = ?', (quiz_id,)).fetchall()
    
    c = conn.cursor()
    score = 0
    total = len(questions)
    
    for q in questions:
        student_answer = answers.get(str(q['id']), '')
        
        # For fill-blanks, require exact match (case-sensitive)
        # For other types, do case-insensitive comparison
        if q['question_type'] == 'fill-blanks':
            is_correct = student_answer.strip() == q['correct_answer'].strip()
        else:
            is_correct = student_answer.strip().lower() == q['correct_answer'].strip().lower()
        
        if is_correct:
            score += 1
        
        c.execute('INSERT INTO answers (student_id, quiz_id, question_id, answer, is_correct) VALUES (?, ?, ?, ?, ?)',
                 (session['user_id'], quiz_id, q['id'], student_answer, is_correct))
    
    percentage = (score / total * 100) if total > 0 else 0
    
    # Check if submission is late
    is_late = False
    if quiz['deadline']:
        deadline_dt = datetime.strptime(quiz['deadline'], '%Y-%m-%d %H:%M:%S') if ' ' in quiz['deadline'] else datetime.fromisoformat(quiz['deadline'].replace('T', ' '))
        is_late = datetime.now() > deadline_dt
    
    c.execute('INSERT INTO quiz_results (student_id, quiz_id, score, total_questions, percentage, is_late) VALUES (?, ?, ?, ?, ?, ?)',
             (session['user_id'], quiz_id, score, total, percentage, is_late))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'score': score, 'total': total, 'percentage': percentage, 'is_late': is_late}), 201

@app.route('/api/quizzes/<int:quiz_id>/results')
@login_required
def get_quiz_results(quiz_id):
    conn = get_db()
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    
    if not quiz:
        conn.close()
        return jsonify({'error': 'Quiz not found'}), 404
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (quiz['classroom_id'],)).fetchone()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] == 'teacher' and classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    if user['role'] == 'teacher':
        results = conn.execute('''
            SELECT qr.*, u.username, e.section
            FROM quiz_results qr
            JOIN users u ON qr.student_id = u.id
            LEFT JOIN enrollments e ON e.student_id = u.id AND e.classroom_id = ?
            WHERE qr.quiz_id = ?
            ORDER BY qr.percentage DESC
        ''', (quiz['classroom_id'], quiz_id)).fetchall()
        
        results_data = [
            {
                'student_name': r['username'],
                'section': r['section'],
                'score': r['score'],
                'total': r['total_questions'],
                'percentage': r['percentage'],
                'is_late': r['is_late'] if 'is_late' in r.keys() else False,
                'completed_at': r['completed_at']
            }
            for r in results
        ]
    else:
        result = conn.execute('SELECT * FROM quiz_results WHERE student_id = ? AND quiz_id = ?',
                             (session['user_id'], quiz_id)).fetchone()
        if not result:
            conn.close()
            return jsonify({'error': 'Quiz not completed'}), 404
        
        results_data = {
            'score': result['score'],
            'total': result['total_questions'],
            'percentage': result['percentage']
        }
    
    conn.close()
    return jsonify(results_data)

@app.route('/api/classrooms/<int:classroom_id>/files', methods=['GET', 'POST'])
@login_required
def handle_files(classroom_id):
    conn = get_db()
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    if request.method == 'POST':
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        custom_name = request.form.get('custom_name', file.filename)
        title = request.form.get('title', '')
        instructions = request.form.get('instructions', '')
        deadline = request.form.get('deadline', None)
        
        filename = secure_filename(file.filename)
        unique_filename = f"{datetime.now().timestamp()}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        c = conn.cursor()
        c.execute('INSERT INTO files (classroom_id, filename, original_filename, custom_name, title, instructions, deadline, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 (classroom_id, unique_filename, filename, custom_name, title, instructions, deadline, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True}), 201
    
    # get ang request
    files = conn.execute('SELECT * FROM files WHERE classroom_id = ?', (classroom_id,)).fetchall()
    conn.close()
    
    return jsonify([dict(f) for f in files])

@app.route('/api/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (file_record['classroom_id'],)).fetchone()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] == 'teacher' and classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    if user['role'] == 'student':
        enrollment = conn.execute('SELECT * FROM enrollments WHERE student_id = ? AND classroom_id = ?',
                                 (session['user_id'], file_record['classroom_id'])).fetchone()
        if not enrollment:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
    
    conn.close()
    
    from flask import send_file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_record['filename'])
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found on server'}), 404
    
    return send_file(filepath, as_attachment=True, download_name=file_record['original_filename'])

# ==================== QUIZ IMAGE UPLOAD ====================

@app.route('/api/quiz/upload-image', methods=['POST'])
@teacher_required
def upload_quiz_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No image selected'}), 400
    
    # Check file type
    allowed_image_types = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in allowed_image_types:
        return jsonify({'error': 'Image type not allowed. Allowed types: jpg, jpeg, png, gif, webp'}), 400
    
    filename = secure_filename(file.filename)
    unique_filename = f"quiz_{datetime.now().timestamp()}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)
    
    return jsonify({'success': True, 'image_path': unique_filename}), 201

@app.route('/uploads/<filename>')
@login_required
def serve_uploaded_file(filename):
    from flask import send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== ANNOUNCEMENTS ====================

@app.route('/api/classrooms/<int:classroom_id>/announcements', methods=['GET', 'POST'])
@login_required
def handle_announcements(classroom_id):
    conn = get_db()
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Check access
    if user['role'] == 'teacher' and classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    if user['role'] == 'student':
        enrollment = conn.execute('SELECT * FROM enrollments WHERE student_id = ? AND classroom_id = ?',
                                 (session['user_id'], classroom_id)).fetchone()
        if not enrollment:
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
    
    if request.method == 'POST':
        # Teachers can create announcements
        if user['role'] != 'teacher':
            conn.close()
            return jsonify({'error': 'Only teachers can create announcements'}), 403
        
        data = request.get_json()
        title = data.get('title')
        content = data.get('content')
        
        if not title or not content:
            conn.close()
            return jsonify({'error': 'Title and content are required'}), 400
        
        conn.execute('INSERT INTO announcements (classroom_id, title, content, created_by) VALUES (?, ?, ?, ?)',
                    (classroom_id, title, content, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True}), 201
    
    # GET - return announcements
    announcements = conn.execute('''
        SELECT a.*, u.username as creator_name
        FROM announcements a
        JOIN users u ON a.created_by = u.id
        WHERE a.classroom_id = ?
        ORDER BY a.created_at DESC
    ''', (classroom_id,)).fetchall()
    
    conn.close()
    return jsonify([dict(a) for a in announcements])

@app.route('/api/classrooms/<int:classroom_id>/announcements/<int:announcement_id>', methods=['DELETE'])
@login_required
def delete_announcement(classroom_id, announcement_id):
    conn = get_db()
    announcement = conn.execute('SELECT * FROM announcements WHERE id = ? AND classroom_id = ?', 
                              (announcement_id, classroom_id)).fetchone()
    
    if not announcement:
        conn.close()
        return jsonify({'error': 'Announcement not found'}), 404
    
    # Only the teacher who created it can delete
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] != 'teacher' or classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    conn.execute('DELETE FROM announcements WHERE id = ?', (announcement_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True}), 200

# ==================== QUIZ WRONG ANSWER STATISTICS ====================

@app.route('/api/quizzes/<int:quiz_id>/wrong-answer-stats')
@teacher_required
def get_wrong_answer_stats(quiz_id):
    conn = get_db()
    
    # Verify quiz belongs to teacher's classroom
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    if not quiz:
        conn.close()
        return jsonify({'error': 'Quiz not found'}), 404
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (quiz['classroom_id'],)).fetchone()
    if classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    # Get all questions for this quiz
    questions = conn.execute('SELECT * FROM questions WHERE quiz_id = ?', (quiz_id,)).fetchall()
    
    # Get total number of students who took the quiz
    total_students = conn.execute('SELECT COUNT(DISTINCT student_id) FROM quiz_results WHERE quiz_id = ?', 
                                  (quiz_id,)).fetchone()[0]
    
    if total_students == 0: 
        conn.close()
        return jsonify({'message': 'No students have taken this quiz yet', 'stats': []})
    
    stats = []
    for question in questions:
        # Count wrong answers for this question
        wrong_count = conn.execute('''
            SELECT COUNT(*) FROM answers
            WHERE question_id = ? AND is_correct = 0
        ''', (question['id'],)).fetchone()[0]
        
        # Count total answers for this question
        total_answers = conn.execute('''
            SELECT COUNT(*) FROM answers
            WHERE question_id = ?
        ''', (question['id'],)).fetchone()[0]
        
        wrong_percentage = (wrong_count / total_answers * 100) if total_answers > 0 else 0
        
        # Get the most common wrong answer
        wrong_answers = conn.execute('''
            SELECT answer, COUNT(*) as count
            FROM answers
            WHERE question_id = ? AND is_correct = 0
            GROUP BY answer
            ORDER BY count DESC
            LIMIT 1
        ''', (question['id'],)).fetchone()
        
        most_common_wrong = wrong_answers['answer'] if wrong_answers else None
        
        stats.append({
            'question_id': question['id'],
            'question_text': question['question_text'],
            'correct_answer': question['correct_answer'],
            'total_answers': total_answers,
            'wrong_count': wrong_count,
            'wrong_percentage': round(wrong_percentage, 2),
            'most_common_wrong_answer': most_common_wrong
        })
    
    # Sort by wrong percentage (highest first)
    stats.sort(key=lambda x: x['wrong_percentage'], reverse=True)
    
    conn.close()
    return jsonify({
        'total_students': total_students,
        'stats': stats
    })

@app.route('/api/quizzes/<int:quiz_id>/student-progress')
@teacher_required
def get_student_progress(quiz_id):
    conn = get_db()
    
    # Verify quiz belongs to teacher's classroom
    quiz = conn.execute('SELECT * FROM quizzes WHERE id = ?', (quiz_id,)).fetchone()
    if not quiz:
        conn.close()
        return jsonify({'error': 'Quiz not found'}), 404
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (quiz['classroom_id'],)).fetchone()
    if classroom['teacher_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    # Get all enrolled students and their quiz status
    students = conn.execute('''
        SELECT u.id, u.username, u.email, e.section, qr.score, qr.total_questions, qr.percentage, qr.completed_at
        FROM users u
        JOIN enrollments e ON u.id = e.student_id
        LEFT JOIN quiz_results qr ON u.id = qr.student_id AND qr.quiz_id = ?
        WHERE e.classroom_id = ?
        ORDER BY e.enrolled_at DESC
    ''', (quiz_id, quiz['classroom_id'])).fetchall()
    
    conn.close()
    return jsonify([dict(s) for s in students])

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user['role'] != 'admin':
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Admin Stats API
@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    conn = get_db()
    
    stats = {
        'total_users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'total_teachers': conn.execute("SELECT COUNT(*) FROM users WHERE role = 'teacher'").fetchone()[0],
        'total_students': conn.execute("SELECT COUNT(*) FROM users WHERE role = 'student'").fetchone()[0],
        'total_classrooms': conn.execute('SELECT COUNT(*) FROM classrooms').fetchone()[0],
        'total_quizzes': conn.execute('SELECT COUNT(*) FROM quizzes').fetchone()[0],
        'total_results': conn.execute('SELECT COUNT(*) FROM quiz_results').fetchone()[0]
    }
    
    conn.close()
    return jsonify(stats)

# Admin Users API
@app.route('/api/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    conn = get_db()
    
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'student')
        section = data.get('section')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        try:
            conn.execute('INSERT INTO users (username, email, password, actual_password, role, section) VALUES (?, ?, ?, ?, ?, ?)',
                        (username, email, generate_password_hash(password), password, role, section))
            conn.commit()
            conn.close()
            return jsonify({'success': True}), 201
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username or email already exists'}), 400
    
    search = request.args.get('search', '')
    users = conn.execute(
        'SELECT * FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY created_at DESC',
        (f'%{search}%', f'%{search}%')
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    conn = get_db()
    
    # Get user role first
    user = conn.execute('SELECT role FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    # If teacher, delete their classrooms and related data first
    if user['role'] == 'teacher':
        # Get all classrooms created by this teacher
        classrooms = conn.execute('SELECT id FROM classrooms WHERE teacher_id = ?', (user_id,)).fetchall()
        for classroom in classrooms:
            classroom_id = classroom['id']
            # Delete quizzes for this classroom
            quizzes = conn.execute('SELECT id FROM quizzes WHERE classroom_id = ?', (classroom_id,)).fetchall()
            for quiz in quizzes:
                conn.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz['id'],))
                conn.execute('DELETE FROM answers WHERE quiz_id = ?', (quiz['id'],))
                conn.execute('DELETE FROM quiz_results WHERE quiz_id = ?', (quiz['id'],))
            conn.execute('DELETE FROM quizzes WHERE classroom_id = ?', (classroom_id,))
            # Delete files
            conn.execute('DELETE FROM files WHERE classroom_id = ?', (classroom_id,))
            # Delete announcements
            conn.execute('DELETE FROM announcements WHERE classroom_id = ?', (classroom_id,))
            # Delete enrollments
            conn.execute('DELETE FROM enrollments WHERE classroom_id = ?', (classroom_id,))
        # Delete classrooms
        conn.execute('DELETE FROM classrooms WHERE teacher_id = ?', (user_id,))
    
    # Delete files uploaded by this user
    conn.execute('DELETE FROM files WHERE uploaded_by = ?', (user_id,))
    
    # Delete announcements created by this user
    conn.execute('DELETE FROM announcements WHERE created_by = ?', (user_id,))
    
    # Delete related data first
    conn.execute('DELETE FROM answers WHERE student_id = ?', (user_id,))
    conn.execute('DELETE FROM quiz_results WHERE student_id = ?', (user_id,))
    conn.execute('DELETE FROM enrollments WHERE student_id = ?', (user_id,))
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Admin Classrooms API
@app.route('/api/admin/classrooms', methods=['GET'])
@admin_required
def admin_classrooms():
    conn = get_db()
    search = request.args.get('search', '')
    
    classrooms = conn.execute('''
        SELECT c.*, u.username as teacher_username,
               (SELECT COUNT(*) FROM enrollments WHERE classroom_id = c.id) as student_count
        FROM classrooms c
        JOIN users u ON c.teacher_id = u.id
        WHERE c.name LIKE ? OR u.username LIKE ?
        ORDER BY c.created_at DESC
    ''', (f'%{search}%', f'%{search}%')).fetchall()
    
    conn.close()
    return jsonify([dict(c) for c in classrooms])

@app.route('/api/admin/classrooms/<int:classroom_id>', methods=['DELETE'])
@admin_required
def admin_delete_classroom(classroom_id):
    conn = get_db()
    
    # Delete related data
    quiz_ids = conn.execute('SELECT id FROM quizzes WHERE classroom_id = ?', (classroom_id,)).fetchall()
    for quiz in quiz_ids:
        conn.execute('DELETE FROM answers WHERE quiz_id = ?', (quiz['id'],))
        conn.execute('DELETE FROM quiz_results WHERE quiz_id = ?', (quiz['id'],))
        conn.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz['id'],))
    
    conn.execute('DELETE FROM quizzes WHERE classroom_id = ?', (classroom_id,))
    conn.execute('DELETE FROM enrollments WHERE classroom_id = ?', (classroom_id,))
    conn.execute('DELETE FROM announcements WHERE classroom_id = ?', (classroom_id,))
    conn.execute('DELETE FROM files WHERE classroom_id = ?', (classroom_id,))
    conn.execute('DELETE FROM classrooms WHERE id = ?', (classroom_id,))
    
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Admin Quizzes API
@app.route('/api/admin/quizzes', methods=['GET'])
@admin_required
def admin_quizzes():
    conn = get_db()
    search = request.args.get('search', '')
    
    quizzes = conn.execute('''
        SELECT q.*, c.name as classroom_name,
               (SELECT COUNT(*) FROM questions WHERE quiz_id = q.id) as question_count
        FROM quizzes q
        JOIN classrooms c ON q.classroom_id = c.id
        WHERE q.title LIKE ? OR c.name LIKE ?
        ORDER BY q.created_at DESC
    ''', (f'%{search}%', f'%{search}%')).fetchall()
    
    conn.close()
    return jsonify([dict(q) for q in quizzes])

@app.route('/api/admin/quizzes/<int:quiz_id>', methods=['DELETE'])
@admin_required
def admin_delete_quiz(quiz_id):
    conn = get_db()
    
    conn.execute('DELETE FROM answers WHERE quiz_id = ?', (quiz_id,))
    conn.execute('DELETE FROM quiz_results WHERE quiz_id = ?', (quiz_id,))
    conn.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz_id,))
    conn.execute('DELETE FROM quizzes WHERE id = ?', (quiz_id,))
    
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Admin Results API
@app.route('/api/admin/results', methods=['GET'])
@admin_required
def admin_results():
    conn = get_db()
    search = request.args.get('search', '')
    
    results = conn.execute('''
        SELECT qr.*, u.username as student_username, q.title as quiz_title
        FROM quiz_results qr
        JOIN users u ON qr.student_id = u.id
        JOIN quizzes q ON qr.quiz_id = q.id
        WHERE u.username LIKE ? OR q.title LIKE ?
        ORDER BY qr.completed_at DESC
    ''', (f'%{search}%', f'%{search}%')).fetchall()
    
    conn.close()
    return jsonify([dict(r) for r in results])

@app.route('/api/admin/results/<int:result_id>', methods=['DELETE'])
@admin_required
def admin_delete_result(result_id):
    conn = get_db()
    
    conn.execute('DELETE FROM answers WHERE student_id IN (SELECT student_id FROM quiz_results WHERE id = ?) AND quiz_id IN (SELECT quiz_id FROM quiz_results WHERE id = ?)', (result_id, result_id))
    conn.execute('DELETE FROM quiz_results WHERE id = ?', (result_id,))
    
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Export API
@app.route('/api/admin/export/<table>/<format>')
@admin_required
def admin_export(table, format):
    conn = get_db()
    
    valid_tables = ['users', 'classrooms', 'quizzes', 'results']
    if table not in valid_tables:
        conn.close()
        return jsonify({'error': 'Invalid table'}), 400
    
    if table == 'users':
        data = conn.execute('SELECT id, username, email, role, section, created_at FROM users').fetchall()
        headers = ['ID', 'Username', 'Email', 'Role', 'Section', 'Created At']
    elif table == 'classrooms':
        data = conn.execute('''SELECT c.id, c.name, c.description, u.username as teacher, c.created_at 
                               FROM classrooms c JOIN users u ON c.teacher_id = u.id''').fetchall()
        headers = ['ID', 'Name', 'Description', 'Teacher', 'Created At']
    elif table == 'quizzes':
        data = conn.execute('''SELECT q.id, q.title, q.quiz_type, c.name as classroom, q.deadline, q.created_at
                               FROM quizzes q JOIN classrooms c ON q.classroom_id = c.id''').fetchall()
        headers = ['ID', 'Title', 'Type', 'Classroom', 'Deadline', 'Created At']
    elif table == 'results':
        data = conn.execute('''SELECT qr.id, u.username as student, q.title as quiz, qr.score, qr.total_questions, 
                               qr.percentage, qr.completed_at
                               FROM quiz_results qr
                               JOIN users u ON qr.student_id = u.id
                               JOIN quizzes q ON qr.quiz_id = q.id''').fetchall()
        headers = ['ID', 'Student', 'Quiz', 'Score', 'Total', 'Percentage', 'Completed At']
    
    conn.close()
    
    if format == 'json':
        return jsonify([dict(row) for row in data])
    
    # CSV format
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for row in data:
        writer.writerow([row[i] for i in range(len(headers))])
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={table}.csv'}
    )

# Database Backup
@app.route('/api/admin/backup')
@admin_required
def admin_backup():
    return send_file('quiz_app.db', as_attachment=True, download_name=f'quiz_app_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')

# SQL Query (read-only for safety)
@app.route('/api/admin/sql', methods=['POST'])
@admin_required
def admin_sql():
    data = request.get_json()
    query = data.get('query', '').strip().upper()
    
    # Only allow SELECT queries for safety
    if not query.startswith('SELECT'):
        return jsonify({'error': 'Only SELECT queries are allowed for safety'}), 400
    
    # Block dangerous queries
    dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'CREATE', 'TRUNCATE']
    if any(keyword in query for keyword in dangerous_keywords):
        return jsonify({'error': 'Query contains forbidden keywords'}), 400
    
    conn = get_db()
    try:
        results = conn.execute(data.get('query')).fetchall()
        conn.close()
        return jsonify({'results': [dict(row) for row in results]})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# Reset Database
@app.route('/api/admin/reset', methods=['POST'])
@admin_required
def admin_reset():
    conn = get_db()
    
    # Delete all data from tables (keep structure)
    conn.execute('DELETE FROM answers')
    conn.execute('DELETE FROM quiz_results')
    conn.execute('DELETE FROM questions')
    conn.execute('DELETE FROM quizzes')
    conn.execute('DELETE FROM files')
    conn.execute('DELETE FROM announcements')
    conn.execute('DELETE FROM enrollments')
    conn.execute('DELETE FROM classrooms')
    conn.execute('DELETE FROM users')
    conn.execute('DELETE FROM db_version')
    
    conn.commit()
    conn.close()
    
    # Reinitialize database
    init_db()
    
    return jsonify({'success': True})

# Admin login bypass (for first-time setup)
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_bypass():
    if request.method == 'GET':
        return render_template('admin_login.html')
    data = request.get_json()
    secret = data.get('secret_key')
    
    if secret != ADMIN_SECRET_KEY:
        return jsonify({'error': 'Invalid secret key'}), 401
    
    # Find or create admin user
    conn = get_db()
    admin = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
    
    if not admin:
        # Create default admin user
        conn.execute('''INSERT INTO users (username, email, password, actual_password, role, section) 
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    ('admin', 'admin@quizapp.local', generate_password_hash('admin123'), 'admin123', 'admin', None))
        conn.commit()
        admin = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
    
    session['user_id'] = admin['id']
    session['role'] = 'admin'
    conn.close()
    
    return jsonify({'success': True, 'redirect': '/admin'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)