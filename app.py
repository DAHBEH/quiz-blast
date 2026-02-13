from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import sqlite3
import os
import json
from functools import wraps

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
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
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
        FOREIGN KEY (quiz_id) REFERENCES quizzes(id)
    )''')
    
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
        completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (quiz_id) REFERENCES quizzes(id),
        UNIQUE(student_id, quiz_id)
    )''')
    
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        classroom_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        custom_name TEXT NOT NULL,
        instructions TEXT,
        title TEXT,
        deadline TIMESTAMP,
        uploaded_by INTEGER NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (classroom_id) REFERENCES classrooms(id),
        FOREIGN KEY (uploaded_by) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
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
        
        if not user or user['role'] != 'teacher':
            return redirect(url_for('student_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
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
            conn.execute('INSERT INTO users (username, email, password, role, section) VALUES (?, ?, ?, ?, ?)',
                        (username, email, generate_password_hash(password), role, section))
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
    password = data.get('password', '')
    
    classroom = conn.execute('SELECT * FROM classrooms WHERE id = ?', (classroom_id,)).fetchone()
    if not classroom:
        conn.close()
        return jsonify({'error': 'Classroom not found'}), 404
    
    # Check classroom password if set
    if classroom['password']:
        if classroom['password'] != password:
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
            c.execute('INSERT INTO questions (quiz_id, question_text, question_type, correct_answer, options, question_order) VALUES (?, ?, ?, ?, ?, ?)',
                     (quiz_id, q['question'], q.get('type', quiz_type), q['correct_answer'], options, idx))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'id': quiz_id}), 201
    
    # get ang request
    quizzes = conn.execute('SELECT * FROM quizzes WHERE classroom_id = ?', (classroom_id,)).fetchall()
    conn.close()
    
    return jsonify([dict(q) for q in quizzes])

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
            c.execute('INSERT INTO questions (quiz_id, question_text, question_type, correct_answer, options, question_order) VALUES (?, ?, ?, ?, ?, ?)',
                     (quiz_id, q['question'], q.get('type', quiz_type), q['correct_answer'], options, idx))
        
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
        is_correct = student_answer.strip().lower() == q['correct_answer'].strip().lower()
        
        if is_correct:
            score += 1
        
        c.execute('INSERT INTO answers (student_id, quiz_id, question_id, answer, is_correct) VALUES (?, ?, ?, ?, ?)',
                 (session['user_id'], quiz_id, q['id'], student_answer, is_correct))
    
    percentage = (score / total * 100) if total > 0 else 0
    
    c.execute('INSERT INTO quiz_results (student_id, quiz_id, score, total_questions, percentage) VALUES (?, ?, ?, ?, ?)',
             (session['user_id'], quiz_id, score, total, percentage))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'score': score, 'total': total, 'percentage': percentage}), 201

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

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)