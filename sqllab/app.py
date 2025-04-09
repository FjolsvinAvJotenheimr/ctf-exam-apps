import os
import time
import sqlite3
import random
import re
import uuid
import shutil
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response

app = Flask(__name__)
app.secret_key = '4nc13nt_3gypt11n_53cr3t_k3y'

# Database directory for per-user databases
DB_DIR = 'user_databases'

# Clean up any existing databases on startup
if os.path.exists(DB_DIR):
    shutil.rmtree(DB_DIR)
    
os.makedirs(DB_DIR, exist_ok=True)

# Session timeout in seconds (1 hour)
SESSION_TIMEOUT = 3600

# Blacklist for SQL injection in the soldier dashboard
BLACKLIST = ["UNION", "union", "SELECT", "select", "AND", "and", "FROM", "from", "null", "NULL"]

# Check if session needs to be reset
def check_session_timeout():
    # Check if session needs to be initialized
    if 'user_db_id' not in session or 'session_start_time' not in session:
        reset_user_session()
        return False
        
    # Check if session has expired
    current_time = time.time()
    session_age = current_time - session['session_start_time']
    
    if session_age > SESSION_TIMEOUT:
        # Session has expired
        reset_user_session(expired=True)
        return True
    
    # Calculate remaining time (for server-side tracking)
    session['time_remaining'] = SESSION_TIMEOUT - session_age
    return False

# Reset user session
def reset_user_session(expired=False):
    # If there was a previous session, try to delete the database
    if 'user_db_id' in session:
        try:
            user_dir = os.path.join(DB_DIR, session['user_db_id'])
            if os.path.exists(user_dir):
                shutil.rmtree(user_dir)
        except Exception as e:
            print(f"Error removing database directory: {e}")
    
    # Create new session
    session['user_db_id'] = str(uuid.uuid4())
    session['session_start_time'] = time.time()
    session['time_remaining'] = SESSION_TIMEOUT
    
    # Ensure session is saved
    session.modified = True
    
    # If this was an expiration, set a flash message
    if expired:
        flash("Session time limit reached. A new session has been started.", "warning")

# Function to check for blacklisted SQL injection words
def contains_blacklisted_word(query):
    for word in BLACKLIST:
        if word in query:
            return True
    return False

# Get user-specific database connection
def get_db(environment='soldier'):
    # Check if session has timed out
    check_session_timeout()
    
    # Construct the database path for this user
    user_dir = os.path.join(DB_DIR, session['user_db_id'])
    os.makedirs(user_dir, exist_ok=True)
    
    # Use separate database files for each environment
    db_path = os.path.join(user_dir, f"{environment}.db")
    
    # If the database doesn't exist yet, initialize it
    if not os.path.exists(db_path):
        init_db(db_path, environment)
    
    # Connect to the specific database
    conn = sqlite3.connect(db_path)
    
    # Allow multiple statements to be executed
    conn.isolation_level = None
    
    # Enable row factory for dictionary-like access
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database with unique path and separate environments
def init_db(db_path, environment='soldier'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    if environment == 'soldier':
        # Initialize soldier environment
        # Drop tables first to ensure clean state - use DROP TABLE IF EXISTS
        cursor.execute('DROP TABLE IF EXISTS workers')
        cursor.execute('DROP TABLE IF EXISTS soldiers')
        cursor.execute('DROP TABLE IF EXISTS pharaohs_secret')
        cursor.execute('DROP TABLE IF EXISTS soldier_schema_tables')
        cursor.execute('DROP TABLE IF EXISTS soldier_schema_columns')
        
        # Create workers table
        cursor.execute('''
        CREATE TABLE workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'worker'
        )
        ''')
        
        # Create soldiers table
        cursor.execute('''
        CREATE TABLE soldiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            rank TEXT NOT NULL,
            strength INTEGER NOT NULL,
            loyalty TEXT NOT NULL
        )
        ''')
        
        # Create pharaohs_secret table for credentials discovery
        cursor.execute('''
        CREATE TABLE pharaohs_secret (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            access_level TEXT NOT NULL
        )
        ''')
        
        # Insert pharaoh credentials
        cursor.execute("INSERT INTO pharaohs_secret (username, access_level) VALUES ('khufu', 'pharaoh')")
        
        # Create a special fake table to simulate information_schema.tables
        cursor.execute('''
        CREATE TABLE soldier_schema_tables (
            table_name TEXT PRIMARY KEY
        )
        ''')
        
        # Populate the fake schema table with visible tables
        tables = [
            ('workers',),
            ('soldiers',),
            ('pharaohs_secret',)
        ]
        
        for table in tables:
            cursor.execute("INSERT INTO soldier_schema_tables (table_name) VALUES (?)", table)
            
        # Create a special fake table to simulate information_schema.columns
        cursor.execute('''
        CREATE TABLE soldier_schema_columns (
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            PRIMARY KEY (table_name, column_name)
        )
        ''')
        
        # Add columns for tables
        columns_data = [        
            # soldiers columns
            ('soldiers', 'id'),
            ('soldiers', 'name'),
            ('soldiers', 'rank'),
            ('soldiers', 'strength'),
            ('soldiers', 'loyalty'),
            
            # workers columns
            ('workers', 'id'),
            ('workers', 'username'),
            ('workers', 'password'),
            ('workers', 'role'),
            
            # pharaohs_secret columns
            ('pharaohs_secret', 'id'),
            ('pharaohs_secret', 'username'),
            ('pharaohs_secret', 'access_level')
        ]
        
        for column in columns_data:
            cursor.execute("INSERT INTO soldier_schema_columns (table_name, column_name) VALUES (?, ?)", column)
        
        # Add a soldier account
        cursor.execute("INSERT INTO workers (username, password, role) VALUES ('soldier', 'warrior_of_ra', 'soldier')")
        
        # Add some regular soldiers
        soldiers_data = [
            ('ramses', 'regular', 75, 'high'),
            ('neferu', 'archer', 65, 'medium'),
            ('khonsu', 'charioteer', 80, 'high'),
            ('sebek', 'elite', 90, 'absolute'),
            ('tauret', 'regular', 70, 'medium')
        ]
        for soldier in soldiers_data:
            cursor.execute("INSERT INTO soldiers (name, rank, strength, loyalty) VALUES (?, ?, ?, ?)", soldier)
        
        # Add more workers
        workers_data = [
            ('stonecutter1', 'build123', 'worker'),
            ('water_bearer', 'nile_flow', 'worker'),
            ('pyramid_builder', 'giza123', 'worker')
        ]
        for worker in workers_data:
            cursor.execute("INSERT INTO workers (username, password, role) VALUES (?, ?, ?)", worker)
    
    elif environment == 'pharaoh':
        # Initialize pharaoh environment
        cursor.execute('DROP TABLE IF EXISTS pharaohs')
        cursor.execute('DROP TABLE IF EXISTS sacred_deities')
        cursor.execute('DROP TABLE IF EXISTS pharaoh_credentials')
        cursor.execute('DROP TABLE IF EXISTS pharaoh_schema_tables')
        cursor.execute('DROP TABLE IF EXISTS pharaoh_schema_columns')
        
        # Create pharaohs table
        cursor.execute('''
        CREATE TABLE pharaohs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            access_level TEXT NOT NULL
        )
        ''')
        
        # Create pharaoh_credentials table for actual login validation
        cursor.execute('''
        CREATE TABLE pharaoh_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            access_level TEXT NOT NULL
        )
        ''')
        
        # Insert the same credentials for login validation
        cursor.execute("INSERT INTO pharaoh_credentials (username, access_level) VALUES ('khufu', 'pharaoh')")
        
        # Create sacred_deities table
        cursor.execute('''
        CREATE TABLE sacred_deities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            power TEXT NOT NULL,
            secret_code TEXT
        )
        ''')
        
        # Add the hidden god
        cursor.execute("INSERT INTO sacred_deities (name, power, secret_code) VALUES ('amuntekh', 'ultimate', 'm4st3r_g0d}')")
        
        # Add decoy gods
        gods_data = [
            ('ra', 'sun', 'not_the_flag'),
            ('anubis', 'death', 'not_the_flag'),
            ('isis', 'magic', 'not_the_flag'),
            ('osiris', 'afterlife', 'not_the_flag'),
            ('seth', 'chaos', 'not_the_flag')
        ]
        for god in gods_data:
            cursor.execute("INSERT INTO sacred_deities (name, power, secret_code) VALUES (?, ?, ?)", god)
            
        # Create a special fake table for pharaoh dashboard environment
        cursor.execute('''
        CREATE TABLE pharaoh_schema_tables (
            table_name TEXT PRIMARY KEY
        )
        ''')
        
        # Populate the pharaoh schema with different tables
        pharaoh_tables = [
            ('sacred_deities',),
            ('pharaohs',)
        ]
        
        for table in pharaoh_tables:
            cursor.execute("INSERT INTO pharaoh_schema_tables (table_name) VALUES (?)", table)

        # Create columns for pharaoh schema
        cursor.execute('''
        CREATE TABLE pharaoh_schema_columns (
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            PRIMARY KEY (table_name, column_name)
        )
        ''')
        
        # Add columns for pharaoh dashboard tables
        pharaoh_columns_data = [
            # sacred_deities columns
            ('sacred_deities', 'id'),
            ('sacred_deities', 'name'),
            ('sacred_deities', 'power'),
            ('sacred_deities', 'secret_code'),
            
            # pharaohs columns
            ('pharaohs', 'id'),
            ('pharaohs', 'name'),
            ('pharaohs', 'access_level')
        ]
        
        for column in pharaoh_columns_data:
            cursor.execute("INSERT INTO pharaoh_schema_columns (table_name, column_name) VALUES (?, ?)", column)
    
    # Commit all changes and close
    conn.commit()
    conn.close()

# Context processor to add timer data to all templates
@app.context_processor
def inject_timer_data():
    timer_data = {
        'session_timeout': SESSION_TIMEOUT,
        'time_remaining': session.get('time_remaining', SESSION_TIMEOUT)
    }
    return {'timer_data': timer_data}

# Format time remaining for display
@app.template_filter('format_time_remaining')
def format_time_remaining(seconds):
    minutes, seconds = divmod(int(seconds), 60)
    return f"{minutes:02d}:{seconds:02d}"

# Before request handler to check session timeout
@app.before_request
def before_request():
    # Skip for static files
    if request.path.startswith('/static/'):
        return
    
    # Check session timeout
    check_session_timeout()

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Worker login route - vulnerable to SQL injection
@app.route('/worker/login', methods=['GET', 'POST'])
def worker_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db('soldier')
        cursor = conn.cursor()
        
        # Vulnerable SQL query - allows login bypass
        query = f"SELECT * FROM workers WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['logged_in'] = True
                session['username'] = user['username']
                session['role'] = user['role']
                
                # Flag for soldier role
                if user['role'] == 'soldier':
                    flash('Welcome, brave soldier! Here is your first haft of the reward: O24{1nj3c10n_', 'success')
                else:
                    flash(f'Welcome back, {user["username"]}!', 'success')
                
                return redirect(url_for(f"{user['role']}_dashboard"))
            else:
                flash('Invalid credentials', 'error')
        except sqlite3.Error as e:
            flash(f'Error: {e}', 'error')
        finally:
            conn.close()
            
    return render_template('worker_login.html')

# Worker registration
@app.route('/worker/register', methods=['GET', 'POST'])
def worker_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db('soldier')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO workers (username, password, role) VALUES (?, ?, 'worker')", 
                          (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('worker_login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
        finally:
            conn.close()
            
    return render_template('worker_register.html')

# Pharaoh login route
@app.route('/pharaoh/login', methods=['GET', 'POST'])
def pharaoh_login():
    if request.method == 'GET':
        return render_template('pharaoh_login.html')
    
    name = request.form.get('name')
    access_level = request.form.get('access_level')
    
    # Debug information
    print(f"Attempting pharaoh login with: name='{name}', access_level='{access_level}'")
    
    conn = get_db('pharaoh')
    cursor = conn.cursor()
    
    try:
        # Check for the specific pharaoh using the pharaoh_credentials table
        cursor.execute("SELECT * FROM pharaoh_credentials WHERE username = ? AND access_level = ?", 
                    (name, access_level))
        pharaoh = cursor.fetchone()
        
        if pharaoh:
            session['logged_in'] = True
            session['username'] = pharaoh['username']
            session['role'] = 'pharaoh'
            return redirect('/pharaoh/dashboard')
        else:
            return render_template('pharaoh_login.html', error="Invalid credentials - No pharaoh found with the provided name and access level")
    except Exception as e:
        return render_template('pharaoh_login.html', error=f"An error occurred: {str(e)}")
    finally:
        conn.close()

# Worker dashboard
@app.route('/worker/dashboard')
def worker_dashboard():
    if not session.get('logged_in') or session.get('role') != 'worker':
        flash('You must be logged in as a worker')
        return redirect(url_for('worker_login'))
        
    tasks = [
        "Water the sacred elephants",
        "Carry stone blocks for the pyramids",
        "Polish the pharaoh's golden statues",
        "Harvest papyrus from the Nile",
        "Feed the sacred cats"
    ]
    
    return render_template('worker_dashboard.html', tasks=tasks)

# Soldier dashboard - has SQL injectable search function
@app.route('/soldier/dashboard')
def soldier_dashboard():
    if not session.get('logged_in') or session.get('role') != 'soldier':
        flash('You must be logged in as a soldier')
        return redirect(url_for('worker_login'))
    
    conn = get_db('soldier')
    cursor = conn.cursor()
    
    # Get worker stats
    cursor.execute("SELECT COUNT(*) as count FROM workers WHERE role = 'worker'")
    worker_count = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM soldiers")
    soldier_count = cursor.fetchone()['count']
    
    # Construction progress (random for flavor)
    progress = random.randint(65, 95)
    
    conn.close()
    
    return render_template('soldier_dashboard.html', 
                          worker_count=worker_count,
                          soldier_count=soldier_count,
                          progress=progress)

@app.route('/soldier/search', methods=['GET', 'POST'])
def soldier_search():
    if not session.get('logged_in') or session.get('role') != 'soldier':
        return jsonify({'error': 'Unauthorized'}), 403
    
    search_term = request.form.get('search', '')
    
    # Check for blacklisted words
    if contains_blacklisted_word(search_term):
        return jsonify({'error': 'Invalid search term detected'}), 403
    
    conn = get_db('soldier')
    cursor = conn.cursor()
    
    # Modified to support realistic SQL injection discovery
    query = f"SELECT id, name, rank, strength FROM soldiers WHERE name LIKE '%{search_term}%'"
    
    try:
        print(f"Original search query: {query}")
        
        # For table discovery (information_schema.tables)
        if "information_schema.tables" in search_term.lower():
            print("Student is attempting to discover tables")
            query = query.replace("information_schema.tables", "soldier_schema_tables")
        
        # For column discovery (information_schema.columns)
        elif "information_schema.columns" in search_term.lower() or "information_schema.column" in search_term.lower():
            print("Student is attempting to discover columns")
            # Fix the singular/plural issue
            query = query.replace("information_schema.columns", "soldier_schema_columns")
            query = query.replace("information_schema.column", "soldier_schema_columns")
        
        # The query can run as-is for direct table access - let SQL handle it
        print(f"Modified query to execute: {query}")
        cursor.execute(query)
        results = cursor.fetchall()
        
        soldiers = []
        for row in results:
            soldier = {}
            for key in row.keys():
                soldier[key] = row[key]
            soldiers.append(soldier)
            
        return jsonify({'soldiers': soldiers})
    except sqlite3.Error as e:
        error_msg = str(e)
        full_error = f"Error in query: {query}. Details: {error_msg}"
        return jsonify({'error': full_error}), 500
    finally:
        conn.close()

# Pharaoh dashboard with the final god challenge
@app.route('/pharaoh/dashboard')
def pharaoh_dashboard():
    if not session.get('logged_in') or session.get('role') != 'pharaoh':
        flash('You must be logged in as the pharaoh')
        return redirect(url_for('worker_login'))
    
    return render_template('pharaoh_dashboard.html')

# God search endpoint - vulnerable to time-based blind SQL injection
@app.route('/pharaoh/search_deity', methods=['GET'])
def search_deity():
    if not session.get('logged_in') or session.get('role') != 'pharaoh':
        return jsonify({'error': 'Unauthorized'}), 403
    
    deity_name = request.args.get('name', '')
    print(f"Deity search query: {deity_name}")
    
    conn = get_db('pharaoh')
    cursor = conn.cursor()
    
    # By default, do not show results
    deities = []
    found_deity = False
    correct_name = "amuntekh"  # Our hidden deity name
    
    try:
        if len(deity_name) == 0:
            return jsonify({
                'deities': [],
                'message': 'The Oracle sees all hidden deities.'
            })
        
        # Check for blind SQL injection attempts
        if "substr" in deity_name.lower() and "and" in deity_name.lower():
            print("Blind SQL injection attempt detected")
            
            # Process single character position checks
            for i in range(1, len(correct_name) + 1):
                for char in 'abcdefghijklmnopqrstuvwxyz':
                    position_check = f"substr(name,{i},1)='{char}'"
                    if position_check.lower() in deity_name.lower():
                        if char == correct_name[i-1]:
                            print(f"Student correctly guessed character {i}: {char}")
                            time.sleep(2)  # Add delay to indicate success
            
            # Process length checks
            if "length(name)" in deity_name.lower():
                length_match = re.search(r"length\(name\)\s*=\s*(\d+)", deity_name.lower())
                if length_match and int(length_match.group(1)) == len(correct_name):
                    time.sleep(2)  # Add delay to indicate success
        
        # If student tries direct name matching
        if f"name='{correct_name}'" in deity_name.lower() or f"name like '{correct_name}%'" in deity_name.lower():
            time.sleep(2)  # Add delay to indicate success
        
        # Only show results for basic SQL injections, but not the hidden deity
        if " or 1=1" in deity_name.lower() or " union " in deity_name.lower():
            cursor.execute(f"SELECT name, power FROM sacred_deities WHERE name <> 'amuntekh' AND name LIKE '%{deity_name.replace('%', '')}%'")
            results = cursor.fetchall()
            
            for row in results:
                deity = {}
                for key in row.keys():
                    deity[key] = row[key]
                deities.append(deity)
            
            found_deity = len(deities) > 0
            
            # If they're using OR 1=1, give them a hint that there's a hidden deity
            if " or 1=1" in deity_name.lower() and not "amuntekh" in deity_name.lower():
                return jsonify({
                    'deities': deities,
                    'message': 'The Oracle shows you known deities, but senses a hidden one that cannot be found directly.'
                })
        
        # Always provide some feedback
        if not found_deity and not "substr" in deity_name.lower():
            message = 'The Oracle refuses to answer directly.'
        elif "substr" in deity_name.lower():
            message = 'The Oracle is thinking...'
        else:
            message = None
            
        return jsonify({
            'deities': deities,
            'message': message
        })
    except sqlite3.Error as e:
        print(f"SQL Error in search_deity: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Endpoint to attempt to become a god
@app.route('/pharaoh/become_deity', methods=['POST'])
def become_deity():
    if not session.get('logged_in') or session.get('role') != 'pharaoh':
        return jsonify({'error': 'Unauthorized'}), 403
    
    deity_name = request.form.get('deity_name', '')
    print(f"Attempting to become deity: {deity_name}")
    
    conn = get_db('pharaoh')
    cursor = conn.cursor()
    
    try:
        # Check if this is the secret deity
        cursor.execute("SELECT * FROM sacred_deities WHERE name = ?", (deity_name,))
        deity = cursor.fetchone()
        
        if deity and deity['name'] == 'amuntekh':
            # They found the secret god!
            print(f"Success! User found the hidden deity: {deity_name}")
            return jsonify({
                'success': True,
                'message': 'You have transcended humanity and become a god!',
                'flag': 'm4st3r_g0d}'
            })
        else:
            print(f"Failed attempt with deity: {deity_name}")
            return jsonify({
                'success': False,
                'message': 'The ritual failed. This deity cannot be embodied by mortals.'
            })
    except sqlite3.Error as e:
        print(f"SQL Error in become_deity: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/view-source/<path:route_path>')
def view_source(route_path):
    # Return the template directly without authentication
    try:
        return render_template(f"{route_path}.html")
    except:
        return "Template not found", 404

# Add custom HTTP headers with hidden hints
@app.after_request
def add_header(response):
    response.headers['X-Ancient-Scroll'] = 'The truth often lies in equality'
    response.headers['X-Sacred-Knowledge'] = 'When searching for soldiers, look beyond what is visible'
    return response

# Function to clean up old databases (can be called periodically)
def cleanup_old_databases():
    """Clean up databases that haven't been accessed in more than 24 hours"""
    current_time = time.time()
    for user_dir in os.listdir(DB_DIR):
        user_path = os.path.join(DB_DIR, user_dir)
        if os.path.isdir(user_path):
            # Check the directory modification time
            dir_mod_time = os.path.getmtime(user_path)
            if current_time - dir_mod_time > 86400:  # 24 hours in seconds
                try:
                    shutil.rmtree(user_path)
                    print(f"Removed old database directory: {user_dir}")
                except Exception as e:
                    print(f"Error removing old database directory {user_dir}: {e}")

# Schedule cleanup - you could use a proper scheduler here
@app.before_request
def check_cleanup():
    # Skip for static files
    if request.path.startswith('/static/'):
        return
        
    # Run cleanup once every 100 requests (adjust as needed)
    if random.randint(1, 100) == 1:
        cleanup_old_databases()

if __name__ == '__main__':
    app.run(debug=True, port=5100)