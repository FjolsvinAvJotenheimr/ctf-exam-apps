from flask import Flask, render_template, request, redirect, url_for, session, abort, send_file
import os
import random
import string
import time
import json
import io
import uuid
from datetime import datetime, timedelta
import re

app = Flask(__name__)
app.secret_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

# Store virtual filesystems for each session
# Now we'll have three separate filesystems per session
virtual_filesystems = {}

def generate_random_string(length=16):
    """Generate a random string of specified length."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def create_virtual_filesystem(session_id):
    """Create three isolated virtual filesystems for a session."""
    # First challenge - passwd file with the winning number
    winning_number_1 = random.randint(100000, 999999)
    
    # Second challenge - shadow file with the winning dice roll
    winning_number_2 = random.randint(3, 54)  # 3 dice with 18 faces (3-54 range)
    
    # Third challenge - treasure password
    treasure_password = generate_random_string(8)
    
    # Create three completely separate virtual filesystem structures
    # Challenge 1 filesystem
    fs_challenge1 = {
        "etc": {
            "passwd": f"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nanubis:x:{winning_number_1}:1000:The Guide of Souls:/home/anubis:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        }
    }
    
    # Challenge 2 filesystem
    fs_challenge2 = {
        "etc": {
            "shadow": f"root:!:18659:0:99999:7:::\ndaemon:*:18659:0:99999:7:::\nbin:*:18659:0:99999:7:::\nsys:*:18659:0:99999:7:::\nsync:*:18659:0:99999:7:::\ngames:*:18659:0:99999:7:::\nman:*:18659:0:99999:7:::\nlp:*:18659:0:99999:7:::\nmail:*:18659:0:99999:7:::\nnews:*:18659:0:99999:7:::\nuucp:*:18659:0:99999:7:::\nproxy:*:18659:0:99999:7:::\nwww-data:*:18659:0:99999:7:::\nbackup:*:18659:0:99999:7:::\nlist:*:18659:0:99999:7:::\nirc:*:18659:0:99999:7:::\nanubis:*:18659:{winning_number_2}:99999:7:::\ngnats:*:18659:0:99999:7:::\nnobody:*:18659:0:99999:7:::"
        }
    }
    
    # Challenge 3 filesystem - Changed to use hosts file
    fs_challenge3 = {
        "etc": {
            "hosts": f"127.0.0.1 localhost\n127.0.1.1 ctf-server\n\n# The following lines are desirable for IPv6 capable hosts\n::1     localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n\n# Secret treasure password\n127.0.0.1 treasure.local # Password: {treasure_password}"
        }
    }
    
    # Store in global dictionary with expiry time (1 hour from now)
    virtual_filesystems[session_id] = {
        "filesystems": {
            1: fs_challenge1,  # Challenge 1 filesystem
            2: fs_challenge2,  # Challenge 2 filesystem
            3: fs_challenge3   # Challenge 3 filesystem
        },
        "expiry": datetime.now() + timedelta(hours=1),
        "challenge_1_route": generate_random_string(),
        "challenge_2_route": generate_random_string(),
        "challenge_3_route": generate_random_string(),
        "winning_number_1": winning_number_1,
        "winning_number_2": winning_number_2,
        "treasure_password": treasure_password
    }
    
    # Print session setup for debugging
    print(f"Created session {session_id} with winning numbers: {winning_number_1}, {winning_number_2}, password: {treasure_password}")
    
    return virtual_filesystems[session_id]

def clean_expired_filesystems():
    """Remove expired virtual filesystems."""
    current_time = datetime.now()
    expired_sessions = [sid for sid, data in virtual_filesystems.items() 
                        if data["expiry"] < current_time]
    
    for sid in expired_sessions:
        del virtual_filesystems[sid]

def filter_path_for_challenge(path, challenge_number):
    """
    Apply challenge-specific filtering to the path.
    Returns the filtered path that will be used for actual file access.
    """
    # For challenge 1, strip the first instance of "../" to make it harder
    if challenge_number == 1:
        # If we find "../" pattern, remove the first occurrence
        if "../" in path:
            return path.replace("../", "", 1)
        # If we find "..\\" pattern (Windows-style), remove the first occurrence
        elif "..\\" in path:
            return path.replace("..\\", "", 1)
        return path
    
    # For challenge 2, decode URL encoding
    elif challenge_number == 2:
        return path.lower().replace('%2f', '/').replace('%2e', '.')
    
    # For challenge 3, remove null byte and everything after it
    elif challenge_number == 3:
        if '%00' in path:
            return path.split('%00')[0]
        return path
        
    return path

def normalize_path(path):
    """
    Normalize a path by:
    1. Handling multiple consecutive slashes
    2. Resolving './' references
    3. Resolving '../' references
    
    This follows standard path normalization rules.
    """
    # Replace multiple consecutive slashes with a single slash
    while '//' in path:
        path = path.replace('//', '/')
    
    # Split the path into components
    components = path.split('/')
    result = []
    
    for component in components:
        if component == '.' or component == '':
            # Skip '.' and empty components
            continue
        elif component == '..':
            # Go up one directory
            if result:
                result.pop()
        else:
            result.append(component)
    
    # Join the components back into a path
    return '/'.join(result)

def is_valid_path_for_challenge(path, challenge_number):
    """
    Check if a path is valid for a specific challenge using hardcoded payload lists.
    """
    # For challenge 1 (passwd)
    if challenge_number == 1:
        # Valid path formats for Challenge 1
        valid_formats = [
            "....//....//etc/passwd",
            "....//....//etc//passwd",
            "....//....//etc///passwd",
            "....//....//etc////passwd",
            "....//....//etc/////passwd",
            "....//....//etc//////passwd",
            "....//....//etc///////passwd",
            "....//....//etc////////passwd",
            "....//....//etc/////////passwd",
            "....//....//etc//////////passwd",
            "....//....//etc/./passwd",
            "....//....//./etc/passwd",
            "....//....//././etc/passwd",
            "....//....//etc/../etc/passwd",
            "....//....//./etc/../etc/passwd",
            "....//....//././etc/./passwd"
        ]
        
        # Check if the path is in the list of valid formats
        if path in valid_formats:
            return True
            
        # Check for paths with more than 2 "....// patterns
        if path.count("....//") >= 2 and path.startswith("....//"):
            # Extract the part after the "....//....// patterns
            for valid_format in valid_formats:
                suffix = valid_format[len("....//....//"):]
                if path.endswith(suffix):
                    return True
            
        return False
    
    # For challenge 2 (shadow)
    elif challenge_number == 2:
        # Valid path formats for Challenge 2
        valid_formats = [
            "..%2f..%2fetc%2fshadow",
            "..%2f..%2fetc%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2f%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2f%2f%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2f%2f%2f%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2f%2f%2f%2f%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2f%2f%2f%2f%2f%2f%2fshadow",
            "..%2f..%2fetc%2f%2f%2f%2f%2f%2f%2f%2f%2f%2fshadow",
            "..%2f..%2fetc%2f.%2fshadow",
            "..%2f..%2f.%2fetc%2fshadow",
            "..%2f..%2f.%2f.%2fetc%2fshadow",
            "..%2f..%2fetc%2f..%2fetc%2fshadow",
            "..%2f..%2f.%2fetc%2f..%2fetc%2fshadow",
            "..%2f..%2f.%2f.%2fetc%2f.%2fshadow"
        ]
        
        # Check if the path is in the list of valid formats (case insensitive)
        path_lower = path.lower()
        if path_lower in [fmt.lower() for fmt in valid_formats]:
            return True
            
        # Check for paths with more than 2 "..%2f patterns
        if path_lower.count("..%2f") >= 2 and path_lower.startswith("..%2f"):
            # Extract the part after the "..%2f..%2f patterns
            for valid_format in valid_formats:
                suffix = valid_format.lower()[len("..%2f..%2f"):]
                if path_lower.endswith(suffix):
                    return True
            
        return False
    
    # For challenge 3 (hosts with null byte)
    elif challenge_number == 3:
        # Valid path formats for Challenge 3
        valid_formats = [
            "../../etc/hosts%00",
            "../../etc//hosts%00",
            "../../etc///hosts%00",
            "../../etc////hosts%00",
            "../../etc/////hosts%00",
            "../../etc//////hosts%00",
            "../../etc///////hosts%00",
            "../../etc////////hosts%00",
            "../../etc/////////hosts%00",
            "../../etc//////////hosts%00",
            "../../etc/./hosts%00",
            "../.././etc/hosts%00",
            "../../././etc/hosts%00",
            "../../etc/../etc/hosts%00",
            "../.././etc/../etc/hosts%00",
            "../../././etc/./hosts%00"
        ]
        
        # Check if the path is in the list of valid formats
        if path in valid_formats:
            return True
            
        # Check for paths with more than 2 "../ patterns
        if path.count("../") >= 2 and path.startswith("../"):
            # Extract the part after the "../../ patterns
            for valid_format in valid_formats:
                suffix = valid_format[len("../../"):]
                if path.endswith(suffix):
                    return True
            
        return False
    
    return False

def get_file_from_path(session_id, path, challenge_number):
    """Retrieve file content from the virtual filesystem based on the path.
    
    Args:
        session_id: The session ID
        path: The path requested by the user
        challenge_number: Which challenge is requesting the file (1, 2, or 3)
        
    This ensures complete isolation between challenges.
    """
    clean_expired_filesystems()
    
    # For debugging - log the original path
    print(f"Challenge {challenge_number} - Original path request: {path}")
    
    # Check if the session exists
    if session_id not in virtual_filesystems:
        return None
    
    # First, check if the path matches the expected pattern for the challenge
    if not is_valid_path_for_challenge(path, challenge_number):
        print(f"Challenge {challenge_number} - Path doesn't meet requirements: {path}")
        return None
    
    # Use the specific filesystem for this challenge - COMPLETE ISOLATION
    fs = virtual_filesystems[session_id]["filesystems"][challenge_number]
    
    # All paths that reached this far are valid according to challenge requirements
    # Simply return the file content
    
    # For Challenge 1 (passwd)
    if challenge_number == 1:
        if "etc" in fs and "passwd" in fs["etc"]:
            return fs["etc"]["passwd"]
    
    # For Challenge 2 (shadow)
    elif challenge_number == 2:
        if "etc" in fs and "shadow" in fs["etc"]:
            return fs["etc"]["shadow"]
    
    # For Challenge 3 (hosts)
    elif challenge_number == 3:
        if "etc" in fs and "hosts" in fs["etc"]:
            return fs["etc"]["hosts"]
    
    print(f"Challenge {challenge_number} - File not found")
    return None

def get_time_remaining(session_id):
    """Calculate remaining time for session in seconds."""
    if session_id not in virtual_filesystems:
        return 0
    
    expiry = virtual_filesystems[session_id]["expiry"]
    remaining = (expiry - datetime.now()).total_seconds()
    return max(0, int(remaining))

@app.route('/')
def index():
    """Landing page for the CTF challenge."""
    # Check for expired session cookie flag
    reset_requested = request.args.get('reset', 'false') == 'true'
    
    # Create or get session ID
    if 'session_id' not in session or reset_requested:
        # Clear existing session if any
        session.clear()
        session['session_id'] = str(uuid.uuid4())
        create_virtual_filesystem(session['session_id'])
    
    # Check if session has expired
    if session['session_id'] not in virtual_filesystems:
        # Clear existing session
        session.clear()
        session['session_id'] = str(uuid.uuid4())
        create_virtual_filesystem(session['session_id'])
    
    time_remaining = get_time_remaining(session['session_id'])
    
    return render_template('index.html', time_remaining=time_remaining)

@app.route('/challenge', methods=['POST'])
def submit_guess():
    """Handle the first challenge guess."""
    if 'session_id' not in session or session['session_id'] not in virtual_filesystems:
        return redirect(url_for('index'))
    
    guess = request.form.get('guess', '')
    
    # Check if the guess is actually a path traversal attempt
    file_content = get_file_from_path(session['session_id'], guess, challenge_number=1)
    
    if file_content:
        # Return the file content directly for path traversal
        return render_template('file_view.html', 
                              file_content=file_content, 
                              time_remaining=get_time_remaining(session['session_id']))
    
    # Check if it's the correct number
    try:
        guess_num = int(guess)
        if guess_num == virtual_filesystems[session['session_id']]["winning_number_1"]:
            challenge_2_route = virtual_filesystems[session['session_id']]["challenge_2_route"]
            return redirect(url_for('challenge_2', random_path=challenge_2_route))
        else:
            return render_template('index.html', 
                                  error="Wrong guess! Try again.", 
                                  time_remaining=get_time_remaining(session['session_id']))
    except ValueError:
        return render_template('index.html', 
                              error="Invalid input! Please enter a number or try something else...", 
                              time_remaining=get_time_remaining(session['session_id']))

@app.route('/<random_path>/challenge_2')
def challenge_2(random_path):
    """Second challenge page."""
    if 'session_id' not in session or session['session_id'] not in virtual_filesystems:
        return redirect(url_for('index'))
    
    session_data = virtual_filesystems[session['session_id']]
    if random_path != session_data["challenge_2_route"]:
        abort(404)
    
    # Generate three random dice values for display
    dice_values = [random.randint(1, 18) for _ in range(3)]
    total = sum(dice_values)
    
    return render_template('challenge_2.html', 
                          dice_values=dice_values, 
                          total=total, 
                          time_remaining=get_time_remaining(session['session_id']))

@app.route('/challenge_2_submit', methods=['POST'])
def challenge_2_submit():
    """Handle the second challenge guess."""
    if 'session_id' not in session or session['session_id'] not in virtual_filesystems:
        return redirect(url_for('index'))
    
    guess = request.form.get('guess', '')
    
    # Debug logging
    print(f"Challenge 2 guess received: {guess}")
    
    # Check if it's a path traversal attempt - using URL encoded format
    file_content = get_file_from_path(session['session_id'], guess, challenge_number=2)
    
    if file_content:
        print("File content found, rendering file view")
        return render_template('file_view.html', 
                             file_content=file_content, 
                             time_remaining=get_time_remaining(session['session_id']))
    
    # Check if it's the correct number
    try:
        guess_num = int(guess)
        if guess_num == virtual_filesystems[session['session_id']]["winning_number_2"]:
            challenge_3_route = virtual_filesystems[session['session_id']]["challenge_3_route"]
            return redirect(url_for('challenge_3', random_path=challenge_3_route))
        else:
            # Generate new dice values
            dice_values = [random.randint(1, 18) for _ in range(3)]
            total = sum(dice_values)
            
            return render_template('challenge_2.html', 
                                  error="Wrong guess! The dice show a different number.", 
                                  dice_values=dice_values, 
                                  total=total, 
                                  time_remaining=get_time_remaining(session['session_id']))
    except ValueError:
        print(f"ValueError when converting guess: {guess}")
        dice_values = [random.randint(1, 18) for _ in range(3)]
        total = sum(dice_values)
        
        return render_template('challenge_2.html', 
                              error="Invalid input! Please enter a number or try something else...", 
                              dice_values=dice_values, 
                              total=total, 
                              time_remaining=get_time_remaining(session['session_id']))

@app.route('/<random_path>/challenge_3')
def challenge_3(random_path):
    """Third challenge page."""
    if 'session_id' not in session or session['session_id'] not in virtual_filesystems:
        return redirect(url_for('index'))
    
    session_data = virtual_filesystems[session['session_id']]
    if random_path != session_data["challenge_3_route"]:
        abort(404)
    
    return render_template('challenge_3.html', 
                          time_remaining=get_time_remaining(session['session_id']))

@app.route('/challenge_3_submit', methods=['POST'])
def challenge_3_submit():
    """Handle the third challenge guess."""
    if 'session_id' not in session or session['session_id'] not in virtual_filesystems:
        return redirect(url_for('index'))
    
    guess = request.form.get('guess', '')
    
    print(f"Challenge 3 guess received: {guess}")
    
    # For the final challenge, get file content using the updated function
    file_content = get_file_from_path(session['session_id'], guess, challenge_number=3)
    if file_content:
        return render_template('file_view.html', 
                              file_content=file_content, 
                              time_remaining=get_time_remaining(session['session_id']))
    
    # Check if it's the correct password
    if guess == virtual_filesystems[session['session_id']]["treasure_password"]:
        return render_template('success.html', 
                              flag="O24{p47h_7r4v3r54l_m45t3r}", 
                              time_remaining=get_time_remaining(session['session_id']))
    else:
        return render_template('challenge_3.html', 
                              error="Incorrect password! The door remains locked.", 
                              time_remaining=get_time_remaining(session['session_id']))

# Custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5005)