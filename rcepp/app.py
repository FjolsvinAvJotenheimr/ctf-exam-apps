from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import os
import subprocess
import re
import random
import string
import time
import shutil
import uuid
import threading
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'CTF_SECURE_SECRET_KEY_FOR_SESSIONS'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=45)


# Flag definition
FLAG = "O24{pr0t0typ3_p0llut10n_1s_4nc13nt_m4g1c}"

# Base directory for virtual environments
VIRTUAL_ENV_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "virtual_environments")
os.makedirs(VIRTUAL_ENV_BASE, exist_ok=True)

# Add this near the beginning of your app.py file, before starting the cleanup thread
def cleanup_all_environments():
    """Remove all virtual environments on server startup"""
    if os.path.exists(VIRTUAL_ENV_BASE):
        for item in os.listdir(VIRTUAL_ENV_BASE):
            item_path = os.path.join(VIRTUAL_ENV_BASE, item)
            if os.path.isdir(item_path):
                try:
                    shutil.rmtree(item_path)
                    print(f"Cleaned up environment: {item}")
                except Exception as e:
                    print(f"Failed to clean up environment {item}: {e}")

# Call this function before starting the Flask app
cleanup_all_environments()

# Whitelisted commands for safe execution
WHITELISTED_COMMANDS = ["ls", "cat", "whoami", "pwd", "id", "ps", "echo", "grep", "head", "tail", "rm"]

# Dictionary to store user environments and timestamps
user_environments = {}

# Create a lock for thread-safe operations
env_lock = threading.Lock()

# Configuration for the "artifact scanner"
class TempleScannerConfig:
    def __init__(self):
        self.scan_timeout = 5000
        self.debug_mode = False
        self.notify_on_scan = True

# Artifact storage - simulates a database
artifacts = [
    {
        "id": 1,
        "name": "Scarab Amulet",
        "description": "A protective amulet in the shape of a scarab beetle.",
        "location": "Tomb Chamber A",
        "power": 3
    },
    {
        "id": 2,
        "name": "Anubis Statue",
        "description": "A small statue of Anubis, guardian of the underworld.",
        "location": "Burial Chamber",
        "power": 5
    },
    {
        "id": 3,
        "name": "Papyrus Scroll",
        "description": "An ancient scroll with hieroglyphic writing.",
        "location": "Scribe's Room",
        "power": 2
    }
]

# Function to generate a random secret key
def generate_random_key():
    digits = ''.join(random.choices(string.digits, k=4))
    return f"the_eye_sees_all_{digits}"

# Function to create a virtual environment for a user
def create_virtual_environment(user_id):
    """Create a virtual environment with Egyptian-themed files and directories"""
    env_path = os.path.join(VIRTUAL_ENV_BASE, user_id)
    
    # Create directories
    os.makedirs(env_path, exist_ok=True)
    
    # Generate a random secret key for this user
    secret_key = generate_random_key()
    
    # Create the eye_of_horus.txt file
    with open(os.path.join(env_path, 'eye_of_horus.txt'), 'w') as f:
        f.write(secret_key)
    
    # Create directories and files with Egyptian-themed content
    directories = [
        "home/pharaoh",
        "etc/temple",
        "var/scrolls",
        "usr/local/hieroglyphs",
        "dev/sacred",
        "opt/artifacts"
    ]
    
    for directory in directories:
        os.makedirs(os.path.join(env_path, directory), exist_ok=True)
    
    files = {
        "home/pharaoh/welcome.txt": "Welcome, High Priest, to the sacred terminal of the Temple of Khnum.",
        "etc/temple/rituals.conf": "# Configuration for daily rituals\nmorning_offering=true\nevening_prayer=true\nmoonlight_ceremony=false",
        "etc/temple/priests.list": "ankhmhor\nkagemni\nptahhotep\nimhotep\nkhnumhotep",
        "var/scrolls/ancient_spells.txt": "# These spells are only to be used by trained priests\n\nSpell of Opening: Wep-em-heset\nSpell of Protection: Sa-Asar\nSpell of Transformation: Kheperu",
        "usr/local/hieroglyphs/translation.md": "# Hieroglyph Translation Guide\n\n𓀀 - Man standing\n𓀁 - Man seated\n𓀂 - Man with staff\n𓀃 - Official",
        "opt/artifacts/inventory.log": "Scarab Amulet - Power level 3 - Last used: 10 days ago\nAnubis Statue - Power level 5 - Last used: 2 days ago\nPapyrus Scroll - Power level 2 - Last used: 15 days ago"
    }
    
    for file_path, content in files.items():
        full_path = os.path.join(env_path, file_path)
        dir_path = os.path.dirname(full_path)
        os.makedirs(dir_path, exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(content)
    
    # Set expiry time (1 hour from now)
    expiry_time = datetime.now() + timedelta(minutes=45)    
    # Create scanner
    scanner = TempleScannerConfig()
    
    # Store environment info
    user_environments[user_id] = {
        'path': env_path,
        'secret_key': secret_key,
        'expiry': expiry_time,
        'scanner': scanner
    }
    
    return env_path

# Get or create user environment (fixed to not reset timer)
def get_user_environment():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    
    user_id = session['user_id']
    
    if user_id not in user_environments:
        # Only create a new environment if one doesn't exist
        create_virtual_environment(user_id)
    
    # Don't update the expiry time on every call
    return user_environments[user_id]

# Get temple scanner for current user
def get_temple_scanner():
    env = get_user_environment()
    return env['scanner']

# Get the secret key for current user
def get_secret_key():
    env = get_user_environment()
    return env['secret_key']

# Get the environment path for current user
def get_env_path():
    env = get_user_environment()
    return env['path']

# Custom JSON decoder that creates objects vulnerable to prototype pollution
class VulnerableJSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
        
    def object_hook(self, obj):
        if "__proto__" in obj:
            temple_scanner = get_temple_scanner()
            for key, value in obj["__proto__"].items():
                setattr(temple_scanner, key, value)
        return obj

# Main route
@app.route('/')
def index():
    # Simple environment check without complex locking
    get_user_environment()
    return render_template('index.html', artifacts=artifacts)

# Artifact details route
@app.route('/artifact/<int:artifact_id>')
def artifact_detail(artifact_id):
    artifact = next((a for a in artifacts if a["id"] == artifact_id), None)
    if artifact:
        return render_template('artifact_detail.html', artifact=artifact)
    return redirect(url_for('index'))

# Scanner configuration route - vulnerable to prototype pollution
@app.route('/api/scanner/configure', methods=['POST'])
def configure_scanner():
    try:
        # Get the scanner for the current user
        temple_scanner = get_temple_scanner()
        
        # Vulnerable code: using the custom decoder without validation
        config_data = json.loads(request.data, cls=VulnerableJSONDecoder)
        
        # Update configuration (vulnerable to prototype pollution)
        for key, value in config_data.items():
            if key == "__proto__":
                # Handle prototype pollution directly
                for proto_key, proto_value in value.items():
                    setattr(temple_scanner, proto_key, proto_value)
            elif hasattr(temple_scanner, key):
                setattr(temple_scanner, key, value)
        
        return jsonify({"status": "success", "message": "Scanner configuration updated"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# Sacred texts route - this is where the RCE happens through command_path pollution
@app.route('/api/sacred-texts/translate', methods=['POST'])
def translate_texts():
    try:
        data = request.get_json()
        text = data.get('text', '')
        
        # Get the user's environment path and scanner
        env_path = get_env_path()
        temple_scanner = get_temple_scanner()
        
        # Vulnerable code that can be exploited via prototype pollution
        command_path = getattr(temple_scanner, 'command_path', None)
        
        if command_path:
            # Check if the command is whitelisted
            command = command_path.split()[0]
            if command not in WHITELISTED_COMMANDS:
                return jsonify({
                    "status": "error",
                    "message": f"Command '{command}' is forbidden by the temple guardians!"
                })
                
            # Execute the command with proper validation
            try:
                # Use a regex to ensure only whitelisted commands are executed
                if re.match(f"^({'|'.join(WHITELISTED_COMMANDS)})( .*)?$", command_path):
                    # Change directory to the user's virtual environment
                    original_dir = os.getcwd()
                    os.chdir(env_path)
                    
                    try:
                        # Execute the command in the virtual environment
                        output = subprocess.check_output(command_path, shell=True, text=True, timeout=5)
                        
                        # Change back to original directory
                        os.chdir(original_dir)
                        
                        return jsonify({
                            "status": "success",
                            "translation": "Translation completed by temple scribe.",
                            "scribe_notes": output
                        })
                    finally:
                        # Ensure we always change back to the original directory
                        if os.getcwd() != original_dir:
                            os.chdir(original_dir)
                else:
                    return jsonify({
                        "status": "error",
                        "message": "The sacred ritual cannot be performed with these instructions."
                    })
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Error in ritual: {str(e)}"
                })
        
        # Normal flow if no command_path is set
        return jsonify({
            "status": "success",
            "translation": f"Ancient text says: {text}",
            "scribe_notes": "No special instructions from the high priest."
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })

# Flag file route - accessible after exploiting RCE
@app.route('/api/get-flag', methods=['POST'])
def get_flag():
    data = request.get_json()
    secret_key = data.get('secret_key', '')
    
    # Get the user's unique secret key
    user_secret_key = get_secret_key()
    
    # The secret key is stored in a file called "eye_of_horus.txt" in the virtual environment
    if secret_key == user_secret_key:
        return jsonify({
            "status": "success",
            "message": "The Eye of Horus has deemed you worthy!",
            "flag": FLAG
        })
    else:
        return jsonify({
            "status": "error",
            "message": "The Eye of Horus sees your deception. You are not worthy!"
        })

# Admin panel - just a distraction
@app.route('/admin')
def admin():
    return render_template('admin.html')

# Add a route to display time remaining before environment reset
@app.route('/api/session-info', methods=['GET'])
def session_info():
    try:
        # Make sure user has an environment
        env = get_user_environment()
        user_id = session['user_id']
        
        expiry_time = env['expiry']
        time_remaining = expiry_time - datetime.now()
        
        minutes_remaining = int(time_remaining.total_seconds() / 60)
        seconds_remaining = int(time_remaining.total_seconds() % 60)
        
        return jsonify({
            "status": "success",
            "session_id": user_id,
            "time_remaining": f"{minutes_remaining} minutes, {seconds_remaining} seconds",
            "expires_at": expiry_time.strftime("%H:%M:%S")
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })

# Replace the entire debug_scanner route with this code
@app.route('/api/scanner/debug', methods=['GET'])
def debug_scanner():
    try:
        # Get the scanner for the current user
        temple_scanner = get_temple_scanner()
        
        # Create a dictionary of the scanner's attributes
        scanner_attrs = {}
        for attr in dir(temple_scanner):
            # Skip private/protected attributes and methods
            if not attr.startswith('_') and not callable(getattr(temple_scanner, attr)):
                scanner_attrs[attr] = str(getattr(temple_scanner, attr))
        
        # Add a "hint" section to the response that always includes command_path
        hints = [
            "scan_timeout: Controls how long a scan can run (ms)",
            "debug_mode: Enables additional debug output",
            "notify_on_scan: Sends notification to high priest after scan",
            "command_path: [RESTRICTED] Used only by high priests for maintenance rituals",

            "WARNING: Improper configuration may anger the gods!"
        ]
        
        return jsonify({
            "status": "success",
            "scanner_attributes": scanner_attrs,
            "message": "The eye of Horus reveals the scanner's secrets.",
            "notes": "Priest's notes: Remember to check all standard and restricted parameters.",
            "available_settings": hints
        })
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e)
        })

# Cleanup function
def cleanup_expired_environments():
    while True:
        current_time = datetime.now()
        expired_users = []
        
        for user_id, env_info in list(user_environments.items()):
            if current_time > env_info['expiry']:
                expired_users.append(user_id)
        
        for user_id in expired_users:
            env_path = user_environments[user_id]['path']
            if os.path.exists(env_path):
                try:
                    shutil.rmtree(env_path)
                except Exception:
                    pass
            del user_environments[user_id]
        
        # Sleep for 5 minutes before checking again
        time.sleep(300)

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_environments, daemon=True)
cleanup_thread.start()

# Main execution
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
