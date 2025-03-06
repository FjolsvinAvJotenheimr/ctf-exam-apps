from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
from functools import wraps
import hashlib

app = Flask(__name__)
app.secret_key = 'anubis_guards_the_secret_key'  # Change this in a real application

# Function to generate MD5 hash of a number
def md5_hash(number):
    return hashlib.md5(str(number).encode()).hexdigest()

# User database for the second IDOR vulnerability
users = {
    1: {
        'username': 'explorer',
        'password': 'tutankhamun',
        'clearance_level': 1,
        'role': 'basic',
        'profile_image': 'profile_explorer.jpg'
    },
    2: {
        'username': 'curator',
        'password': 'nefertiti',
        'clearance_level': 2,
        'role': 'staff',
        'profile_image': 'profile_curator.jpg'
    },
    3: {
        'username': 'director',
        'password': 'ramesses',
        'clearance_level': 3,
        'role': 'admin',
        'profile_image': 'profile_director.jpg',
        'secret_artifact_id': 'a7f39e1cb8d542b6c9184b8374fe36a1'
    }
}

# Artifact database with MD5 hashes as keys
artifacts = {
    md5_hash(1): {
        'name': 'Scarab Amulet',
        'description': 'This golden scarab beetle amulet symbolizes rebirth and transformation. It was found in the tomb of a minor noble who served under Pharaoh Amenhotep III.',
        'era': 'New Kingdom, 18th Dynasty',
        'location': 'Valley of the Nobles',
        'image': 'scarab_amulet.jpg',
        'restricted': False,
        'clearance_required': 1,
        'original_id': 1  # Keep track of original ID for navigation
    },
    md5_hash(2): {
        'name': 'Canopic Jar',
        'description': 'This alabaster canopic jar once held the mummified liver of a high priest. The lid is shaped as the falcon-headed god Qebehsenuef, one of the four sons of Horus.',
        'era': 'Late Period',
        'location': 'Saqqara Necropolis',
        'image': 'canopic_jar.jpg',
        'restricted': False,
        'clearance_required': 1,
        'original_id': 2
    },
    md5_hash(3): {
        'name': 'Ankh Pendant',
        'description': 'This silver ankh pendant represents eternal life. It was discovered around the neck of a mummified priestess of the goddess Hathor.',
        'era': 'Middle Kingdom',
        'location': 'Abydos',
        'image': 'ankh_pendant.jpg',
        'restricted': False,
        'clearance_required': 1,
        'original_id': 3
    },
    md5_hash(4): {
        'name': 'Ushabti Figure',
        'description': 'This painted wooden ushabti figure was meant to act as a servant for the deceased in the afterlife. The hieroglyphs inscribed contain a spell from the Book of the Dead.',
        'era': 'Third Intermediate Period',
        'location': 'Thebes',
        'image': 'ushabti_figure.jpg',
        'restricted': False,
        'clearance_required': 1,
        'original_id': 4
    },
    md5_hash(5): {
        'name': 'Eye of Horus Amulet',
        'description': 'This faience Eye of Horus (Wadjet) amulet was worn for protection. It represents the eye of the god Horus, which was injured in his battle with Seth and later healed by Thoth.',
        'era': 'New Kingdom',
        'location': 'Valley of the Kings',
        'image': 'eye_of_horus.jpg',
        'restricted': False,
        'clearance_required': 1,
        'original_id': 5
    },
    # ID 6 is hidden for the first IDOR challenge
    md5_hash(6): {
        'name': 'Anubis Scepter',
        'description': 'This obsidian scepter topped with the head of Anubis was used by high priests during mummification rituals. Legend says it can open the gateway to the afterlife.',
        'era': 'Unknown - Possibly Old Kingdom',
        'location': 'Secret chamber in the Temple of Isis',
        'image': 'anubis_scepter.jpg',
        'restricted': True,
        'clearance_required': 1,  # Accessible with any login, but not listed in gallery
        'secret_note': 'First half of the secret: O24{0s1r1s_m45k',
        'original_id': 6
    },
    md5_hash(7): {
        'name': 'Papyrus Scroll',
        'description': 'This fragmentary papyrus contains spells from the Book of the Dead, including illustrations of the weighing of the heart ceremony in the Hall of Two Truths.',
        'era': 'New Kingdom',
        'location': 'Deir el-Medina',
        'image': 'papyrus_scroll.jpg',
        'restricted': False,
        'clearance_required': 1,
        'original_id': 7
    },
    'a7f39e1cb8d542b6c9184b8374fe36a1': {
        'name': 'Mask of Osiris',
        'description': 'HIGHLY RESTRICTED ARTIFACT: This golden mask was supposedly worn by the pharaoh who united with Osiris in the afterlife. It contains inscriptions of forbidden knowledge that complete the ritual begun in the Hidden Papyrus Fragment.',
        'era': 'Pre-Dynastic Period',
        'location': 'Unknown - artifact appeared mysteriously in the museum vault',
        'image': 'osiris_mask.jpg',
        'restricted': True,
        'clearance_required': 3,  # Requires level 3 clearance to view legitimately
        'secret_note': 'Second half of the secret: _r3v34ls_th3_truth}',
        'original_id': None  # Special case
    },
}

# Create a mapping from original ID to MD5 hash for easier navigation
id_to_hash = {artifact_data['original_id']: hash_id for hash_id, artifact_data in artifacts.items() if artifact_data['original_id'] is not None}

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first to access the tomb.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Check clearance level
def has_clearance(required_level):
    if 'clearance_level' not in session:
        return False
    return session['clearance_level'] >= required_level

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # IDOR vulnerability #2: Using user_id in login form
        user_id_input = request.form.get('user_id', '')
        
        # Normal login flow
        authenticated = False
        user_data = None
        user_id = None
        
        # Attempt to authenticate with provided credentials
        for uid, user in users.items():
            if user['username'] == username and user['password'] == password:
                authenticated = True
                user_data = user
                user_id = uid
                break
        
        # IDOR vulnerability: If user_id was specified directly (and it exists), bypass normal authentication
        if user_id_input and user_id_input.strip().isdigit():
            input_id = int(user_id_input)
            if input_id in users:
                # Directly access the user account by ID - this is the vulnerability
                authenticated = True
                user_data = users[input_id]
                user_id = input_id
        
        if authenticated:
            session['user_id'] = user_id
            session['username'] = user_data['username']
            session['clearance_level'] = user_data['clearance_level']
            session['role'] = user_data['role']
            flash(f'Welcome, {user_data["username"]}! You have successfully entered the ancient tomb!', 'success')
            return redirect(url_for('gallery'))
        else:
            flash('Incorrect credentials. The curse of the pharaohs prevents your entry!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have left the ancient tomb.', 'info')
    return redirect(url_for('index'))

@app.route('/gallery')
@login_required
def gallery():
    # Only show artifacts that are not restricted
    # Note: ID 6 (md5_hash(6)) is hidden (not shown in gallery)
    visible_artifacts = {k: v for k, v in artifacts.items() if not v['restricted']}
    return render_template('gallery.html', artifacts=visible_artifacts, clearance_level=session.get('clearance_level', 0))

@app.route('/artifact/<artifact_id>')
@login_required
def view_artifact(artifact_id):
    # Check if the artifact exists
    if artifact_id not in artifacts:
        flash('The artifact you seek does not exist in our records.', 'danger')
        return redirect(url_for('gallery'))
    
    artifact = artifacts[artifact_id]
    
    # IDOR vulnerability: Missing proper authorization check based on clearance level
    # A secure implementation would look like this:
    # if artifact['restricted'] and session.get('clearance_level', 0) < artifact['clearance_required']:
    #     flash('You do not have sufficient clearance to view this restricted artifact.', 'danger')
    #     return redirect(url_for('gallery'))
    
    # Get previous and next artifact IDs for navigation
    prev_artifact_id = None
    next_artifact_id = None
    
    # Only set up navigation for artifacts with original_id
    if artifact['original_id'] is not None:
        current_original_id = artifact['original_id']
        
        # Previous artifact
        if current_original_id > 1:
            prev_original_id = current_original_id - 1
            # Skip ID 6 in navigation
            if prev_original_id == 6:
                prev_original_id = 5
            prev_artifact_id = id_to_hash.get(prev_original_id)
        
        # Next artifact
        if current_original_id < max(artifact_data['original_id'] for artifact_data in artifacts.values() if artifact_data['original_id'] is not None):
            next_original_id = current_original_id + 1
            # Skip ID 6 in navigation
            if next_original_id == 6:
                next_original_id = 7
            next_artifact_id = id_to_hash.get(next_original_id)
    
    return render_template('artifact.html', 
                          artifact=artifact, 
                          artifact_id=artifact_id, 
                          clearance_level=session.get('clearance_level', 0),
                          prev_artifact_id=prev_artifact_id,
                          next_artifact_id=next_artifact_id)

@app.route('/profile')
@login_required
def profile():
    user_id = session.get('user_id')
    if user_id not in users:
        flash('User profile not found.', 'danger')
        return redirect(url_for('gallery'))
    
    user = users[user_id]
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    app.run(debug=False, port=5000)