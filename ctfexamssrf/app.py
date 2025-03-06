from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
from urllib.parse import urlparse, quote
import os
import random
import string

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session

# Hieroglyphs translator
hieroglyph_map = {
    # Lower case
    "a": "𓏏", "b": "𓈬", "c": "𓋏", "d": "𓍷", "e": "𓆣",
    "f": "𓀃", "g": "𓆑", "h": "𓎉", "i": "𓌮", "j": "𓊫",
    "k": "𓋖", "l": "𓍖", "m": "𓋫", "n": "𓌩", "o": "𓊿",
    "p": "𓍶", "q": "𓋔", "r": "𓍄", "s": "𓉡", "t": "𓎛",
    "u": "𓍓", "v": "𓋝", "w": "𓀠", "x": "𓀋", "y": "𓍵",
    "z": "𓃷",
    # Special characters
    "_": "𓃟",
    "{": "𓂀",
    "}": "𓅡",
    "'": "𓎬",
    ".": "𓊢",
    ",": "𓆯",
    " ": "𓋪",
    # Numbers
    "0": "𓅿", "1": "𓊘", "2": "𓂆", "3": "𓎿", "4": "𓁹",
    "5": "𓉓", "6": "𓎜", "7": "𓋮", "8": "𓃺", "9": "𓌷",
    # Upper case
    "A": "𓏬", "B": "𓐍", "C": "𓇌", "D": "𓃜", "E": "𓂶",
    "F": "𓆟", "G": "𓐧", "H": "𓈉", "I": "𓏵", "J": "𓅒",
    "K": "𓅴", "L": "𓂻", "M": "𓆡", "N": "𓀊", "O": "𓆺",
    "P": "𓃦", "Q": "𓆄", "R": "𓄀", "S": "𓄁", "T": "𓇁",
    "U": "𓀟", "V": "𓃙", "W": "𓋸", "X": "𓍪", "Y": "𓉬",
    "Z": "𓌎"
}

# Hieroglyphs to plain text - modified to skip unknown hieroglyphs
def hieroglyphs_to_text(hieroglyphs):
    reverse_map = {v: k for k, v in hieroglyph_map.items()}
    result = ""
    for char in hieroglyphs:
        if char in reverse_map:
            result += reverse_map[char]
        # Skip character if not in the reverse map
    return result

# Egyptian website names for the fake API
EGYPTIAN_WEBSITES = [
    "ancientpyramids.eg",
    "pharaohtreasures.com",
    "tutankhamun-archives.org",
    "valley-of-kings.net",
    "egyptology-database.com",
    "niletreasury.eg",
    "sphinxarchives.org"
]

# Egyptian pharaoh names and titles for random name generation
PHARAOH_FIRST_NAMES = [
    "Amenhotep", "Tutankhamun", "Ramses", "Thutmose", "Akhenaten", 
    "Khufu", "Hatshepsut", "Cleopatra", "Nefertiti", "Seti"
]

PHARAOH_TITLES = [
    "the-Great", "Keeper-Of-Secrets", "Master-Of-Tombs", "Ruler-Of-Sands",
    "Guardian-Of-Pyramids", "Lord-Of-Nile", "Chosen-By-Ra", "Beloved-Of-Osiris",
    "Eye-Of-Horus", "Protector-Of-Afterlife"
]

# Constants
def generate_random_string(length=8):
    """Generate a random string of specified length"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_session_data():
    """Get or create session data with random values"""
    if 'initialized' not in session:
        session['secret_path'] = generate_random_string(10)
        session['admin_name'] = f"{random.choice(PHARAOH_FIRST_NAMES)}-{random.choice(PHARAOH_FIRST_NAMES)}-{random.choice(PHARAOH_TITLES)}"
        session['api_domain'] = random.choice(EGYPTIAN_WEBSITES)
        session['port_number'] = random.randint(1000, 9999)
        session['initialized'] = True
    
    return session['secret_path'], session['admin_name'], session['api_domain'], session['port_number']

# Treasure inventory data
TREASURES = {
    "gold": "783 gold pieces",
    "artifacts": "142 ancient artifacts",
    "wine": "56 amphoras of wine",
    "jewels": "329 precious stones and jewels"
}

# Main route - Challenge entrance
@app.route('/')
def index():
    # Initialize session data with random values
    secret_path, admin_name, api_domain, port_number = get_session_data()
    
    # Generate hints
    port_hint = f"𓍶𓊿𓍄𓎛𓋪{hieroglyph_map.get(str(port_number)[0], '')}{hieroglyph_map.get(str(port_number)[1], '')}{hieroglyph_map.get(str(port_number)[2], '')}{hieroglyph_map.get(str(port_number)[3], '')}"
    localtomb_hint = "𓎛𓍄𓍵𓋪𓍖𓊿𓋏𓏏𓍖𓎛𓊿𓋫𓈬"
    
    return render_template('index.html', 
                          treasures=TREASURES.keys(), 
                          api_domain=api_domain, 
                          port_number=port_number, 
                          port_hint=port_hint,
                          localtomb_hint=localtomb_hint)

# Hieroglyphs translator endpoint - now only translates hieroglyphs to text
@app.route('/translate', methods=['POST'])
def translate():
    text = request.form.get('text', '')
    # Note: We ignore the direction parameter and always convert hieroglyphs to text
    result = hieroglyphs_to_text(text)
    return jsonify({'result': result})

# Stock check endpoint
@app.route('/check-stock', methods=['POST'])
def check_stock():
    # Get the sarcophagiAPI parameter from the form
    sarcophagi_url = request.form.get('sarcophagiAPI', '')
    secret_path, admin_name, api_domain, port_number = get_session_data()
    
    # Regular stock check response for URLs containing our treasure types
    if any(treasure in sarcophagi_url for treasure in TREASURES.keys()):
        # Extract which treasure is being requested
        treasure = next((t for t in TREASURES.keys() if t in sarcophagi_url), 'gold')
        api_url = f"http://{api_domain}/contents/{treasure}"
        stock_result = f"Current stock of {treasure}: {TREASURES[treasure]}"
        return render_template('partials/stock_result.html', stock_result=stock_result, api_url=api_url)
    
    # Handle SSRF attempts
    if sarcophagi_url.startswith('http://'):
        # Parse the URL to get the path
        parsed_url = urlparse(sarcophagi_url)
        
        # Check if the URL is valid for our challenge - accept both with and without port
        if parsed_url.netloc == f'localtomb:{port_number}' or parsed_url.netloc == 'localtomb':
            path = parsed_url.path.strip('/') if parsed_url.path else ''
            
            # Simulate different responses based on the path
            if path == 'pharaoh':
                return render_template('partials/pharaoh.html', secret_path=secret_path)
            elif path.startswith(f'pharaoh/{secret_path}/secrettomb'):
                return render_template('partials/secrettomb.html', admin_name=admin_name)
            else:
                return render_template('partials/unknown.html', port_number=port_number)
    
    # Return error for invalid inputs
    return render_template('partials/error.html', port_number=port_number)

# Verification endpoint for the sacred name
@app.route('/verify', methods=['POST'])
def verify_name():
    username = request.form.get('username', '')
    
    # Fix: Unpack all 4 values returned by get_session_data()
    secret_path, admin_name, api_domain, port_number = get_session_data()
    
    if username == admin_name:
        return render_template('success.html', flag=f"O24{{4nkh_th3_k3y_0f_l1f3_unl0ck5_7h3_s4cr3d_t0mb}}")
    else:
        return render_template('failure.html')

# Handle admin function requests
@app.route('/admin-function', methods=['POST'])
def admin_function():
    function = request.form.get('function', '')
    return render_template('partials/access_denied.html')

# Direct access to secret tomb (should be blocked)
@app.route('/pharaoh/<path:subpath>', methods=['GET'])
def secret_tomb_direct(subpath):
    return render_template('partials/access_denied.html')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5005)