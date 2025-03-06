import os
import random
import string
from flask import Flask, render_template, request, send_file, make_response, jsonify
from fpdf import FPDF
import io
import hashlib
import time
import datetime

app = Flask(__name__)

# Global variable to store the special document ID containing the flag
special_doc_id = None

# Configuration
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
PDF_CACHE_DIR = os.path.join(STATIC_DIR, 'pdf_cache')
PAPYRUS_TEXTS = [
    "The pharaoh Khufu orders the construction of the Great Pyramid, a monument to last eternity.",
    "Scribes record the rising of the Nile, bringing life to the parched lands of Egypt.",
    "Priests of Amun-Ra prepare the sacred rituals to ensure the sun's return at dawn.",
    "The Book of the Dead contains spells to guide the deceased through the underworld.",
    "Hieroglyphs tell of battles against the Hittites, fierce warriors from the north.",
    "Astronomers chart the movement of stars, predicting the flooding of the Nile.",
    "The sacred scarab beetle represents rebirth and the morning sun's journey.",
    "Craftsmen prepare the tomb of Tutankhamun with treasures for the afterlife.",
    "The Eye of Horus protects against evil and brings health to the faithful.",
    "Queen Nefertiti's beauty is celebrated in stone and praised throughout the kingdom.",
    "The healing papyrus describes remedies made from plants along the Nile.",
    "Sacred cats patrol the temples, honored as manifestations of the goddess Bastet.",
    "Workers quarry limestone blocks for the pharaoh's eternal resting place.",
    "The sacred ibis represents Thoth, god of wisdom and writing.",
    "Sailors navigate the Nile using stars and ancient knowledge passed down generations.",
    "Embalmers prepare the body for its journey to the Field of Reeds.",
    "The ankh symbol represents eternal life, held by gods in sacred imagery.",
    "Scribes record the pharaoh's decree on taxes from the recent harvest.",
    "The Book of Thoth contains dangerous knowledge, hidden from the uninitiated.",
    "Divine barques carry the gods across the sky and through the underworld."
]

# Create necessary directories if they don't exist
os.makedirs(PDF_CACHE_DIR, exist_ok=True)

# Flag to be hidden in metadata of one random restricted document
FLAG = "O24{4nc13nt_p4pyru5_15_4_h1dd3n_tr34sur3}"

# Decoy flags to be placed in document text - will assign one decoy to each of 8 specific documents
DECOY_FLAGS = [
    "O24{f4k3_fl4g_n1c3_try}",
    "O24{n0t_th3_r34l_fl4g_k33p_l00k1ng}",
    "O24{4lm0st_th3r3_but_n0t_qu1t3}",
    "O24{y0u_f0und_m3_but_1m_ju5t_4_d3c0y}",
    "O24{tr34sur3_hunt3r5_mu5t_d1g_d33p3r}",
    "O24{m3t4d4t4_m1ght_b3_us3ful_h1nt}",
    "O24{4nc13nt_s3cr3ts_r3qu1r3_4nc13nt_m3th0ds}",
    "O24{pdf_h4s_m4ny_l4y3rs_l1k3_4n_0n10n}"
]

# Documents that will contain decoy flags (8 specific IDs between 1-100)
# Make sure document #23 isn't in this list since it has the real flag
DECOY_DOCS = [10, 25, 37, 42, 58, 73, 81, 94]

def generate_papyrus_pdf(doc_id, collection="public", regenerate=False):
    """Generate a PDF that looks like an ancient papyrus document"""
    global special_doc_id
    
    # Create a deterministic filename based on doc_id and collection
    filename = f"papyrus_{collection}_{doc_id}.pdf"
    filepath = os.path.join(PDF_CACHE_DIR, filename)
    
    # If the file already exists and we're not regenerating, return it
    if os.path.exists(filepath) and not regenerate:
        return filepath
    
    # Initialize a random generator with deterministic seed based on doc_id and collection
    local_seed = SEED = int(hashlib.md5(f"egyptian_papyrus_lab_{doc_id}_{collection}".encode()).hexdigest(), 16) % 10000
    rand_gen = random.Random(local_seed)
    
    # Create PDF
    pdf = FPDF()
    pdf.add_page()
    
    # Set up the papyrus-like appearance
    pdf.set_fill_color(240, 230, 200)  # Light papyrus color
    pdf.rect(0, 0, 210, 297, style="F")  # Fill the page
    
    # Add some papyrus texture effects
    for i in range(50):
        x = rand_gen.randint(5, 200)
        y = rand_gen.randint(5, 290)
        pdf.set_fill_color(230, 220, 190)  # Slightly darker spots
        pdf.rect(x, y, rand_gen.randint(1, 3), rand_gen.randint(1, 3), style="F")
    
    # Set font for ancient text
    pdf.set_font("Times", "", 12)
    pdf.set_text_color(50, 30, 10)  # Dark brown text
    
    # Add a title
    pdf.set_font("Times", "B", 16)
    pdf.cell(0, 20, f"Ancient Papyrus #{doc_id}", 0, 1, "C")
    pdf.set_font("Times", "", 12)
    
    # Add collection indicator
    pdf.set_font("Times", "I", 10)
    pdf.cell(0, 10, f"Collection: {collection.upper()}", 0, 1, "C")
    pdf.set_font("Times", "", 12)
    
    # Add papyrus text content
    y_position = 60
    
    # Select some random texts
    selected_texts = rand_gen.sample(PAPYRUS_TEXTS, 5)
    
    for text in selected_texts:
        pdf.set_y(y_position)
        pdf.multi_cell(0, 10, text)
        y_position += 30
    
    # Add document reference info WITHOUT any flag-like fragments
    pdf.set_y(y_position + 10)
    pdf.cell(0, 10, f"Document Reference: AEP-{doc_id}", 0, 1, "L")
    
    pdf.set_y(y_position + 20)
    pdf.cell(0, 10, f"Classification Level: {collection.upper()}", 0, 1, "L")
    
    pdf.set_y(y_position + 30)
    pdf.cell(0, 10, f"Authentication Code: {rand_gen.randint(10000, 99999)}", 0, 1, "L")
    
    # Set metadata
    pdf.set_title(f"Ancient Egyptian Papyrus #{doc_id}")
    
    # The flag is ONLY placed in the restricted collection document #23
    is_special_document = (collection == "restricted" and doc_id == 23)
    
    if is_special_document:
        # Put the flag directly in the Author field for document #23
        pdf.set_author(FLAG)
        pdf.set_subject("Ancient Egyptian Historical Documents")
        pdf.set_keywords("ancient, egypt, papyrus, history, archaeology")
        print(f"Added flag to document {doc_id} in collection {collection}")
    else:
        # Set normal metadata for non-special documents
        pdf.set_author("Digital Papyrus Project")
        pdf.set_subject("Ancient Egyptian Historical Documents")
        pdf.set_keywords("ancient, egypt, papyrus, history, archaeology")
    
    # Add decoy flags to specific documents in the restricted collection
    # Make sure document #23 doesn't get a decoy flag since it has the real flag
    if collection == "restricted" and doc_id in DECOY_DOCS and doc_id != 23:
        # Get the decoy flag for this document
        decoy_index = DECOY_DOCS.index(doc_id)
        decoy_flag = DECOY_FLAGS[decoy_index % len(DECOY_FLAGS)]
        
        # Add the decoy flag in a semi-hidden way
        pdf.set_font("Times", "", rand_gen.choice([6, 7, 8]))  # Small text
        
        # Choose a random color - some dark enough to see, some very light
        color_intensity = rand_gen.randint(50, 200)
        pdf.set_text_color(color_intensity, color_intensity, color_intensity)
        
        # Position it randomly on the page
        pdf.set_y(rand_gen.randint(100, 250))
        pdf.set_x(rand_gen.randint(20, 100))
        
        # Different prefixes to make it look "official"
        prefix = rand_gen.choice([
            "Special Classification: ",
            "Security Notice: ",
            "Clearance Code: ",
            "Restricted Access: ",
            "Authorization Required: ",
            "Confidential: "
        ])
        
        pdf.cell(0, 10, f"{prefix}{decoy_flag}", 0, 1, "L")
    
    # Save the PDF to the cache directory
    pdf.output(filepath)
    return filepath

@app.route('/')
def index():
    # Use a fixed document ID for the flag - always document #23
    global special_doc_id
    special_doc_id = 23
    
    print(f"Flag will be hidden in restricted document #{special_doc_id}")
    
    # Clear any cached PDFs to ensure clean generation
    for file in os.listdir(PDF_CACHE_DIR):
        if file.startswith("papyrus_"):
            try:
                os.remove(os.path.join(PDF_CACHE_DIR, file))
            except:
                pass
                
    return render_template('index.html')

@app.route('/papyrus')
def papyrus_list():
    return render_template('papyrus_list.html', papyrus_count=5)

@app.route('/papyrus/view')
def papyrus_view():
    doc_id = request.args.get('id', '1')
    
    try:
        doc_id = int(doc_id)
        if doc_id < 1 or doc_id > 5:
            return "Access denied: You do not have clearance for this document.", 403
    except ValueError:
        return "Invalid document ID", 400
    
    # Always use public collection for normal view
    collection = "public"
    
    return render_template('papyrus_view.html', doc_id=doc_id, collection=collection)

@app.route('/papyrus/download')
def papyrus_download_single():
    doc_id = request.args.get('id', '1')
    collection = request.args.get('collection', 'public')
    
    try:
        doc_id = int(doc_id)
        if collection == "public" and (doc_id < 1 or doc_id > 5):
            return "Access denied: You do not have clearance for this document.", 403
    except ValueError:
        return "Invalid document ID", 400
    
    # Generate the PDF
    pdf_path = generate_papyrus_pdf(doc_id, collection)
    
    # Send the file as an attachment
    return send_file(pdf_path, as_attachment=True, 
                    download_name=f"papyrus_{doc_id}.pdf")

@app.route('/papyrus/download-all', methods=['GET', 'POST', 'PUT'])
def papyrus_download_all():
    collection = request.args.get('collection', 'public')
    
    # Normal GET/POST requests only allow public collection
    if request.method in ['GET', 'POST'] and collection != "public":
        return "Access denied: You do not have clearance for this collection.", 403
    
    # PUT requests allow changing the collection parameter
    if request.method == 'PUT':
        collection = request.args.get('collection', 'public')
    
    # Create a zip file in memory with all PDFs from the specified collection
    if collection == "public":
        # For public collection, only include docs 1-5
        doc_count = 5
    else:
        # For restricted collection, include docs 1-100
        doc_count = 100
    
    # For zip file creation
    import zipfile
    from io import BytesIO
    
    # Force regeneration of all PDFs for the collection to ensure consistency
    for i in range(1, doc_count + 1):
        generate_papyrus_pdf(i, collection, regenerate=True)
    
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        for i in range(1, doc_count + 1):
            # Add each PDF to zip
            pdf_path = os.path.join(PDF_CACHE_DIR, f"papyrus_{collection}_{i}.pdf")
            zf.write(pdf_path, f"papyrus_{i}.pdf")
    
    # Prepare zip file for download
    memory_file.seek(0)
    
    response = make_response(memory_file.getvalue())
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = f'attachment; filename=papyrus_collection_{collection}.zip'
    
    # Add a hint in the response headers
    response.headers['X-Papyrus-Collection'] = collection
    response.headers['X-Total-Documents'] = str(doc_count)
    
    return response

if __name__ == '__main__':
    # Pre-generate some PDFs on startup
    print("Pre-generating public papyrus documents...")
    for i in range(1, 6):
        generate_papyrus_pdf(i, "public")
    print("Done!")
    
    # Start the Flask application
    app.run(debug=True, port=5007)