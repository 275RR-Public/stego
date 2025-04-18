import os, re

# Helper function to sanitize and validate filenames for Output Filename text inputs
def sanitize_and_validate_filename(base_filename, existing_filenames, suffix=""):
    """
    Sanitize the base filename to prevent path traversal and invalid characters,
    ensure it doesn't overwrite existing files, and append the suffix if provided.
    
    Parameters:
    - base_filename: The user-provided base filename
    - existing_filenames: List of existing filenames in the user's folder
    - suffix: Optional suffix to append (e.g., '.enc', '_rsa.enc')
    
    Returns:
    - A safe and unique filename with the suffix appended
    """
    # Remove any directory components
    safe_base = os.path.basename(base_filename)
    
    # Remove invalid characters (allow alphanumeric, _, -, .)
    safe_base = re.sub(r'[^a-zA-Z0-9._-]', '', safe_base)
    
    # Ensure base is not empty
    if not safe_base:
        safe_base = "unnamed_file"
    
    # Limit length (reserve space for suffix and potential uniqueness counter)
    max_base_length = 255 - len(suffix) - 10  # Reserve space for "_1" etc.
    if len(safe_base) > max_base_length:
        safe_base = safe_base[:max_base_length]
    
    # Construct the full filename with suffix
    full_filename = safe_base + suffix
    
    # Check for uniqueness
    base, ext = os.path.splitext(full_filename)
    counter = 1
    unique_filename = full_filename
    while unique_filename in existing_filenames:
        unique_filename = f"{base}_{counter}{ext}"
        counter += 1
    
    return unique_filename

def sanitize_and_validate_hash(hash):
    hash = hash.strip()
    if re.match(r'^[0-9a-fA-F]{64}$', hash):
        return hash.lower()
    else:
        return None