from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.backends import default_backend
import os, string, secrets

# Define symmetric key sizes
SYM_KEY_SIZES = {
    "AES-128": 16,  # 128 bits
    "AES-256": 32,  # 256 bits
    "3-DES": 24     # 192 bits (effective 168 bits due to parity)
}

def encrypt_user_key(master_key, user_key):
    """
    Encrypt the user's encryption key using the master key with AES-GCM.
    
    Parameters:
    master_key - The server-side master key (32 bytes)
    user_key - The user's randomly generated encryption key (32 bytes)
    
    Returns:
    The encrypted user key (nonce + ciphertext + tag)
    """
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)  # 12-byte nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, user_key, None)
    return nonce + ciphertext

def decrypt_user_key(master_key, encrypted_user_key):
    """
    Decrypt the user's encryption key using the master key with AES-GCM.
    
    Parameters:
    master_key - The server-side master key (32 bytes)
    encrypted_user_key - The encrypted user key (nonce + ciphertext + tag)
    
    Returns:
    The decrypted user encryption key (32 bytes)
    """
    nonce = encrypted_user_key[:12]
    ciphertext = encrypted_user_key[12:]
    aesgcm = AESGCM(master_key)
    user_key = aesgcm.decrypt(nonce, ciphertext, None)
    return user_key

def encrypt_data(key, data):
    """Encrypt data using AES-256-CBC with the given key."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_data(key, encrypted_data):
    """Decrypt data using AES-256-CBC with the given key."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def generate_and_encrypt_symmetric_key(algorithm, encryption_key):
    """
    Generate a symmetric key for the given algorithm and encrypt it.
    
    Parameters:
    - algorithm (str): The symmetric algorithm ("AES-128", "AES-256", "3-DES")
    - encryption_key (bytes): The user's encryption key from session state
    
    Returns:
    - bytes: The encrypted symmetric key
    """
    key_size = SYM_KEY_SIZES[algorithm]
    sym_key = os.urandom(key_size)
    encrypted_sym_key = encrypt_data(encryption_key, sym_key)
    return encrypted_sym_key

def generate_and_encrypt_asymmetric_key_pair(encryption_key):
    """
    Generate an RSA key pair, encrypt the private key, and return both keys.
    
    Parameters:
    - encryption_key (bytes): The user's encryption key from session state
    
    Returns:
    - tuple: (public_pem, encrypted_private)
        - public_pem (bytes): Public key in PEM format
        - encrypted_private (bytes): Encrypted private key
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_private = encrypt_data(encryption_key, private_pem)
    return public_pem, encrypted_private

def encrypt_symmetric(data, key, algorithm, mode):
    """
    Encrypt data using the specified symmetric algorithm and mode.
    
    Parameters:
    - data (bytes): The data to encrypt
    - key (bytes): The symmetric key
    - algorithm (str): "AES-128", "AES-256", or "3-DES"
    - mode (str): "CBC" or "GCM" (NO GCM option for 3-DES)
    
    Returns:
    - bytes: Encrypted data (IV + ciphertext for CBC, IV + ciphertext + tag for GCM)
    """
    if algorithm == "3-DES":
        if mode != "CBC":
            raise ValueError("3-DES only supports CBC mode")
        iv = os.urandom(8)  # 8-byte IV for 3-DES
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        padder = padding.PKCS7(64).padder()  # 8-byte block size
        padded_data = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    elif algorithm in ["AES-128", "AES-256"]:
        if mode == "CBC":
            iv = os.urandom(16)  # 16-byte IV for AES
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            padder = padding.PKCS7(128).padder()  # 16-byte block size
            padded_data = padder.update(data) + padder.finalize()
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return iv + ciphertext
        elif mode == "GCM":
            iv = os.urandom(12)  # 12-byte IV recommended for GCM
            encryptor = AESGCM(key)
            ciphertext_with_tag = encryptor.encrypt(iv, data, None)  # Tag is appended
            return iv + ciphertext_with_tag
        else:
            raise ValueError("Invalid mode for AES")
    else:
        raise ValueError("Unsupported algorithm")

def decrypt_symmetric(encrypted_data, key, algorithm, mode):
    """
    Decrypt data using the specified symmetric algorithm and mode.
    
    Parameters:
    - encrypted_data (bytes): The encrypted data (IV + ciphertext or IV + ciphertext + tag)
    - key (bytes): The symmetric key
    - algorithm (str): "AES-128", "AES-256", or "3-DES"
    - mode (str): "CBC" or "GCM" (NO GCM option for 3-DES)
    
    Returns:
    - bytes: Decrypted data
    """
    if algorithm == "3-DES":
        if mode != "CBC":
            raise ValueError("3-DES only supports CBC mode")
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data
    elif algorithm in ["AES-128", "AES-256"]:
        if mode == "CBC":
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data
        elif mode == "GCM":
            iv = encrypted_data[:12]
            ciphertext_with_tag = encrypted_data[12:]  # Tag is at the end
            decryptor = AESGCM(key)
            data = decryptor.decrypt(iv, ciphertext_with_tag, None)
            return data
        else:
            raise ValueError("Invalid mode for AES")
    else:
        raise ValueError("Unsupported algorithm")
    
def load_public_key(pem_bytes):
    """
    Load a public key from PEM-encoded bytes.
    
    Parameters:
        pem_bytes - Bytes containing the PEM-encoded public key
    
    Returns:
        The loaded public key object
    
    Raises:
        ValueError - If the public key cannot be loaded
    """
    try:
        public_key = serialization.load_pem_public_key(
            pem_bytes,
            backend=default_backend()
        )
        return public_key
    except Exception as e:
        raise ValueError(f"Failed to load public key: {str(e)}")

def load_private_key(pem_bytes, password=None):
    """
    Load a private key from PEM-encoded bytes.
    
    Parameters:
        pem_bytes - Bytes containing the PEM-encoded private key
        password - Optional password for decrypting the private key (default: None)
    
    Returns:
        The loaded private key object
    
    Raises:
        ValueError - If the private key cannot be loaded
    """
    try:
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=password,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")
    
def encrypt_asymmetric(data, public_key):
    """
    Encrypt data using hybrid encryption with AES-256-GCM for the data (performance),
    and encrypt the AES key with RSA-OAEP (portability).
    
    Parameters:
    - data: The data to encrypt (bytes)
    - public_key: RSA public key object
    
    Returns:
    - Encrypted data: encrypted_aes_key (256 bytes) + iv (12 bytes) + ciphertext_with_tag
    """
    # Generate a random AES-256 key
    # 1. Because we are enc/dec the key with RSA, this can be a nonce
    # 2. A nonce is actually better than reusing saved symmetric keys
    aes_key = os.urandom(32)
    # Encrypt the AES key with RSA-OAEP
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encrypt the data with AES-256-GCM
    iv = os.urandom(12)
    encryptor = AESGCM(aes_key)
    ciphertext_with_tag = encryptor.encrypt(iv, data, None)
    # Combine components
    return encrypted_aes_key + iv + ciphertext_with_tag

def decrypt_asymmetric(encrypted_data, private_key):
    """
    Decrypt data encrypted with hybrid encryption: AES-256-GCM with RSA-OAEP.
    
    Parameters:
    - encrypted_data: Encrypted data (encrypted_aes_key + iv + ciphertext_with_tag)
    - private_key: RSA private key object
    
    Returns:
    - Decrypted data (bytes)
    """
    # Extract components
    encrypted_aes_key = encrypted_data[:256]  # RSA 2048 OAEP output is 256 bytes
    iv = encrypted_data[256:268]              # GCM IV is 12 bytes
    ciphertext_with_tag = encrypted_data[268:]
    # Decrypt the AES key with RSA-OAEP
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decrypt the data with AES-256-GCM
    decryptor = AESGCM(aes_key)
    data = decryptor.decrypt(iv, ciphertext_with_tag, None)
    return data

def compute_hash(data, algorithm):
    """
    Compute the hash of the given data using the specified algorithm.

    Parameters:
    - data (bytes): The data to hash.
    - algorithm (str): The hashing algorithm ("SHA2-256" or "SHA3-256").

    Returns:
    - str: The hexadecimal representation of the hash.

    Raises:
    - ValueError: If an unsupported algorithm is provided.
    """
    if algorithm == "SHA2-256":
        hash_obj = hashes.Hash(hashes.SHA256())
    elif algorithm == "SHA3-256":
        hash_obj = hashes.Hash(hashes.SHA3_256())
    else:
        raise ValueError("Unsupported algorithm")
    hash_obj.update(data)
    digest = hash_obj.finalize()
    return digest.hex()

def generate_password(length, use_lower, use_upper, use_digits, use_special):
    """
    Generate a random password based on the specified criteria.
    
    Parameters:
    - length: The length of the password.
    - use_lower: Include lowercase letters.
    - use_upper: Include uppercase letters.
    - use_digits: Include digits.
    - use_special: Include special characters.
    
    Returns:
    - A securely generated password string.
    """
    # Define character sets for password generation
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SPECIAL = '!@#$%^&*()'

    charsets = []
    if use_lower:
        charsets.append(LOWERCASE)
    if use_upper:
        charsets.append(UPPERCASE)
    if use_digits:
        charsets.append(DIGITS)
    if use_special:
        charsets.append(SPECIAL)
    
    if not charsets:
        raise ValueError("At least one character type must be selected")
    
    num_types = len(charsets)
    if length < num_types:
        raise ValueError(f"Password length must be at least {num_types} to include all selected character types")
    
    # Ensure at least one character from each selected type
    password = [secrets.choice(charset) for charset in charsets]
    
    # Fill the rest of the password
    all_chars = ''.join(charsets)
    while len(password) < length:
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)