from bitstring import BitArray
from PIL import Image
import io


def embed(P, M, S, C):
    """
    Embed message M into carrier P starting at bit S with periodicity C.
    
    Parameters:
    P - Carrier data as bytes
    M - Message to embed as bytes
    S - Starting bit position
    C - Periodicity (int or list of int)
    
    Returns:
    Modified carrier data as bytes
    """
    P_bits = BitArray(P)
    M_bits = BitArray(M)
    pos = S
    m_idx = 0
    c_idx = 0
    while m_idx < len(M_bits) and pos < len(P_bits):
        P_bits[pos] = M_bits[m_idx]
        m_idx += 1
        pos += C[c_idx % len(C)]
        c_idx += 1
    return P_bits.tobytes()


def extract(modified_P, S, C, M_length):
    """
    Extract message from modified_P starting at bit S with periodicity C,
    up to M_length bits.
    
    Parameters:
    modified_P - Modified carrier data as bytes
    S - Starting bit position
    C - Periodicity (int or list of int)
    M_length - Length of the message in bits
    
    Returns:
    Extracted message as bytes
    """
    P_bits = BitArray(modified_P)
    pos = S
    extracted_bits = BitArray()
    c_idx = 0
    while len(extracted_bits) < M_length and pos < len(P_bits):
        extracted_bits.append(P_bits[pos:pos+1])
        pos += C[c_idx % len(C)]
        c_idx += 1
    return extracted_bits.tobytes()


def get_max_bits(P_len, S, C):
    """
    Calculate the max number of bits that can be embedded in P_len bits
    starting at S with C.

    Parameters:
    P_len - Length of carrier in bits
    S - Starting bit position
    C - Periodicity (int or list of int)
    
    Returns:
    Max number of embeddable bits
    """
    pos = S
    count = 0
    c_idx = 0
    while pos < P_len:
        count += 1
        pos += C[c_idx % len(C)]
        c_idx += 1
    return count


def embed_in_png(image_file, message, S, C):
    """
    Embed a message into a PNG image's pixel data.
    Allows for transparency.
    Because of compression, size could change.

    Parameters:
    image_file - File-like object or path to the input PNG image
    message - Message to embed as bytes
    S - Starting bit position in the pixel data
    C - Periodicity for embedding

    Returns:
    A BytesIO object containing the modified PNG image
    """
    # Open PNG and convert to RGB (no alpha channel)
    img = Image.open(image_file).convert('RGBA')
    pixel_data = img.tobytes()

    # Separate RGB and A bytes
    rgb_data = bytearray()
    a_data = bytearray()
    for i in range(0, len(pixel_data), 4):
        rgb_data.extend(pixel_data[i:i+3])  # R, G, B
        a_data.append(pixel_data[i+3])      # A
    
    # Check if the message fits
    usable_rgb = bytes(rgb_data)
    P_len = len(usable_rgb) * 8
    max_bits = get_max_bits(P_len, S, C)
    if max_bits < len(message) * 8:
        raise ValueError("Message is too large for the image")
    
    # Embed the message into the RGB bytes only
    modified_rgb_data = embed(usable_rgb, message, S, C)
    
    # Reconstruct the modified pixel data
    modified_pixel_data = bytearray()
    for i in range(len(a_data)):
        start = i * 3
        modified_pixel_data.extend(modified_rgb_data[start:start+3])  # Modified R, G, B
        modified_pixel_data.append(a_data[i])                        # Original A
    # Create a new RGBA image with the modified pixel data
    modified_img = Image.frombytes('RGBA', img.size, bytes(modified_pixel_data))
    
    # Save to a new BytesIO file-like object
    output = io.BytesIO()
    modified_img.save(output, 'PNG')
    output.seek(0)  # Reset pointer to the start for reading
    return output


def extract_from_png(modified_image_path, S, C, M_length):
    """
    Extract a message from a PNG image's pixel data.
    Allows for transparency.
    
    Parameters:
    modified_image_path - Path to the modified PNG image
    S - Starting bit position in the pixel data
    C - Periodicity for extraction
    M_length - Length of the message in bits
    
    Returns:
    Extracted message as bytes
    """
    # Open the modified image in RGBA mode
    img = Image.open(modified_image_path).convert('RGBA')
    # Get the pixel data as a byte sequence
    pixel_data = img.tobytes()
    
    # Extract only the RGB bytes
    rgb_data = bytearray()
    for i in range(0, len(pixel_data), 4):
        rgb_data.extend(pixel_data[i:i+3])  # R, G, B only
    
    # Extract the message from the RGB bytes
    extracted_message = extract(bytes(rgb_data), S, C, M_length)
    return extracted_message


if __name__ == "__main__":
    IMAGE = "cat_surprised.png"
    MESSAGE = "message.txt"
    
    # Read the message as bytes
    with open(MESSAGE, "rb") as f:
        msg = f.read()
    
    S = 0  # Start bit
    C = 8  # Replace the LSB of each byte (every 8th bit)
    
    # Embed the message into the PNG
    mod_img = embed_in_png(IMAGE, msg, S, C)
    print("Message embedded successfully!")
    
    # Extract the message from the modified PNG
    M_length = len(msg) * 8
    extracted_message = extract_from_png(mod_img, S, C, M_length)
    try:
        print("Extracted Message:", extracted_message.decode("utf-8"))
    except UnicodeDecodeError:
        print("Extracted Message (as bytes):", extracted_message)