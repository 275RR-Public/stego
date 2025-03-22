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
    C - Periodicity (integer)
    
    Returns:
    Modified carrier data as bytes
    """
    P_bits = BitArray(P)
    M_bits = BitArray(M)
    pos = S
    m_idx = 0
    while m_idx < len(M_bits) and pos < len(P_bits):
        P_bits[pos] = M_bits[m_idx]
        m_idx += 1
        pos += C
    return P_bits.tobytes()


def extract(modified_P, S, C, M_length):
    """
    Extract message from modified_P starting at bit S with periodicity C, up to M_length bits.
    
    Parameters:
    modified_P - Modified carrier data as bytes
    S - Starting bit position
    C - Periodicity (integer)
    M_length - Length of the message in bits
    
    Returns:
    Extracted message as bytes
    """
    P_bits = BitArray(modified_P)
    pos = S
    extracted_bits = BitArray()
    while len(extracted_bits) < M_length and pos < len(P_bits):
        extracted_bits.append(P_bits[pos:pos+1])
        pos += C
    return extracted_bits.tobytes()


def embed_in_png(image_file, message, S, C):
    """
    Embed a message into a PNG image's pixel data.

    Parameters:
    image_file - File-like object or path to the input PNG image
    message - Message to embed as bytes
    S - Starting bit position in the pixel data
    C - Periodicity for embedding

    Returns:
    A BytesIO object containing the modified PNG image
    """
    # Open PNG and convert to RGB (no alpha channel)
    img = Image.open(image_file).convert('RGB')
    pixel_data = img.tobytes()
    
    # Check if the message fits in the pixel data
    usable_bits = (len(pixel_data) * 8 - S) // C
    if usable_bits < len(message) * 8:
        raise ValueError("Message is too large for the image")
    
    # Embed the message
    modified_pixel_data = embed(pixel_data, message, S, C)
    
    # Reconstruct the modified image
    modified_img = Image.frombytes('RGB', img.size, modified_pixel_data)
    
    # Save to a new BytesIO object
    output = io.BytesIO()
    modified_img.save(output, 'PNG')
    output.seek(0)  # Reset pointer to the start for reading
    return output


def extract_from_png(modified_image_path, S, C, M_length):
    """
    Extract a message from a PNG image's pixel data.
    
    Parameters:
    modified_image_path - Path to the modified PNG image
    S - Starting bit position in the pixel data
    C - Periodicity for extraction
    M_length - Length of the message in bits
    
    Returns:
    Extracted message as bytes
    """
    # Open modified PNG and convert to RGB (no alpha channel)
    img = Image.open(modified_image_path).convert('RGB')
    pixel_data = img.tobytes()
    
    # Extract the message
    extracted_message = extract(pixel_data, S, C, M_length)
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