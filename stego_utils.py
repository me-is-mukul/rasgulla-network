from PIL import Image
import os

# ================================
# NEW SAFE LENGTH-PREFIX STEGANOGRAPHY
# ================================

def hide_data_in_image(image_path, data, output_path):
    """
    Hide binary data inside an image using LSB steganography.
    Stores the length of the data in the first 32 bits.
    Prevents padding corruption issues.
    """

    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    # Store data length in first 4 bytes (32 bits)
    data_length = len(data)
    length_bytes = data_length.to_bytes(4, byteorder='big')

    payload = length_bytes + data  # Final payload to embed

    # Convert payload to binary string
    binary_data = ''.join(format(byte, '08b') for byte in payload)

    img_capacity = img.width * img.height * 3  # RGB → 3 bits per pixel
    if len(binary_data) > img_capacity:
        raise ValueError("Data too large to hide in the image")

    pixels = img.load()
    data_index = 0

    for y in range(img.height):
        for x in range(img.width):
            if data_index >= len(binary_data):
                break

            r, g, b = pixels[x, y]

            # 1 bit → R
            r = (r & ~1) | int(binary_data[data_index])
            data_index += 1

            # 1 bit → G
            if data_index < len(binary_data):
                g = (g & ~1) | int(binary_data[data_index])
                data_index += 1

            # 1 bit → B
            if data_index < len(binary_data):
                b = (b & ~1) | int(binary_data[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)

        if data_index >= len(binary_data):
            break

    img.save(output_path)


def extract_data_from_image(image_path):
    """
    Extract binary data hidden inside an image.
    Reads the first 32 bits as the length, then extracts that many bytes.
    """

    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    bits = []

    # Extract ALL LSB bits from image
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = img.getpixel((x, y))
            bits.append(str(r & 1))
            bits.append(str(g & 1))
            bits.append(str(b & 1))

    bitstream = ''.join(bits)

    # First 32 bits = data length
    length_bits = bitstream[:32]
    data_length = int(length_bits, 2)

    # Extract next (data_length * 8) bits
    data_bits = bitstream[32:32 + (data_length * 8)]

    if len(data_bits) < data_length * 8:
        raise ValueError("Extracted data is incomplete or corrupted.")

    # Convert bits → bytes
    data = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = int(data_bits[i:i + 8], 2)
        data.append(byte)

    return bytes(data)
