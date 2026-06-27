# S-Box (4-bit input -> 4-bit output)
S_BOX = [0, 12, 5, 6, 11, 9, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]

# Permutation (8-bit)
# Bit `i` goes to position `P(i)`
# P = [7, 3, 5, 1, 6, 2, 4, 0] means:
# output bit at index 7 comes from input bit 0 (if i=0)
# output bit at index 3 comes from input bit 1 (if i=1)
# etc...
# The problem statement: "bit i goes to position P(i)"
# So if input is b7 b6 b5 b4 b3 b2 b1 b0 (where b0 is i=0)
# Then in the output, position P(i) gets the value of input bit i.
P_PERM = [7, 3, 5, 1, 6, 2, 4, 0]

def apply_permutation(byte_val):
    """Applies the P permutation to an 8-bit value."""
    out_val = 0
    for i in range(8):
        # Extract the i-th bit from byte_val (0-indexed from right)
        bit = (byte_val >> i) & 1
        # Place it at position P_PERM[i] in the output
        out_val |= (bit << P_PERM[i])
    return out_val

def feistel_function(half_block, round_key):
    """
    F Function for Feistel cipher.
    half_block: 8 bits
    round_key: 8 bits
    """
    # 1. XOR with round key
    x = half_block ^ round_key

    # 2. Pass high 4 bits through S-Box
    h = S_BOX[x >> 4]

    # 3. Pass low 4 bits through S-Box
    l = S_BOX[x & 0x0F]

    # 4. Recombine
    tmp = (h << 4) | l

    # 5. Apply permutation
    out = apply_permutation(tmp)

    return out

def get_round_keys(master_key):
    """
    Extracts 4 round keys (8-bit each) from the 16-bit master key.
    Ki = ((master_key >> i) XOR (master_key >> (i + 4))) & 0xFF
    """
    keys = []
    for i in range(1, 5): # i from 1 to 4
        ki = ((master_key >> i) ^ (master_key >> (i + 4))) & 0xFF
        keys.append(ki)
    return keys

def feistel_encrypt_block(block, master_key):
    """
    Encrypts a 16-bit block using a 4-round Feistel network.
    block: 16 bits
    """
    round_keys = get_round_keys(master_key)

    left = (block >> 8) & 0xFF
    right = block & 0xFF

    for i in range(4):
        ki = round_keys[i]
        new_left = right
        new_right = left ^ feistel_function(right, ki)

        left = new_left
        right = new_right

    # Swap back at the end
    return (right << 8) | left

def feistel_decrypt_block(block, master_key):
    """
    Decrypts a 16-bit block using a 4-round Feistel network.
    block: 16 bits
    """
    # For decryption, round keys are used in reverse order
    round_keys = get_round_keys(master_key)[::-1]

    left = (block >> 8) & 0xFF
    right = block & 0xFF

    for i in range(4):
        ki = round_keys[i]
        new_left = right
        new_right = left ^ feistel_function(right, ki)

        left = new_left
        right = new_right

    # Swap back at the end
    return (right << 8) | left

def text_to_blocks(text):
    """
    Converts string to 16-bit blocks with ISO/IEC 7816-4 padding.
    Padding rule: Add byte 10000000 (0x80) to the end of data.
    Then add 00000000 (0x00) until the total length is a multiple of 16 bits (2 bytes).
    Note: Even if original data is a multiple of 16 bits, padding MUST be added.
    """
    # 1. Convert text to bytes
    data_bytes = text.encode('ascii')

    # 2 & 3. Add padding
    padded_bytes = bytearray(data_bytes)
    padded_bytes.append(0x80) # 10000000

    while len(padded_bytes) % 2 != 0:
        padded_bytes.append(0x00)

    # 4. Split into 16-bit blocks
    blocks = []
    for i in range(0, len(padded_bytes), 2):
        block = (padded_bytes[i] << 8) | padded_bytes[i+1]
        blocks.append(block)

    return blocks

def blocks_to_text(blocks):
    """
    Converts 16-bit blocks back to text, removing ISO/IEC 7816-4 padding.
    """
    # 1. Reconstruct bytes
    data_bytes = bytearray()
    for block in blocks:
        data_bytes.append((block >> 8) & 0xFF)
        data_bytes.append(block & 0xFF)

    # 2. Find padding: Traverse from the end backwards to find 0x80
    pad_idx = len(data_bytes) - 1
    while pad_idx >= 0 and data_bytes[pad_idx] == 0x00:
        pad_idx -= 1

    if pad_idx >= 0 and data_bytes[pad_idx] == 0x80:
        data_bytes = data_bytes[:pad_idx]
    else:
        raise ValueError("Invalid padding format")

    # 3. Decode ASCII
    return data_bytes.decode('ascii')

def encrypt_message(message, master_key):
    """Encrypts a full string message."""
    blocks = text_to_blocks(message)
    encrypted_blocks = [feistel_encrypt_block(b, master_key) for b in blocks]
    return encrypted_blocks

def decrypt_message(encrypted_blocks, master_key):
    """Decrypts a list of 16-bit encrypted blocks back to a string."""
    decrypted_blocks = [feistel_decrypt_block(b, master_key) for b in encrypted_blocks]
    return blocks_to_text(decrypted_blocks)
