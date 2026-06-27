import unittest
import _bootstrap  # noqa: F401

from src.phase3 import (
    S_BOX,
    apply_permutation,
    get_round_keys,
    feistel_encrypt_block,
    feistel_decrypt_block,
    text_to_blocks,
    blocks_to_text,
    encrypt_message,
    decrypt_message
)

class TestPhase3(unittest.TestCase):
    def test_s_box_matches_project_specification(self):
        self.assertEqual(S_BOX, [0, 12, 5, 6, 11, 9, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2])

    def test_permutation(self):
        # P_PERM = [7, 3, 5, 1, 6, 2, 4, 0]
        # input: 00000001 (bit 0 is 1)
        # bit 0 goes to position 7: 10000000 (128)
        self.assertEqual(apply_permutation(1), 128)

        # input: 00000010 (bit 1 is 1)
        # bit 1 goes to position 3: 00001000 (8)
        self.assertEqual(apply_permutation(2), 8)

    def test_round_keys(self):
        master_key = 0b1010101010101010
        keys = get_round_keys(master_key)
        self.assertEqual(len(keys), 4)

    def test_feistel_block(self):
        master_key = 12345
        block = 54321
        enc = feistel_encrypt_block(block, master_key)
        dec = feistel_decrypt_block(enc, master_key)
        self.assertEqual(block, dec)

    def test_padding(self):
        text = "Hi" # 2 bytes
        blocks = text_to_blocks(text)
        # Since 'Hi' is exactly 16 bits, padding will add another 16-bit block
        self.assertEqual(len(blocks), 2)
        # 'H' = 72, 'i' = 105 -> 01001000 01101001 -> 18537
        self.assertEqual(blocks[0], (72 << 8) | 105)
        # padding block: 10000000 00000000 -> 32768
        self.assertEqual(blocks[1], 0x8000)

        recovered_text = blocks_to_text(blocks)
        self.assertEqual(text, recovered_text)

    def test_encrypt_decrypt_message(self):
        master_key = 54321
        message = "Hello, Secure World!"

        encrypted_blocks = encrypt_message(message, master_key)
        decrypted_message = decrypt_message(encrypted_blocks, master_key)

        self.assertEqual(message, decrypted_message)

if __name__ == '__main__':
    unittest.main()
