import os
import base64
import pytest

os.environ["COMMENT_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()
os.environ["EXPORT_HMAC_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()

from web.crypto_utils import encrypt_comment, decrypt_comment

def test_encrypt_decrypt_comment():
    note_id = 1
    original = "This is a secret comment."
    encrypted = encrypt_comment(original, note_id)
    
    assert encrypted.startswith("aesgcm:v1:")
    decrypted = decrypt_comment(encrypted, note_id)
    assert decrypted == original