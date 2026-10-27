"""Versioned AES-GCM storage. Keys come only from the runtime environment."""
import base64
import binascii
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = 'aesgcm:v1:'

def load_key(name):
    try:
        key = base64.b64decode(os.environ[name], validate=True)
    except (KeyError, ValueError, binascii.Error) as exc:
        raise ValueError(f'{name} must contain a base64-encoded 32-byte key') from exc
    if len(key) != 32:
        raise ValueError(f'{name} must decode to 32 bytes')
    return key

def context(note_id):
    return f'notesapp:notes.comment:v1:{int(note_id)}'.encode('ascii')

def encrypt_comment(value, note_id):
    if value is None: return None
    nonce = os.urandom(12)
    ciphertext = AESGCM(load_key('COMMENT_KEY_B64')).encrypt(
        nonce, value.encode('utf-8'), context(note_id))
    return PREFIX + base64.b64encode(nonce + ciphertext).decode('ascii')

def decrypt_comment(value, note_id):
    if value is None: return None
    if not value.startswith(PREFIX):
        raise ValueError('Unencrypted comment: run migrate_comments.py first')
    raw = base64.b64decode(value[len(PREFIX):], validate=True)
    if len(raw) < 28: raise ValueError('Truncated encrypted comment')
    return AESGCM(load_key('COMMENT_KEY_B64')).decrypt(
        raw[:12], raw[12:], context(note_id)).decode('utf-8')

def decrypt_rows(rows):
    for row in rows:
        row['comment'] = decrypt_comment(row['comment'], row['id'])
    return rows