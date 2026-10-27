"""Authenticate the exact CSV bytes; the final footer is outside the CSV data."""
import hashlib
import hmac
import re
from crypto_utils import load_key

MARKER = b'# HMAC-SHA256: '

def sign_export(payload):
    if not payload.endswith(b'\r\n'):
        raise ValueError('CSV payload must end with CRLF')
    digest = hmac.new(load_key('EXPORT_HMAC_KEY_B64'), payload, hashlib.sha256).hexdigest()
    return payload + MARKER + digest.encode('ascii') + b'\r\n'

def verify_export(document):
    payload, marker, footer = document.rpartition(MARKER)
    if not marker or not payload.endswith(b'\r\n'):
        return False
    if not re.fullmatch(rb'[0-9a-f]{64}\r\n', footer):
        return False
    expected = hmac.new(load_key('EXPORT_HMAC_KEY_B64'), payload, hashlib.sha256).hexdigest().encode('ascii')
    return hmac.compare_digest(expected, footer[:-2])