"""Argon2id verification with one-time upgrade of legacy course passwords."""
import hmac
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

def verify_password(stored, supplied):
    """Return (authenticated, replacement_hash_or_None). Never downgrade a hash."""
    if not isinstance(stored,str) or not isinstance(supplied,str): return False,None
    if stored.startswith('$argon2'):
        try:
            ph.verify(stored,supplied)
        except (VerificationError,InvalidHashError):
            return False,None
        return True, ph.hash(supplied) if ph.check_needs_rehash(stored) else None
    if hmac.compare_digest(stored.encode('utf-8'),supplied.encode('utf-8')):
        return True,ph.hash(supplied)
    return False,None