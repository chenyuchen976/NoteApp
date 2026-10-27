"""Transactional, repeatable migration of the existing comment column."""
from app import get_db
from crypto_utils import PREFIX, load_key, encrypt_comment, decrypt_comment

def migrate():
    load_key('COMMENT_KEY_B64')
    conn = get_db()
    conn.autocommit = False
    count = 0
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute('LOCK TABLE notes IN SHARE ROW EXCLUSIVE MODE')
                cur.execute('SELECT id, comment FROM notes ORDER BY id')
                for row in cur.fetchall():
                    value = row['comment']
                    if value is None: continue
                    if value.startswith(PREFIX):
                        decrypt_comment(value, row['id'])
                    else:
                        cur.execute('UPDATE notes SET comment = %s WHERE id = %s',
                                    (encrypt_comment(value, row['id']), row['id']))
                        count += 1
    finally:
        conn.close()
    print(f'Encrypted {count} legacy comments; existing ciphertext authenticated.')
    return count

if __name__ == '__main__':
    migrate()