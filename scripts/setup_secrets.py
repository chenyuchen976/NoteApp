#!/usr/bin/env python3
"""Generate secrets and write them to .env in the project root."""
import base64
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

def gen_key_b64():
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")

def main():
    comment_key = gen_key_b64()
    export_key = gen_key_b64()

    content = (
        f"# Generated secrets\n"
        f"COMMENT_KEY_B64={comment_key}\n"
        f"EXPORT_HMAC_KEY_B64={export_key}\n"
    )

    if ENV_FILE.exists():
        print(f"{ENV_FILE} already exists, skipping overwrite.")
    else:
        ENV_FILE.write_text(content)
        print(f"Created {ENV_FILE} with generated base64 keys.")

if __name__ == "__main__":
    main()