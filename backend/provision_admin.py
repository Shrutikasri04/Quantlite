"""Bootstrap or dual-control provision a QuantLite founder/co-founder account."""
import getpass
import json
import os
import secrets
import sys
import urllib.parse

from cryptography.fernet import Fernet

from backend.main import (
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    get_db,
    iso,
    new_id,
    password_hash,
    token_hash,
    verify_password,
    verify_totp,
    write_audit,
)


def authenticate_approver(db, target_email: str):
    print("An existing founder/co-founder must approve this privileged change.")
    approver_email = input("Approving founder email: ").strip().lower()
    if not approver_email or approver_email == target_email:
        print("Refused: approval must come from a different founder account.")
        return None
    user = db.execute("SELECT * FROM users WHERE email=? AND role='ADMIN'", (approver_email,)).fetchone()
    if not user or not user["email_verified"] or user["account_status"] != "ACTIVE" or not user["mfa_enabled"]:
        print("Refused: approver must be an active, verified, MFA-protected founder.")
        return None
    password = getpass.getpass("Approver password: ")
    if not verify_password(password, user["password_hash"]):
        print("Refused: approver authentication failed.")
        return None
    code = getpass.getpass("Approver authenticator code: ").strip()
    try:
        secret = decrypt_mfa_secret(user["mfa_secret_enc"])
    except RuntimeError as error:
        print(f"Refused: {error}")
        return None
    if not verify_totp(secret, code):
        print("Refused: approver MFA check failed. Recovery codes cannot approve ownership changes.")
        return None
    return user


def main() -> int:
    if sys.argv[1:] == ["--generate-encryption-key"]:
        print(Fernet.generate_key().decode("ascii"))
        return 0
    if len(sys.argv) != 2:
        print("Usage: python -m backend.provision_admin founder@example.org")
        print("       python -m backend.provision_admin --generate-encryption-key")
        return 2
    target_email = sys.argv[1].strip().lower()
    if "@" not in target_email:
        print("Refused: provide a valid founder email address.")
        return 2
    try:
        # Fail before requesting credentials if the at-rest MFA key is missing or invalid.
        encrypt_mfa_secret("configuration-check")
    except RuntimeError as error:
        print(f"Refused: {error}")
        print("Generate a key with --generate-encryption-key and store it in the backend environment.")
        return 1

    full_name = input("Founder/co-founder full name: ").strip()
    if len(full_name) < 2:
        print("Refused: a full name is required.")
        return 1
    db = get_db()
    try:
        existing = db.execute("SELECT id,role FROM users WHERE email=?", (target_email,)).fetchone()
        if existing and existing["role"] != "ADMIN":
            print("Refused: a customer account cannot be elevated to founder privileges.")
            return 1
        founder_count = db.execute("SELECT COUNT(*) FROM users WHERE role='ADMIN'").fetchone()[0]
        approver = None
        if founder_count == 0:
            bootstrap_email = os.getenv("BOOTSTRAP_OWNER_EMAIL", "").strip().lower()
            if not bootstrap_email or target_email != bootstrap_email:
                print("Refused: first-owner bootstrap must match BOOTSTRAP_OWNER_EMAIL exactly.")
                return 1
            title = "Founder"
            print("First founder bootstrap selected. Keep the generated MFA key and recovery codes offline.")
        else:
            approver = authenticate_approver(db, target_email)
            if not approver:
                return 1
            current_profile = db.execute("SELECT owner_title FROM admin_profiles WHERE user_id=?", (existing["id"],)).fetchone() if existing else None
            default_title = current_profile["owner_title"] if current_profile else "Co-founder"
            answer = input(f"Owner title [F]ounder / [C]o-founder (default {default_title[0]}): ").strip().lower()
            title = "Founder" if answer == "f" else "Co-founder" if answer == "c" else default_title

        password = getpass.getpass("Founder password (12+ characters): ")
        if len(password) < 12:
            print("Refused: password must contain at least 12 characters.")
            return 1
        confirm = getpass.getpass("Confirm founder password: ")
        if password != confirm:
            print("Refused: passwords do not match.")
            return 1

        secret = __import__("base64").b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        secret_encrypted = encrypt_mfa_secret(secret)
        recovery_codes = [secrets.token_hex(16) for _ in range(10)]
        recovery_hashes = json.dumps([token_hash(code) for code in recovery_codes])
        founder_id = existing["id"] if existing else new_id("usr_")
        if existing:
            db.execute("UPDATE users SET password_hash=?,email_verified=1,account_status='ACTIVE',mfa_secret_enc=?,mfa_enabled=1,recovery_codes_json=? WHERE id=?", (password_hash(password), secret_encrypted, recovery_hashes, founder_id))
            db.execute("DELETE FROM sessions WHERE user_id=?", (founder_id,))
            action = "OWNER_MFA_AND_CREDENTIALS_REPROVISIONED"
        else:
            db.execute("INSERT INTO users(id,email,password_hash,role,email_verified,account_status,mfa_secret_enc,mfa_enabled,recovery_codes_json,created_at) VALUES(?,?,?,'ADMIN',1,'ACTIVE',?,1,?,?)", (founder_id, target_email, password_hash(password), secret_encrypted, recovery_hashes, iso()))
            action = "OWNER_ACCOUNT_PROVISIONED"
        db.execute("INSERT INTO admin_profiles(user_id,full_name,owner_title,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET full_name=excluded.full_name,owner_title=excluded.owner_title,updated_at=excluded.updated_at", (founder_id, full_name, title, iso()))
        write_audit(db, approver["id"] if approver else None, action, "founder_account", founder_id)
        db.commit()
        label = urllib.parse.quote(target_email, safe="")
        uri = f"otpauth://totp/QuantLite:{label}?secret={secret}&issuer=QuantLite&algorithm=SHA1&digits=6&period=30"
        print("\nFounder account provisioned. MFA is required for every new sign-in.")
        print("Add this secret to the founder's authenticator now; it is not retrievable from the database:")
        print(f"TOTP secret: {secret}")
        print(f"Authenticator URI: {uri}")
        print("\nSave these one-time recovery codes offline in the founder's approved secure vault:")
        print("\n".join(recovery_codes))
        print("\nRecovery codes are single-use and cannot approve founder account changes.")
        if approver:
            print(f"Approval was recorded for {target_email} by {approver['email']} in the audit chain.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
