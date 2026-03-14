from flask import Flask, request, jsonify
from flask_cors import CORS
import datetime
import uuid
import sqlite3
import kyber_kem
import kdf
import aead
import ecdh
import random
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)

SECRET_KEY = "hpqc_secure_jwt_secret" # In production, this should be in an env var

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

import traceback
from werkzeug.exceptions import HTTPException

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    return jsonify(error=str(e), traceback=traceback.format_exc()), 500


DB_NAME = 'pqc_secure.db'
signup_otps = {}  # In-memory mapping of email -> OTP for verification

# ==========================================
# 📧 EMAIL SMTP CONFIGURATION 
# ==========================================
# Replace these with your actual Gmail or App Password:
# E.g., Use a Gmail "App Password" (must have 2FA enabled on Google)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "quantumdevs3@gmail.com"
SMTP_PASSWORD = "hmix iugy audi bcgg"
# ==========================================

from db import get_db

import time
import random

def init_db():
    print("[init_db] Running FINAL RELIABILITY initialization...")
    
    # Consistently use plural 'users' for production
    tables = [
        ("users", "(id VARCHAR(255) PRIMARY KEY, email VARCHAR(255) UNIQUE, password TEXT, role TEXT, name TEXT, approved INTEGER, last_active TEXT, profile_pic TEXT, created_at TEXT)"),
        ("locks", "(id VARCHAR(255) PRIMARY KEY, name TEXT, status TEXT, type TEXT, approved INTEGER, token TEXT, last_unlocked_by TEXT, last_unlocked_at TEXT)"),
        ("permissions", "(user_id VARCHAR(255), lock_id VARCHAR(255), UNIQUE(user_id, lock_id))"),
        ("audit_logs", "(id VARCHAR(255) PRIMARY KEY, user_id TEXT, user_name TEXT, lock_id TEXT, lock_name TEXT, action TEXT, result TEXT, message TEXT, timestamp TEXT)"),
        ("messages", "(id VARCHAR(255) PRIMARY KEY, sender_id TEXT, receiver_id TEXT, group_id TEXT, content TEXT, type TEXT, timestamp TEXT, is_deleted INTEGER DEFAULT 0, is_edited INTEGER DEFAULT 0, seen_by TEXT DEFAULT '[]')")
    ]
    
    for table_name, schema in tables:
        conn = get_db()
        c = conn.cursor()
        try:
            # Using double quotes for table names is the standard way to avoid Postgres keyword errors
            c.execute(f'CREATE TABLE IF NOT EXISTS "{table_name}" {schema}')
            conn.commit()
            print(f"[init_db] Table created/verified: {table_name}")
        except Exception as e:
            print(f"[init_db] Table {table_name} warning: {e}")
            conn.rollback()
        finally:
            conn.close()

    # Create indices
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON "users" (email)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON "audit_logs" (user_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_lock_id ON "audit_logs" (lock_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON "messages" (receiver_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_permissions_user_id ON "permissions" (user_id)')
        conn.commit()
        print("[init_db] Indices verified.")
    except Exception as e:
        print(f"[init_db] Indices update error: {e}")
    finally:
        conn.close()

    # Seed Default Data (Quoted Names)
    conn = get_db()
    c = conn.cursor()
    try:
        # Seed 'users' table with hashed passwords
        admin_pass = generate_password_hash('admin')
        user_pass = generate_password_hash('password')
        now = datetime.datetime.now().isoformat()

        c.execute('SELECT * FROM "users" WHERE email=?', ('admin@example.com',))
        if not c.fetchone():
            c.execute('INSERT INTO "users" (id, email, password, role, name, approved, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                      ('a1', 'admin@example.com', admin_pass, 'Admin', 'Administrator', 1, now))

        c.execute('SELECT * FROM "users" WHERE email=?', ('user@example.com',))
        if not c.fetchone():
            c.execute('INSERT INTO "users" (id, email, password, role, name, approved, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                      ('u1', 'user@example.com', user_pass, 'User', 'Employee', 1, now))

        # Seed locks
        c.execute('SELECT * FROM "locks" WHERE id=?', ('lock1',))
        if not c.fetchone():
            c.execute('INSERT INTO "locks" (id, name, status, type, approved, token) VALUES (?, ?, ?, ?, ?, ?)',
                      ('lock1', 'Main Entrance', 'Locked', 'HPQC Hub', 1, 'secret1'))

        conn.commit()
        print("[init_db] Seeding completed.")
    except Exception as e:
        print(f"[init_db] Seeding error: {e}")
        conn.rollback()
    finally:
        conn.close()

init_db()

def get_user_from_token(token):
    if not token: return None
    if token.startswith("token_lock_"): return None
    
    user_id = None
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        # Fallback for old sessions to not abruptly break current users during the update
        if token.startswith("token_"):
            user_id = token.replace("token_", "")
        else:
            return None

    if not user_id:
        return None

    conn = get_db()
    user = conn.execute('SELECT * FROM "users" WHERE id=?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    device_id = data.get('device_id')
    
    conn = get_db()
    
    if device_id:
        lock = conn.execute('SELECT * FROM "locks" WHERE id=?', (device_id,)).fetchone()
        conn.close()
        if lock and lock['approved'] == 1 and lock['token'] == password:
            return jsonify({"token": f"token_lock_{device_id}", "role": "Lock", "id": device_id})
        return jsonify({"error": "Invalid lock credentials or not approved"}), 401

    user = conn.execute('SELECT * FROM "users" WHERE email=?', (email,)).fetchone()
    conn.close()
    
    # Verify hashed password
    if user and check_password_hash(user['password'], password):
        if user['role'] != 'Admin' and dict(user).get('approved', 1) == 0:
            return jsonify({"error": "Account pending Admin approval."}), 403
            
        token = jwt.encode({
            "user_id": user['id'],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24) # 24 hour expiry
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "token": token, 
            "role": user['role'], 
            "id": user['id'], 
            "name": user['name']
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/register-user', methods=['POST'])
def register_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    role = data.get('role', 'User')
    
    conn = get_db()
    existing = conn.execute('SELECT * FROM "users" WHERE email=?', (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Email already exists"}), 400
        
    user_id = "u_" + str(uuid.uuid4()).split('-')[0]
    hashed_pass = generate_password_hash(password)
    now = datetime.datetime.now().isoformat()
    conn.execute('INSERT INTO "users" (id, email, password, role, name, approved, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (user_id, email, hashed_pass, role, name, 1, now)) # Direct API registration currently auto-approves
    conn.commit()
    conn.close()
    return jsonify({"message": "User registered successfully", "id": user_id})

@app.route('/request-signup', methods=['POST'])
def request_signup():
    data = request.json
    email = data.get('email')
    
    conn = get_db()
    existing = conn.execute('SELECT * FROM "users" WHERE email=?', (email,)).fetchone()
    conn.close()
    
    if existing:
        return jsonify({"error": "Email already exists"}), 400
        
    otp = str(random.randint(100000, 999999))
    signup_otps[email] = otp
    
    # Actually send the email using SMTP
    try:
        msg = EmailMessage()
        msg['Subject'] = 'HPQC Verification Code'
        msg['From'] = SMTP_EMAIL
        msg['To'] = email
        msg.set_content(f"""\
Hello,

Your HPQC verification code is: {otp}

Enter this 6-digit code on your device to create your user account.
This code is valid securely via our PQC interface.

Thank you,
HPQC Security System
""")

        if "your.email" in SMTP_EMAIL:
            print(f"\n[WARNING] Real email not sent to {email}. You must change the 'SMTP_EMAIL' and 'SMTP_PASSWORD' in app.py first!\n")
            return jsonify({"message": "App needs SMTP set up. (Check Terminal for details)"})
        
        # Connect to the remote server and send
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure the connection
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
            
        print(f"✅ Real Email successfully sent to: {email}")
        return jsonify({"message": f"OTP successfully sent to {email}"})
        
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return jsonify({"error": "Failed to send OTP email. Contact system administrator."}), 500

@app.route('/verify-signup', methods=['POST'])
def verify_signup():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    password = data.get('password')
    name = data.get('name')
    
    if email not in signup_otps or signup_otps[email] != otp:
        return jsonify({"error": "Invalid or expired OTP code"}), 400
        
    signup_otps.pop(email, None)
    
    user_id = "u_" + str(uuid.uuid4()).split('-')[0]
    hashed_pass = generate_password_hash(password)
    now = datetime.datetime.now().isoformat()
    conn = get_db()
    conn.execute('INSERT INTO "users" (id, email, password, role, name, approved, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (user_id, email, hashed_pass, "User", name, 0, now)) # Set to 0 = Needs Admin Approval
    conn.commit()
    conn.close()
    return jsonify({"message": "Email verified! Account created and is now awaiting Admin approval."})

@app.route('/pending-users', methods=['GET'])
def get_pending_users():
    token = request.headers.get('Authorization')
    admin = get_user_from_token(token)
    if not admin or admin['role'] != 'Admin':
        return jsonify({"error": "Unauthorized"}), 401
        
    conn = get_db()
    users = conn.execute('SELECT id, email, name, role FROM "users" WHERE approved=0').fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/approve-user/<user_id>', methods=['POST'])
def approve_user(user_id):
    token = request.headers.get('Authorization')
    admin = get_user_from_token(token)
    if not admin or admin['role'] != 'Admin':
        return jsonify({"error": "Unauthorized"}), 401
        
    conn = get_db()
    conn.execute('UPDATE "users" SET approved=1 WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "User approved successfully"})

@app.route('/decline-user/<user_id>', methods=['POST'])
def decline_user(user_id):
    token = request.headers.get('Authorization')
    admin = get_user_from_token(token)
    if not admin or admin['role'] != 'Admin':
        return jsonify({"error": "Unauthorized"}), 401
        
    conn = get_db()
    conn.execute('DELETE FROM "users" WHERE id=? AND approved=0', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "User signup request declined and deleted."})

@app.route('/register-lock', methods=['POST'])
def register_lock():
    data = request.json
    device_id = data.get('device_id')
    name = data.get('name', f"Lock {device_id}")
    token = data.get('token')
    lock_type = data.get('type', 'HPQC Hub')
    
    conn = get_db()
    existing = conn.execute('SELECT * FROM "locks" WHERE id=?', (device_id,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Lock ID already exists"}), 400
        
    conn.execute('INSERT INTO "locks" (id, name, status, type, approved, token) VALUES (?, ?, ?, ?, ?, ?)',
                 (device_id, name, "Locked", lock_type, 0, token)) # 0 = not approved yet
    conn.commit()
    conn.close()
    return jsonify({"message": "Lock registered. Waiting for Admin approval."})

@app.route('/approve-lock/<lock_id>', methods=['POST'])
def approve_lock(lock_id):
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user or user['role'] != 'Admin':
        return jsonify({"error": "Unauthorized"}), 401
        
    conn = get_db()
    conn.execute('UPDATE "locks" SET approved=1 WHERE id=?', (lock_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Lock approved successfully"})

@app.route('/assign-permission', methods=['POST'])
def assign_permission():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user or user['role'] != 'Admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    user_id = data.get('user_id')
    lock_id = data.get('lock_id')
    
    conn = get_db()
    try:
        conn.execute('INSERT OR IGNORE INTO "permissions" (user_id, lock_id) VALUES (?, ?)', (user_id, lock_id))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 400
    conn.close()
    return jsonify({"message": "Permission granted"})

@app.route('/change-password', methods=['POST'])
def change_password():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    old_pass = data.get('oldPassword')
    new_pass = data.get('newPassword')
    
    if not check_password_hash(user['password'], old_pass):
        return jsonify({"error": "Incorrect current password"}), 400
        
    conn = get_db()
    hashed_new = generate_password_hash(new_pass)
    conn.execute('UPDATE "users" SET password=? WHERE id=?', (hashed_new, user['id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Password updated successfully"})

@app.route('/locks', methods=['GET'])
def get_locks():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    try:
        if user['role'] == 'Admin':
            locks = conn.execute('SELECT * FROM "locks"').fetchall()
        else:
            # Check permissions
            locks = conn.execute('''
                SELECT l.* FROM "locks" l 
                JOIN "permissions" p ON l.id = p.lock_id 
                WHERE p.user_id=? AND l.approved=1
            ''', (user['id'],)).fetchall()
        
        return jsonify([dict(l) for l in locks])
    finally:
        conn.close()

@app.route('/users', methods=['GET'])
def get_users():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user or user['role'] != 'Admin':
        return jsonify({"error": "Unauthorized"}), 401
        
    conn = get_db()
    users = conn.execute('SELECT id, email, role, name, \'Active\' as status FROM "users"').fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

def log_audit(conn, user_id, user_name, lock_id, lock_name, action, result, message):
    conn.execute("""
        INSERT INTO "audit_logs" (id, user_id, user_name, lock_id, lock_name, action, result, message, timestamp) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (str(uuid.uuid4()), user_id, user_name, lock_id, lock_name, action, result, message, datetime.datetime.now().isoformat()))

@app.route('/unlock', methods=['POST'])
def unlock():
    data = request.json
    token = request.headers.get('Authorization')
    lock_id = data.get('lock_id')
    verification = data.get('verification')
    
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    if user['role'] != 'Admin' and user['password'] != verification:
        return jsonify({"error": "Invalid password verification"}), 401
    
    conn = get_db()
    lock = conn.execute('SELECT * FROM "locks" WHERE id=?', (lock_id,)).fetchone()
    
    if not lock:
        conn.close()
        return jsonify({"error": "Lock not found"}), 404

    # Permission Check
    if user['role'] != 'Admin':
        perm = conn.execute('SELECT * FROM "permissions" WHERE user_id=? AND lock_id=?', (user['id'], lock_id)).fetchone()
        if not perm:
            log_audit(conn, user['id'], user['name'], lock_id, lock['name'], "Unlock Attempt", "Denied", "Permission Denied")
            conn.commit()
            conn.close()
            return jsonify({"error": "Permission denied"}), 403

    pqc_details = ""
    payloads = {}
    # ----------------------------------------------------
    # Hybrid Cryptography: ECDH + CRYSTALS-Kyber (ML-KEM-512)
    # ----------------------------------------------------
    try:
        import base64
        
        # 1. GENERATE KEYPAIRS (Simulating Sender/Receiver locally on backend)
        try:
            kyber_pub, kyber_sec = kyber_kem.generate_keypair()
            ecdh_pub_rec, ecdh_sec_rec = ecdh.generate_keypair()
            ecdh_pub_send, ecdh_sec_send = ecdh.generate_keypair()
        except Exception as e:
            raise Exception(f"Key generation failed: {str(e)}")
            
        # 2. ENCAPSULATION & ECDH (Sender side)
        try:
            ciphertext, kyber_shared_sender = kyber_kem.encapsulate(kyber_pub)
            ecdh_shared_sender = ecdh.generate_shared_secret(ecdh_sec_send, ecdh_pub_rec)
        except Exception as e:
            raise Exception(f"Encapsulation or ECDH sender exchange failed: {str(e)}")
            
        # 3. DECAPSULATION & ECDH (Receiver side)
        try:
            kyber_shared_receiver = kyber_kem.decapsulate(kyber_sec, ciphertext)
            ecdh_shared_receiver = ecdh.generate_shared_secret(ecdh_sec_rec, ecdh_pub_send)
        except Exception as e:
            raise Exception(f"Decapsulation or ECDH receiver exchange failed: {str(e)}")

        # Verification & Security check
        if kyber_shared_sender != kyber_shared_receiver or ecdh_shared_sender != ecdh_shared_receiver:
            raise Exception("Hybrid Key Exchange Failed: Shared secrets do not match!")
            
        # 4. HYBRID KEY DERIVATION (FinalKey = SHA3(ECDH_secret || Kyber_secret))
        sender_aes_key = kdf.derive_key(ecdh_shared_sender, kyber_shared_sender)
        receiver_aes_key = kdf.derive_key(ecdh_shared_receiver, kyber_shared_receiver)
        
        # 5. AUTHENTICATED ENCRYPTION (AES-GCM)
        try:
            encrypted_payload = aead.encrypt(b"SIGNAL_UNLOCK_AUTHENTICATED", sender_aes_key)
            decrypted_command = aead.decrypt(encrypted_payload, receiver_aes_key)
        except Exception as e:
            raise Exception(f"Invalid ciphertext or decryption failed: {str(e)}")
            
        if decrypted_command != b"SIGNAL_UNLOCK_AUTHENTICATED":
            raise Exception("Final command verification failed or tampered!")
            
        pqc_details = f"Secured via Hybrid ML-KEM-512 + ECDH, SHA3-256 KDF, AES-GCM"
        
        # Base64 serialization for API response (no raw bytes serialized)
        payloads = {
            "kyber_public_key": base64.b64encode(kyber_pub).decode('utf-8'),
            "kyber_ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "ecdh_public_key": base64.b64encode(ecdh_pub_rec).decode('utf-8'),
            "aes_gcm_payload": encrypted_payload  # Already B64 encoded dictionary via aead.encrypt
        }
        
    except Exception as e:
        log_audit(conn, user['id'], user['name'], lock_id, lock['name'], "Unlock Attempt", "Failed", f"Crypto Error: {str(e)}")
        conn.commit()
        conn.close()
        return jsonify({"error": str(e)}), 500

    # Ensure symmetric keys and shared secrets are never logged
    try:
        del kyber_shared_sender, kyber_shared_receiver, ecdh_shared_sender, ecdh_shared_receiver
        del sender_aes_key, receiver_aes_key
        del kyber_sec, ecdh_sec_rec, ecdh_sec_send
    except Exception:
        pass

    # Perform Unlock
    conn.execute('UPDATE "locks" SET status=\'Unlocked\', last_unlocked_by=?, last_unlocked_at=? WHERE id=?', 
                 (user['name'], datetime.datetime.now().isoformat(), lock_id))
    
    log_audit(conn, user['id'], user['name'], lock_id, lock['name'], "Unlock", "Success", f"Remote Unlock. {pqc_details}")
    conn.commit()
    conn.close()
    
    return jsonify({
        "message": "Unlock successful", 
        "status": "Unlocked",
        "pqc": "Hybrid ML-KEM-512 + ECDH Verified",
        "handshake_payloads": payloads
    })

@app.route('/lock-status', methods=['GET'])
def get_lock_status():
    token = request.headers.get('Authorization')
    if not token or "token_lock_" not in token:
        return jsonify({"error": "Unauthorized lock"}), 401
    
    lock_id = token.replace("token_lock_", "")
    conn = get_db()
    lock = conn.execute('SELECT * FROM "locks" WHERE id=?', (lock_id,)).fetchone()
    conn.close()
    
    if lock:
        return jsonify(dict(lock))
    return jsonify({"error": "Lock not found"}), 404

@app.route('/relock', methods=['POST'])
def relock():
    token = request.headers.get('Authorization')
    data = request.json or {}
    
    if token and "token_lock_" in token:
        lock_id = token.replace("token_lock_", "")
        user_name = "Device Itself"
        user_id = "Device"
    else:
        user = get_user_from_token(token)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        lock_id = data.get('lock_id')
        user_name = user['name']
        user_id = user['id']
        
        if user['role'] != 'Admin':
            conn = get_db()
            perm = conn.execute('SELECT * FROM "permissions" WHERE user_id=? AND lock_id=?', (user_id, lock_id)).fetchone()
            if not perm:
                conn.close()
                return jsonify({"error": "Permission denied"}), 403
            conn.close()
            
    if not lock_id:
        return jsonify({"error": "Missing lock ID"}), 400

    conn = get_db()
    lock = conn.execute('SELECT * FROM "locks" WHERE id=?', (lock_id,)).fetchone()
    if lock:
        conn.execute('UPDATE "locks" SET status=\'Locked\', last_unlocked_by=NULL WHERE id=?', (lock_id,))
        log_audit(conn, user_id, user_name, lock_id, lock['name'], "Relock", "Success", "Device Secured Remotely")
        conn.commit()
        conn.close()
        return jsonify({"status": "Locked"})
    conn.close()
    return jsonify({"error": "Lock not found"}), 404

@app.route('/logs', methods=['GET'])
def get_logs():
    conn = get_db()
    try:
        logs = conn.execute('SELECT * FROM "audit_logs" ORDER BY timestamp DESC LIMIT 50').fetchall()
        return jsonify([dict(l) for l in logs])
    finally:
        conn.close()

@app.route('/my-activity', methods=['GET'])
def get_my_activity():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    try:
        logs = conn.execute('SELECT * FROM "audit_logs" WHERE user_id=? ORDER BY timestamp DESC LIMIT 10', (user['id'],)).fetchall()
        return jsonify([dict(l) for l in logs])
    finally:
        conn.close()

@app.route('/my-stats', methods=['GET'])
def get_my_stats():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    # Total assigned locks
    locks_count = conn.execute('SELECT COUNT(*) FROM "permissions" WHERE user_id=?', (user['id'],)).fetchone()[0]
    
    # Total lifetime personal unlocks
    unlocks_count = conn.execute('SELECT COUNT(*) FROM "audit_logs" WHERE user_id=? AND action=\'Unlock\' AND result=\'Success\'', (user['id'],)).fetchone()[0]
    
    # Last login based on audit
    last_login_row = conn.execute('SELECT timestamp FROM "audit_logs" WHERE user_id=? ORDER BY timestamp DESC LIMIT 1', (user['id'],)).fetchone()
    last_auth = last_login_row['timestamp'] if last_login_row else "Never"
    
    conn.close()
    return jsonify({
        "assigned_locks": locks_count,
        "lifetime_unlocks": unlocks_count,
        "last_auth": last_auth
    })

@app.route('/system-health', methods=['GET'])
def system_health():
    # Simulated connection strings specifically for the user dashboard UI
    return jsonify({
        "connection": "Secure HTTPS",
        "encryption": "CRYSTALS-Kyber (ML-KEM-512)",
        "handshake": "QKD Simulated",
        "latency": f"{random.randint(12, 45)}ms"
    })

@app.route('/chat/messages', methods=['GET'])
def get_messages():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    receiver_id = request.args.get('receiver_id', 'group')
    conn = get_db()
    try:
        if receiver_id == 'group':
            msgs = conn.execute('''
                SELECT m.*, u.name as sender_name 
                FROM "messages" m 
                JOIN "users" u ON m.sender_id = u.id 
                WHERE m.receiver_id = 'group' 
                ORDER BY m.timestamp ASC
            ''').fetchall()
        else:
            msgs = conn.execute('''
                SELECT m.*, u.name as sender_name 
                FROM "messages" m 
                JOIN "users" u ON m.sender_id = u.id 
                WHERE (m.sender_id = ? AND m.receiver_id = ?) 
                   OR (m.sender_id = ? AND m.receiver_id = ?)
                ORDER BY m.timestamp ASC
            ''', (user['id'], receiver_id, receiver_id, user['id'])).fetchall()
            
        # Get total expected viewers for group chats (excluding sender)
        total_users_count = conn.execute('SELECT COUNT(*) FROM "users" WHERE approved=1').fetchone()[0]
    finally:
        conn.close()
    
    import json
    formatted_msgs = []
    for m in msgs:
        d = dict(m)
        try:
            seen_list = json.loads(d.get('seen_by', '[]') or '[]')
        except:
            seen_list = []
        d['seen_by'] = seen_list  # type: ignore
        d['is_deleted'] = bool(d.get('is_deleted', 0))  # type: ignore
        d['is_edited'] = bool(d.get('is_edited', 0))  # type: ignore
        d['total_group_users'] = total_users_count - 1 # type: ignore
        
        # Admin can view deleted messages for recovery
        if d['is_deleted'] and user['role'] != 'Admin':
            d['content'] = 'This message was deleted'
            d['type'] = 'deleted'
            
        formatted_msgs.append(d)
        
    return jsonify(formatted_msgs)

@app.route('/chat/messages', methods=['POST'])
def send_message():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    receiver_id = data.get('receiver_id', 'group')
    content = data.get('content')
    msg_type = data.get('type', 'text') # text, media, poll
    
    msg_id = "msg_" + str(uuid.uuid4()).split('-')[0]
    conn = get_db()
    conn.execute('''
        INSERT INTO "messages" (id, sender_id, receiver_id, group_id, content, type, timestamp, is_deleted, is_edited, seen_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, '[]')
    ''', (msg_id, user['id'], receiver_id, 'group' if receiver_id == 'group' else None, content, msg_type, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"message": "Sent", "id": msg_id})

@app.route('/chat/messages/<msg_id>', methods=['PATCH'])
def edit_message(msg_id):
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    new_content = data.get('content')
    
    conn = get_db()
    msg = conn.execute('SELECT * FROM "messages" WHERE id=?', (msg_id,)).fetchone()
    if not msg:
        conn.close()
        return jsonify({"error": "Message not found"}), 404
        
    if msg['sender_id'] != user['id']:
        conn.close()
        return jsonify({"error": "Not authorized to edit this message"}), 403
        
    # Check 10 mins window
    time_diff = datetime.datetime.now() - datetime.datetime.fromisoformat(msg['timestamp'])
    if time_diff.total_seconds() > 600:
        conn.close()
        return jsonify({"error": "Edit window (10 mins) has expired"}), 400
        
    conn.execute('UPDATE "messages" SET content=?, is_edited=1 WHERE id=?', (new_content, msg_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Edited"})

@app.route('/chat/messages/<msg_id>', methods=['DELETE'])
def delete_message(msg_id):
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    msg = conn.execute('SELECT * FROM "messages" WHERE id=?', (msg_id,)).fetchone()
    if not msg:
        conn.close()
        return jsonify({"error": "Message not found"}), 404
        
    if msg['sender_id'] != user['id'] and user['role'] != 'Admin':
        conn.close()
        return jsonify({"error": "Not authorized to delete"}), 403
        
    conn.execute('UPDATE "messages" SET is_deleted=1 WHERE id=?', (msg_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"})

@app.route('/chat/messages/<msg_id>/recover', methods=['POST'])
def recover_message(msg_id):
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user or user['role'] != 'Admin': 
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    conn.execute('UPDATE "messages" SET is_deleted=0 WHERE id=?', (msg_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Message recovered"})

@app.route('/chat/read', methods=['POST'])
def mark_read():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    room_id = data.get('room_id', 'group')
    
    conn = get_db()
    if room_id == 'group':
        msgs = conn.execute('SELECT id, seen_by FROM "messages" WHERE receiver_id=\'group\' AND sender_id != ?', (user['id'],)).fetchall()
    else:
        # DMs
        msgs = conn.execute('SELECT id, seen_by FROM "messages" WHERE receiver_id=? AND sender_id=?', (user['id'], room_id)).fetchall()
        
    import json
    for m in msgs:
        try:
            seen_list = json.loads(m['seen_by'] or '[]')
        except:
            seen_list = []
            
        if user['id'] not in seen_list:
            seen_list.append(user['id'])
            conn.execute('UPDATE "messages" SET seen_by=? WHERE id=?', (json.dumps(seen_list), m['id']))
            
    conn.commit()
    conn.close()
    return jsonify({"message": "Marked seen"})

@app.route('/chat/users', methods=['GET'])
def chat_users():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    
    # Simple check for who we have talked with before
    conversations = conn.execute('SELECT DISTINCT sender_id, receiver_id FROM "messages" WHERE sender_id = ? OR receiver_id = ?', (user['id'], user['id'])).fetchall()
    talked_set = set()
    for c in conversations:
        talked_set.add(c['sender_id'])
        talked_set.add(c['receiver_id'])
        
    users = conn.execute('SELECT id, name, email, role, last_active, profile_pic FROM "users" WHERE approved=1 AND id != ?', (user['id'],)).fetchall()
    conn.close()
    
    result = []
    for u in users:
        d = dict(u)
        d['has_conversed'] = d['id'] in talked_set
        result.append(d)
        
    return jsonify(result)

@app.route('/chat/unread', methods=['GET'])
def chat_unread():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"unread": 0}), 401
    
    conn = get_db()
    try:
        # Fetch all messages where user is not sender, but could be receiver (group or direct)
        msgs = conn.execute('SELECT id, seen_by, receiver_id FROM "messages" WHERE sender_id != ? AND (receiver_id = \'group\' OR receiver_id = ?)', (user['id'], user['id'])).fetchall()
        
        count = 0
        import json
        for m in msgs:
            try:
                seen_list = json.loads(m['seen_by'] or '[]')
                if user['id'] not in seen_list:
                    count += 1 # type: ignore
            except:
                pass
                
        return jsonify({"unread": count})
    finally:
        conn.close()

@app.route('/ping', methods=['POST'])
def ping():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if user:
        conn = get_db()
        conn.execute("UPDATE users SET last_active=? WHERE id=?", (datetime.datetime.now().isoformat(), user['id']))
        conn.commit()
        conn.close()
    return jsonify({"status": "ok"})

@app.route('/profile-pic', methods=['POST'])
def update_profile_pic():
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    pic = data.get('profile_pic')
    
    conn = get_db()
    conn.execute('UPDATE "users" SET profile_pic=? WHERE id=?', (pic, user['id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Profile picture updated"})
@app.route('/stats', methods=['GET'])
def get_stats():
    conn = get_db()
    try:
        users_count = conn.execute('SELECT COUNT(*) FROM "users"').fetchone()[0]
        locks_count = conn.execute('SELECT COUNT(*) FROM "locks"').fetchone()[0]
        
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        unlocks_today = conn.execute('SELECT COUNT(*) FROM "audit_logs" WHERE result=\'Success\' AND action=\'Unlock\' AND timestamp LIKE ?', (today + '%',)).fetchone()[0]
        
        return jsonify({
            "users": users_count,
            "locks": locks_count,
            "unlocks_today": unlocks_today
        })
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
