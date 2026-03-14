import sqlite3
import datetime
import uuid

DB_NAME = 'pqc_secure.db'

def send_update_broadcast():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    msg_id = "msg_" + str(uuid.uuid4()).split('-')[0]
    sender_id = "a1" # Administrator ID from seeding
    receiver_id = "group"
    content = "🚀 **HPQC SYSTEM UPDATE** 🚀\n\nA new premium version of the application (**HPQC SECURE**) is now available! \n\n✨ **What's New:**\n- All-new Premium UI with High-Tech Aesthetics\n- Enhanced PQC Tunneling Status\n- Improved Terminal Integration\n- New 'HPQC SECURE' Branding & Icon\n\nPlease update your application to the latest version to ensure continuous secure access to all hubs."
    msg_type = "text"
    timestamp = datetime.datetime.now().isoformat()
    
    try:
        c.execute('''
            INSERT INTO "messages" (id, sender_id, receiver_id, group_id, content, type, timestamp, is_deleted, is_edited, seen_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, '[]')
        ''', (msg_id, sender_id, receiver_id, 'group', content, msg_type, timestamp))
        conn.commit()
        print(f"Update message sent successfully. ID: {msg_id}")
    except Exception as e:
        print(f"Error sending message: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    send_update_broadcast()
