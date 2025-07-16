# pearpeak_cli.py
# Sebuah aplikasi chat CLI P2P dengan E2EE menggunakan Supabase sebagai broker.
# Versi 2.2 - Fitur Room Global

import os
import pickle
import random
import string
import time
import threading
import hashlib
import base64
from datetime import datetime, timedelta, timezone

import bcrypt
import getpass4
from coolname import generate_slug
from supabase import create_client, Client
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidKey

# Konfigurasi Supabase
SUPABASE_URL = "https://tahwqtminymcmeiyzrwc.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRhaHdxdG1pbnltY21laXl6cndjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTI1NzQ1OTksImV4cCI6MjA2ODE1MDU5OX0.G_ZSyS78ZUiZNOMKcP6UAP4j1nVVqUrvpqGr0cFL3ng"

# Konstanta Aplikasi
PEARPEAK_DIR = os.path.join(os.path.expanduser("~"), ".pearpeak")
USER_FILE = os.path.join(PEARPEAK_DIR, "user.dat")
HEARTBEAT_INTERVAL = 60
ONLINE_THRESHOLD = timedelta(minutes=2)
ROOM_CODE_LENGTH = 4
GLOBAL_ROOMS = ["GLBL", "GLBB"]

class CryptoManager:
    @staticmethod
    def generate_deterministic_key(seed: str) -> bytes:
        hashed_seed = hashlib.sha256(seed.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(hashed_seed)
    @staticmethod
    def hash_password(p): return bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt())
    @staticmethod
    def verify_password(p, h): return bcrypt.checkpw(p.encode('utf-8'), h)
    @staticmethod
    def generate_rsa_keys(): pk = rsa.generate_private_key(public_exponent=65537, key_size=2048); return pk, pk.public_key()
    @staticmethod
    def generate_symmetric_key(): return Fernet.generate_key()
    @staticmethod
    def serialize_private_key(prv_k, enc_k): f = Fernet(enc_k); pem = prv_k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()); return f.encrypt(pem)
    @staticmethod
    def deserialize_private_key(ser_k, enc_k): f = Fernet(enc_k); pem = f.decrypt(ser_k); return serialization.load_pem_private_key(pem, password=None)
    @staticmethod
    def serialize_public_key(pub_k): pem = pub_k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo); return pem.decode('utf-8')
    @staticmethod
    def deserialize_public_key(pem_s): return serialization.load_pem_public_key(pem_s.encode('utf-8'))
    @staticmethod
    def encrypt_with_public_key(d, pub_k): return pub_k.encrypt(d, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    @staticmethod
    def decrypt_with_private_key(enc_d, prv_k): return prv_k.decrypt(enc_d, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    @staticmethod
    def encrypt_with_symmetric_key(d, k): return Fernet(k).encrypt(d.encode('utf-8')).decode('utf-8')
    @staticmethod
    def decrypt_with_symmetric_key(enc_d, k): return Fernet(k).decrypt(enc_d.encode('utf-8')).decode('utf-8')

class UserManager:
    def __init__(self): self.crypto = CryptoManager(); os.makedirs(PEARPEAK_DIR, exist_ok=True)
    def user_data_exists(self): return os.path.exists(USER_FILE)
    def create_user(self, password):
        username, hashed_password = generate_slug(2), self.crypto.hash_password(password)
        private_key, public_key = self.crypto.generate_rsa_keys(); encryption_key = Fernet.generate_key()
        encrypted_private_key = self.crypto.serialize_private_key(private_key, encryption_key)
        user_data = {'username': username, 'hashed_password': hashed_password, 'encrypted_private_key': encrypted_private_key, 'encryption_key': encryption_key}
        with open(USER_FILE, 'wb') as f: pickle.dump(user_data, f)
        print(f"Profil berhasil dibuat. Nama pengguna Anda: {username}"); return self.load_user(password)
    def load_user(self, password):
        if not self.user_data_exists(): return None
        with open(USER_FILE, 'rb') as f: user_data = pickle.load(f)
        if not self.crypto.verify_password(password, user_data['hashed_password']): raise ValueError("Password salah!")
        private_key = self.crypto.deserialize_private_key(user_data['encrypted_private_key'], user_data['encryption_key'])
        return {'username': user_data['username'], 'private_key': private_key, 'public_key': private_key.public_key()}

class SupabaseManager:
    def __init__(self, url, key): self.client = create_client(url, key)
    def publish_user(self, u, pk_str): self.client.table('users').upsert({'username': u, 'public_key': pk_str, 'last_seen': datetime.now(timezone.utc).isoformat()}).execute()
    def update_last_seen(self, u): self.client.table('users').update({'last_seen': datetime.now(timezone.utc).isoformat()}).eq('username', u).execute()
    def get_online_users(self): threshold = (datetime.now(timezone.utc) - ONLINE_THRESHOLD).isoformat(); return self.client.table('users').select('username').gt('last_seen', threshold).execute().data
    def get_public_key(self, u): res = self.client.table('users').select('public_key').eq('username', u).limit(1).single().execute(); return res.data.get('public_key') if res.data else None
    def send_invitation(self, s, r, ec): self.client.table('messages').insert({'sender_username': s, 'recipient_username': r, 'encrypted_content': pickle.dumps(ec).hex()}).execute(); return True
    def fetch_invitations(self, r):
        msgs = self.client.table('messages').select('*').eq('recipient_username', r).execute().data
        if msgs: self.client.table('messages').delete().in_('id', [m['id'] for m in msgs]).execute()
        for m in msgs: m['encrypted_content'] = pickle.loads(bytes.fromhex(m['encrypted_content']))
        return msgs
    def create_room(self, c, rc, ek): return self.client.table('rooms').insert({'created_by': c, 'room_code': rc, 'encrypted_session_keys': ek}).execute().data[0]
    def get_room_by_code(self, rc):
        try: return self.client.table('rooms').select('*').eq('room_code', rc).limit(1).single().execute().data
        except Exception: return None
    def send_room_message(self, rid, s, c): self.client.table('room_messages').insert({'room_id': rid, 'sender_username': s, 'encrypted_content': c}).execute()
    def fetch_room_messages(self, rid, sid=0): return self.client.table('room_messages').select('*').eq('room_id', rid).gt('id', sid).order('id').execute().data
    def send_global_room_message(self, rc, s, c): self.client.table('global_room_messages').insert({'room_code': rc, 'sender_username': s, 'encrypted_content': c}).execute()
    def fetch_global_room_messages(self, rc, sid=0): return self.client.table('global_room_messages').select('*').eq('room_code', rc).gt('id', sid).order('id').execute().data

class PearPeakCLI:
    def __init__(self):
        self.user_manager = UserManager(); self.crypto = CryptoManager(); self.supabase = SupabaseManager(SUPABASE_URL, SUPABASE_KEY)
        self.current_user = None; self.stop_threads = threading.Event()
    def _heartbeat(self):
        while not self.stop_threads.is_set():
            if self.current_user: self.supabase.update_last_seen(self.current_user['username'])
            self.stop_threads.wait(HEARTBEAT_INTERVAL)
    def startup(self):
        print("="*40); print(" Selamat Datang di PearPeak CLI v2.2"); print("="*40)
        if self.user_manager.user_data_exists():
            print("Profil ditemukan.");
            for _ in range(3):
                try: self.current_user = self.user_manager.load_user(getpass4.getpass("Password: ")); print(f"\nLogin sukses. Welcome, {self.current_user['username']}!"); return True
                except ValueError as e: print(f"Error: {e}")
            print("Terlalu banyak percobaan."); return False
        else:
            print("Profil tidak ditemukan."); password = getpass4.getpass("Buat password baru: ")
            if password != getpass4.getpass("Konfirmasi: "): print("Password tidak cocok."); return False
            self.current_user = self.user_manager.create_user(password); return True
    def list_users(self):
        print("\n--- Pengguna Online ---"); users = self.supabase.get_online_users()
        if not users: print("Tidak ada pengguna online.")
        else:
            for user in users: print(f"- {user['username']}{' (Anda)' if user['username'] == self.current_user['username'] else ''}")
    def create_room_flow(self):
        recipient = input("Undang username: ")
        if recipient == self.current_user['username']: print("Tidak bisa mengundang diri sendiri."); return
        pub_key_str = self.supabase.get_public_key(recipient)
        if not pub_key_str: print(f"Pengguna '{recipient}' tidak ditemukan."); return
        recipient_pk = self.crypto.deserialize_public_key(pub_key_str); creator_pk = self.current_user['public_key']; session_key = self.crypto.generate_symmetric_key()
        enc_key_creator = self.crypto.encrypt_with_public_key(session_key, creator_pk); enc_key_recipient = self.crypto.encrypt_with_public_key(session_key, recipient_pk)
        keys_payload = {self.current_user['username']: pickle.dumps(enc_key_creator).hex(), recipient: pickle.dumps(enc_key_recipient).hex()}
        room_code = ''.join(random.choices(string.ascii_uppercase, k=ROOM_CODE_LENGTH))
        if self.supabase.create_room(self.current_user['username'], room_code, keys_payload):
            inv_msg = f"Diundang ke room. Kode: {room_code}"; enc_inv = self.crypto.encrypt_with_public_key(inv_msg.encode(), recipient_pk)
            if self.supabase.send_invitation(self.current_user['username'], recipient, enc_inv): print(f"Undangan terkirim ke {recipient}. Kode: {room_code}")
    def check_mail_flow(self):
        print("\n--- Mailbox ---"); invitations = self.supabase.fetch_invitations(self.current_user['username'])
        if not invitations: print("Tidak ada pesan baru.")
        else:
            for inv in invitations:
                try: print(f"[{inv['created_at'][:16]}] Dari {inv['sender_username']}: {self.crypto.decrypt_with_private_key(inv['encrypted_content'], self.current_user['private_key']).decode()}")
                except: print(f"[{inv['created_at'][:16]}] Dari {inv['sender_username']}: [Pesan rusak]")
    def list_global_rooms_flow(self):
        print("\n--- Room Global Tersedia ---")
        for room in GLOBAL_ROOMS: print(f"- {room}")
    def join_room_flow(self):
        room_code = input("Masukkan kode room: ").upper()
        if room_code in GLOBAL_ROOMS:
            self.chat_session({'room_code': room_code, 'is_global': True})
        else:
            room_data = self.supabase.get_room_by_code(room_code)
            if not room_data: print("Room pribadi tidak ditemukan."); return
            if self.current_user['username'] not in room_data.get('encrypted_session_keys', {}): print("Anda tidak diundang."); return
            self.chat_session(room_data)
    def chat_session(self, room_data):
        is_global = room_data.get('is_global', False)
        room_code = room_data['room_code']
        print(f"\nBergabung ke room {room_code}. Ketik '/keluar' untuk kembali.")
        try:
            if is_global: session_key = self.crypto.generate_deterministic_key(room_code)
            else:
                enc_key_hex = room_data.get('encrypted_session_keys', {})[self.current_user['username']]
                session_key = self.crypto.decrypt_with_private_key(pickle.loads(bytes.fromhex(enc_key_hex)), self.current_user['private_key'])
        except Exception as e: print(f"Gagal mendapat kunci sesi: {e}"); return

        stop_listening = threading.Event(); last_message_id = 0
        def _listen():
            nonlocal last_message_id
            fetch_func = self.supabase.fetch_global_room_messages if is_global else self.supabase.fetch_room_messages
            fetch_id = room_code if is_global else room_data['id']
            while not stop_listening.is_set():
                try:
                    messages = fetch_func(fetch_id, last_message_id)
                    if messages:
                        print(f"\r{' ' * 80}\r", end="") # Hapus baris input saat ini
                        for msg in messages:
                            if msg['sender_username'] != self.current_user['username']:
                                decrypted = self.crypto.decrypt_with_symmetric_key(msg['encrypted_content'], session_key)
                                print(f"[{msg['sender_username']}]: {decrypted}")
                            last_message_id = msg['id']
                        print(f"[{self.current_user['username']}]> ", end="", flush=True) # Tulis ulang prompt
                except: pass
                time.sleep(2)
        
        listener_thread = threading.Thread(target=_listen, daemon=True); listener_thread.start()
        while True:
            try: message = input(f"[{self.current_user['username']}]> ")
            except EOFError: break
            if message.lower() == '/keluar': break
            encrypted_message = self.crypto.encrypt_with_symmetric_key(message, session_key)
            if is_global: self.supabase.send_global_room_message(room_code, self.current_user['username'], encrypted_message)
            else: self.supabase.send_room_message(room_data['id'], self.current_user['username'], encrypted_message)
        stop_listening.set(); listener_thread.join(0.5); print(f"\nMeninggalkan room {room_code}.")
    def run(self):
        if not self.startup(): return
        self.supabase.publish_user(self.current_user['username'], self.crypto.serialize_public_key(self.current_user['public_key']))
        heartbeat_thread = threading.Thread(target=self._heartbeat, daemon=True); heartbeat_thread.start()
        try:
            while True:
                print("\n--- Menu PearPeak ---")
                print("1) Lihat Pengguna Online\n2) Buat Room Pribadi\n3) Mail (Undangan)\n4) Gabung Room\n5) Lihat Room Global\n6) Keluar")
                choice = input("> ")
                if choice == '1': self.list_users()
                elif choice == '2': self.create_room_flow()
                elif choice == '3': self.check_mail_flow()
                elif choice == '4': self.join_room_flow()
                elif choice == '5': self.list_global_rooms_flow()
                elif choice == '6': print("Keluar..."); break
        except KeyboardInterrupt: print("\nKeluar.")
        finally: self.stop_threads.set(); heartbeat_thread.join(1); print("Selamat tinggal!")

if __name__ == "__main__":
    try: PearPeakCLI().run()
    except Exception as e: print(f"Error fatal: {e}")
