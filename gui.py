# pearpeak_gui.py
# Sebuah aplikasi chat GUI dengan E2EE menggunakan Supabase dan PyQt6.
# Versi 3.1 - Fitur Room Global & Perbaikan Bug

import os
import pickle
import random
import string
import sys
import time
import threading
import hashlib
import base64
from datetime import datetime, timedelta, timezone

# --- LANGKAH 1: Instalasi Dependensi ---
# pip install --upgrade supabase cryptography bcrypt coolname getpass4 PyQt6

import bcrypt
from coolname import generate_slug
from supabase import create_client, Client
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidKey

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QListWidget, QTextEdit, QStackedWidget,
    QMainWindow, QMessageBox, QInputDialog
)
from PyQt6.QtCore import QObject, QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont

# Konfigurasi Supabase
SUPABASE_URL = "https://tahwqtminymcmeiyzrwc.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRhaHdxdG1pbnltY21laXl6cndjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTI1NzQ1OTksImV4cCI6MjA2ODE1MDU5OX0.G_ZSyS78ZUiZNOMKcP6UAP4j1nVVqUrvpqGr0cFL3ng"

# Konstanta Aplikasi
PEARPEAK_DIR = os.path.join(os.path.expanduser("~"), ".pearpeak")
USER_FILE = os.path.join(PEARPEAK_DIR, "user.dat")
ONLINE_THRESHOLD = timedelta(minutes=2)
ROOM_CODE_LENGTH = 4
GLOBAL_ROOMS = ["GLBL", "GLBB"]

# ==============================================================================
# BAGIAN BACKEND (LOGIKA INTI)
# ==============================================================================

class CryptoManager:
    @staticmethod
    def generate_deterministic_key(seed: str) -> bytes:
        """Membuat kunci simetris yang sama setiap saat dari sebuah seed."""
        # Gunakan SHA-256 untuk membuat hash dari seed, lalu encode ke base64
        # Ini memastikan kunci selalu sama untuk seed yang sama (misal: "GLBL")
        hashed_seed = hashlib.sha256(seed.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(hashed_seed)
        
    @staticmethod
    def hash_password(p): return bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt())
    @staticmethod
    def verify_password(p, h): return bcrypt.checkpw(p.encode('utf-8'), h)
    @staticmethod
    def generate_rsa_keys():
        pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return pk, pk.public_key()
    @staticmethod
    def generate_symmetric_key(): return Fernet.generate_key()
    @staticmethod
    def serialize_private_key(prv_k, enc_k):
        f = Fernet(enc_k)
        pem = prv_k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return f.encrypt(pem)
    @staticmethod
    def deserialize_private_key(ser_k, enc_k):
        f = Fernet(enc_k)
        pem = f.decrypt(ser_k)
        return serialization.load_pem_private_key(pem, password=None)
    @staticmethod
    def serialize_public_key(pub_k):
        pem = pub_k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem.decode('utf-8')
    @staticmethod
    def deserialize_public_key(pem_s): return serialization.load_pem_public_key(pem_s.encode('utf-8'))
    @staticmethod
    def encrypt_with_public_key(d, pub_k):
        return pub_k.encrypt(d, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    @staticmethod
    def decrypt_with_private_key(enc_d, prv_k):
        return prv_k.decrypt(enc_d, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    @staticmethod
    def encrypt_with_symmetric_key(d, k): return Fernet(k).encrypt(d.encode('utf-8')).decode('utf-8')
    @staticmethod
    def decrypt_with_symmetric_key(enc_d, k): return Fernet(k).decrypt(enc_d.encode('utf-8')).decode('utf-8')

class UserManager:
    def __init__(self):
        self.crypto = CryptoManager()
        os.makedirs(PEARPEAK_DIR, exist_ok=True)
    def user_data_exists(self): return os.path.exists(USER_FILE)
    def create_user(self, password):
        username, hashed_password = generate_slug(2), self.crypto.hash_password(password)
        private_key, public_key = self.crypto.generate_rsa_keys()
        encryption_key = Fernet.generate_key()
        encrypted_private_key = self.crypto.serialize_private_key(private_key, encryption_key)
        user_data = {'username': username, 'hashed_password': hashed_password, 'encrypted_private_key': encrypted_private_key, 'encryption_key': encryption_key}
        with open(USER_FILE, 'wb') as f: pickle.dump(user_data, f)
        return self.load_user(password)
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
    def get_online_users(self):
        threshold = (datetime.now(timezone.utc) - ONLINE_THRESHOLD).isoformat()
        return self.client.table('users').select('username').gt('last_seen', threshold).execute().data
    def get_public_key(self, u):
        res = self.client.table('users').select('public_key').eq('username', u).limit(1).single().execute()
        return res.data.get('public_key') if res.data else None
    def send_invitation(self, s, r, ec):
        self.client.table('messages').insert({'sender_username': s, 'recipient_username': r, 'encrypted_content': pickle.dumps(ec).hex()}).execute()
    def fetch_invitations(self, r):
        msgs = self.client.table('messages').select('*').eq('recipient_username', r).execute().data
        if msgs: self.client.table('messages').delete().in_('id', [m['id'] for m in msgs]).execute()
        for m in msgs: m['encrypted_content'] = pickle.loads(bytes.fromhex(m['encrypted_content']))
        return msgs
    def create_room(self, c, rc, ek):
        return self.client.table('rooms').insert({'created_by': c, 'room_code': rc, 'encrypted_session_keys': ek}).execute().data[0]
    def get_room_by_code(self, rc):
        try: return self.client.table('rooms').select('*').eq('room_code', rc).limit(1).single().execute().data
        except Exception: return None
    def send_room_message(self, rid, s, c):
        self.client.table('room_messages').insert({'room_id': rid, 'sender_username': s, 'encrypted_content': c}).execute()
    def fetch_room_messages(self, rid, sid=0):
        return self.client.table('room_messages').select('*').eq('room_id', rid).gt('id', sid).order('id').execute().data
    def send_global_room_message(self, rc, s, c):
        self.client.table('global_room_messages').insert({'room_code': rc, 'sender_username': s, 'encrypted_content': c}).execute()
    def fetch_global_room_messages(self, rc, sid=0):
        return self.client.table('global_room_messages').select('*').eq('room_code', rc).gt('id', sid).order('id').execute().data

# ==============================================================================
# BAGIAN FRONTEND (GUI DENGAN PYQT6)
# ==============================================================================

class Worker(QObject):
    new_message = pyqtSignal(str, str)
    finished = pyqtSignal()

    def __init__(self, supabase_manager, room, session_key, current_username):
        super().__init__()
        self.supabase = supabase_manager
        self.room = room
        self.session_key = session_key
        self.current_username = current_username
        self.crypto = CryptoManager()
        self.is_running = True
        self.last_message_id = 0
        self.is_global = room.get('is_global', False)

    def run(self):
        fetch_func = self.supabase.fetch_global_room_messages if self.is_global else self.supabase.fetch_room_messages
        fetch_id = self.room['room_code'] if self.is_global else self.room['id']
        
        try:
            initial_messages = fetch_func(fetch_id)
            for msg in initial_messages:
                decrypted = self.crypto.decrypt_with_symmetric_key(msg['encrypted_content'], self.session_key)
                self.new_message.emit(msg['sender_username'], decrypted)
                self.last_message_id = msg['id']
        except Exception:
            pass
        
        while self.is_running:
            try:
                messages = fetch_func(fetch_id, self.last_message_id)
                for msg in messages:
                    decrypted = self.crypto.decrypt_with_symmetric_key(msg['encrypted_content'], self.session_key)
                    self.new_message.emit(msg['sender_username'], decrypted)
                    self.last_message_id = msg['id']
            except Exception:
                pass
            time.sleep(2)
        self.finished.emit()

    def stop(self):
        self.is_running = False

class LoginPage(QWidget):
    login_successful = pyqtSignal(object)
    def __init__(self, user_manager):
        super().__init__()
        self.user_manager = user_manager
        self.init_ui()
    def init_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(50, 50, 50, 50); layout.setSpacing(15); layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label = QLabel("PearPeak"); self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter); self.title_label.setObjectName("titleLabel")
        self.status_label = QLabel(""); self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter); self.status_label.setObjectName("statusLabel")
        self.password_input = QLineEdit(); self.password_input.setEchoMode(QLineEdit.EchoMode.Password); self.password_input.setPlaceholderText("Masukkan Password Anda"); self.password_input.returnPressed.connect(self.handle_login)
        self.login_button = QPushButton("Login / Buat Profil"); self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.title_label); layout.addWidget(self.status_label); layout.addWidget(self.password_input); layout.addWidget(self.login_button)
    def handle_login(self):
        password = self.password_input.text()
        if not password: self.status_label.setText("Password tidak boleh kosong."); return
        try:
            if self.user_manager.user_data_exists(): self.login_successful.emit(self.user_manager.load_user(password))
            else:
                confirm_password, ok = QInputDialog.getText(self, "Buat Profil Baru", "Profil tidak ditemukan. Konfirmasi password baru:", QLineEdit.EchoMode.Password)
                if ok and password == confirm_password: self.login_successful.emit(self.user_manager.create_user(password))
                elif ok: self.status_label.setText("Password konfirmasi tidak cocok.")
        except ValueError as e: self.status_label.setText(str(e))
        except Exception as e: self.status_label.setText(f"Error: {e}")

class MainPage(QWidget):
    join_room_request = pyqtSignal(str)
    def __init__(self, supabase_manager, crypto_manager):
        super().__init__()
        self.supabase = supabase_manager; self.crypto = crypto_manager; self.current_user = None
        self.init_ui()
    def set_user(self, user):
        self.current_user = user; self.welcome_label.setText(f"Selamat datang, {self.current_user['username']}"); self.refresh_all()
    def init_ui(self):
        main_layout = QHBoxLayout(self); main_layout.setSpacing(20); main_layout.setContentsMargins(20, 20, 20, 20)
        left_panel = QVBoxLayout(); mid_panel = QVBoxLayout(); right_panel = QVBoxLayout()
        self.welcome_label = QLabel("Selamat datang!"); self.welcome_label.setObjectName("welcomeLabel")
        
        users_label = QLabel("Pengguna Online"); self.users_list = QListWidget(); refresh_users_btn = QPushButton("Refresh Pengguna"); refresh_users_btn.clicked.connect(self.refresh_users)
        left_panel.addWidget(users_label); left_panel.addWidget(self.users_list); left_panel.addWidget(refresh_users_btn)

        global_rooms_label = QLabel("Room Global"); self.global_rooms_list = QListWidget(); self.global_rooms_list.addItems(GLOBAL_ROOMS); join_global_btn = QPushButton("Gabung Room Global"); join_global_btn.clicked.connect(self.join_global_room_flow)
        mid_panel.addWidget(global_rooms_label); mid_panel.addWidget(self.global_rooms_list); mid_panel.addWidget(join_global_btn)

        mail_label = QLabel("Mail (Undangan Pribadi)"); self.mail_list = QListWidget(); refresh_mail_btn = QPushButton("Refresh Mail"); refresh_mail_btn.clicked.connect(self.refresh_mail)
        right_panel.addWidget(mail_label); right_panel.addWidget(self.mail_list); right_panel.addWidget(refresh_mail_btn)

        bottom_layout = QHBoxLayout(); create_room_btn = QPushButton("Buat Room Pribadi"); create_room_btn.clicked.connect(self.create_room_flow); join_room_btn = QPushButton("Gabung Room Pribadi (Kode)"); join_room_btn.clicked.connect(self.join_private_room_flow)
        bottom_layout.addWidget(create_room_btn); bottom_layout.addWidget(join_room_btn)

        top_layout = QHBoxLayout(); top_layout.addLayout(left_panel, 1); top_layout.addLayout(mid_panel, 1); top_layout.addLayout(right_panel, 2)
        main_v_layout = QVBoxLayout(); main_v_layout.addWidget(self.welcome_label); main_v_layout.addLayout(top_layout); main_v_layout.addLayout(bottom_layout)
        main_layout.addLayout(main_v_layout)

    def refresh_all(self): self.refresh_users(); self.refresh_mail()
    def refresh_users(self):
        self.users_list.clear()
        try:
            for user in self.supabase.get_online_users(): self.users_list.addItem(user['username'])
        except Exception as e: self.users_list.addItem(f"Error: {e}")
    def refresh_mail(self):
        self.mail_list.clear()
        try:
            invitations = self.supabase.fetch_invitations(self.current_user['username'])
            if not invitations: self.mail_list.addItem("Tidak ada pesan baru.")
            for inv in invitations:
                decrypted = self.crypto.decrypt_with_private_key(inv['encrypted_content'], self.current_user['private_key']).decode()
                self.mail_list.addItem(f"Dari {inv['sender_username']}: {decrypted}")
        except Exception: self.mail_list.addItem("Gagal mendekripsi pesan.")
    def create_room_flow(self):
        recipient, ok = QInputDialog.getText(self, "Buat Room Pribadi", "Undang pengguna (username):")
        if ok and recipient:
            if recipient == self.current_user['username']: QMessageBox.warning(self, "Error", "Tidak bisa mengundang diri sendiri."); return
            pub_key_str = self.supabase.get_public_key(recipient)
            if not pub_key_str: QMessageBox.warning(self, "Error", f"Pengguna '{recipient}' tidak ditemukan."); return
            recipient_pk = self.crypto.deserialize_public_key(pub_key_str); creator_pk = self.current_user['public_key']; session_key = self.crypto.generate_symmetric_key()
            enc_key_creator = self.crypto.encrypt_with_public_key(session_key, creator_pk); enc_key_recipient = self.crypto.encrypt_with_public_key(session_key, recipient_pk)
            keys_payload = {self.current_user['username']: pickle.dumps(enc_key_creator).hex(), recipient: pickle.dumps(enc_key_recipient).hex()}
            room_code = ''.join(random.choices(string.ascii_uppercase, k=ROOM_CODE_LENGTH))
            if self.supabase.create_room(self.current_user['username'], room_code, keys_payload):
                inv_msg = f"Anda diundang ke room. Kode: {room_code}"; enc_inv = self.crypto.encrypt_with_public_key(inv_msg.encode(), recipient_pk)
                self.supabase.send_invitation(self.current_user['username'], recipient, enc_inv)
                QMessageBox.information(self, "Sukses", f"Room '{room_code}' dibuat dan undangan dikirim ke {recipient}.")
                self.join_room_request.emit(room_code)
            else: QMessageBox.critical(self, "Error", "Gagal membuat room di database.")
    def join_private_room_flow(self):
        code, ok = QInputDialog.getText(self, "Gabung Room Pribadi", "Masukkan kode room:");
        if ok and code: self.join_room_request.emit(code.upper())
    def join_global_room_flow(self):
        item = self.global_rooms_list.currentItem()
        if item: self.join_room_request.emit(item.text())
        else: QMessageBox.warning(self, "Peringatan", "Pilih room global dari daftar terlebih dahulu.")

class ChatPage(QWidget):
    back_to_main = pyqtSignal()
    def __init__(self, supabase_manager, crypto_manager):
        super().__init__(); self.supabase = supabase_manager; self.crypto = crypto_manager
        self.current_user = None; self.room_data = None; self.session_key = None; self.worker_thread = None; self.worker = None
        self.init_ui()
    def init_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(20, 20, 20, 20)
        self.room_label = QLabel("Room: -"); self.room_label.setObjectName("roomLabel")
        self.chat_display = QTextEdit(); self.chat_display.setReadOnly(True)
        input_layout = QHBoxLayout(); self.message_input = QLineEdit(); self.message_input.setPlaceholderText("Ketik pesan..."); self.message_input.returnPressed.connect(self.send_message)
        send_button = QPushButton("Kirim"); send_button.clicked.connect(self.send_message)
        back_button = QPushButton("Kembali ke Menu Utama"); back_button.clicked.connect(self.go_back)
        input_layout.addWidget(self.message_input); input_layout.addWidget(send_button)
        layout.addWidget(self.room_label); layout.addWidget(self.chat_display); layout.addLayout(input_layout); layout.addWidget(back_button)
    def start_chat_session(self, user, room_data):
        self.current_user = user; self.room_data = room_data; self.chat_display.clear()
        is_global = self.room_data.get('is_global', False)
        room_code = self.room_data['room_code']
        self.room_label.setText(f"Room: {room_code} {'(Global)' if is_global else ''}")
        try:
            if is_global: self.session_key = self.crypto.generate_deterministic_key(room_code)
            else:
                enc_key_hex = self.room_data.get('encrypted_session_keys', {})[self.current_user['username']]
                enc_key = pickle.loads(bytes.fromhex(enc_key_hex))
                self.session_key = self.crypto.decrypt_with_private_key(enc_key, self.current_user['private_key'])
        except Exception as e: QMessageBox.critical(self, "Error Kunci", f"Gagal mendapatkan kunci sesi: {e}"); self.go_back(); return
        self.worker = Worker(self.supabase, self.room_data, self.session_key, self.current_user['username'])
        self.worker_thread = QThread(); self.worker.moveToThread(self.worker_thread); self.worker_thread.started.connect(self.worker.run)
        self.worker.new_message.connect(self.display_message); self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater); self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.start()
    def display_message(self, sender, message):
        if sender == self.current_user['username']: self.chat_display.append(f"<p style='text-align: right;'><b>You</b>: {message}</p>")
        else: self.chat_display.append(f"<p style='text-align: left;'><b>{sender}</b>: {message}</p>")
    def send_message(self):
        msg = self.message_input.text()
        if msg and self.session_key:
            encrypted_msg = self.crypto.encrypt_with_symmetric_key(msg, self.session_key)
            if self.room_data.get('is_global', False):
                self.supabase.send_global_room_message(self.room_data['room_code'], self.current_user['username'], encrypted_msg)
            else:
                self.supabase.send_room_message(self.room_data['id'], self.current_user['username'], encrypted_msg)
            # PERBAIKAN BUG: Jangan tampilkan pesan secara lokal. Biarkan worker yang menampilkannya.
            self.message_input.clear()
    def go_back(self):
        if self.worker: self.worker.stop()
        if self.worker_thread and self.worker_thread.isRunning(): self.worker_thread.quit(); self.worker_thread.wait()
        self.back_to_main.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("PearPeak GUI"); self.setGeometry(100, 100, 900, 700); self.apply_stylesheet()
        self.user_manager = UserManager(); self.crypto_manager = CryptoManager(); self.supabase_manager = SupabaseManager(SUPABASE_URL, SUPABASE_KEY)
        self.current_user = None
        self.stacked_widget = QStackedWidget(); self.setCentralWidget(self.stacked_widget)
        self.login_page = LoginPage(self.user_manager); self.main_page = MainPage(self.supabase_manager, self.crypto_manager); self.chat_page = ChatPage(self.supabase_manager, self.crypto_manager)
        self.stacked_widget.addWidget(self.login_page); self.stacked_widget.addWidget(self.main_page); self.stacked_widget.addWidget(self.chat_page)
        self.login_page.login_successful.connect(self.on_login); self.main_page.join_room_request.connect(self.handle_join_room); self.chat_page.back_to_main.connect(self.show_main_page)
        self.heartbeat_thread = threading.Thread(target=self.run_heartbeat, daemon=True); self.app_running = True; self.heartbeat_thread.start()
    def on_login(self, user):
        self.current_user = user; self.supabase_manager.publish_user(user['username'], self.crypto_manager.serialize_public_key(user['public_key']))
        self.main_page.set_user(user); self.show_main_page()
    def handle_join_room(self, room_code):
        if room_code in GLOBAL_ROOMS:
            virtual_room_data = {'room_code': room_code, 'is_global': True}
            self.chat_page.start_chat_session(self.current_user, virtual_room_data)
            self.stacked_widget.setCurrentWidget(self.chat_page)
        else:
            room_data = self.supabase_manager.get_room_by_code(room_code)
            if not room_data: QMessageBox.warning(self, "Error", "Room pribadi tidak ditemukan."); return
            if self.current_user['username'] not in room_data.get('encrypted_session_keys', {}): QMessageBox.warning(self, "Error", "Anda tidak diundang ke room ini."); return
            self.chat_page.start_chat_session(self.current_user, room_data); self.stacked_widget.setCurrentWidget(self.chat_page)
    def show_main_page(self):
        self.main_page.refresh_all(); self.stacked_widget.setCurrentWidget(self.main_page)
    def run_heartbeat(self):
        while self.app_running:
            if self.current_user:
                try: self.supabase_manager.update_last_seen(self.current_user['username'])
                except Exception: pass
            time.sleep(60)
    def closeEvent(self, event):
        self.app_running = False; self.chat_page.go_back(); event.accept()
    def apply_stylesheet(self):
        self.setStyleSheet("""
            QWidget { background-color: #2c3e50; color: #ecf0f1; font-family: 'Segoe UI', Arial, sans-serif; }
            QMainWindow { background-color: #2c3e50; }
            QLabel#titleLabel { font-size: 48px; font-weight: bold; color: #1abc9c; }
            QLabel#welcomeLabel, QLabel#roomLabel { font-size: 20px; font-weight: bold; padding-bottom: 10px; }
            QLabel#statusLabel { color: #e74c3c; }
            QLineEdit, QTextEdit, QListWidget { background-color: #34495e; border: 1px solid #1abc9c; padding: 10px; font-size: 14px; border-radius: 5px; }
            QPushButton { background-color: #1abc9c; color: white; border: none; padding: 12px; font-size: 14px; font-weight: bold; border-radius: 5px; }
            QPushButton:hover { background-color: #16a085; }
            QListWidget::item { padding: 5px; }
            QListWidget::item:selected, QListWidget::item:hover { background-color: #3498db; }
        """)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
