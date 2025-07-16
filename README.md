# PearPeak Chat

PearPeak adalah aplikasi chat terenkripsi end-to-end (E2EE) berbasis Python yang mendukung dua antarmuka: **GUI (PyQt6)** dan **CLI (Command Line Interface)**. Proyek ini menggunakan **Supabase** sebagai backend untuk menyimpan data pengguna, pesan, dan sesi room. PearPeak mendukung private room dan global room, serta fitur undangan.

## 🔐 Fitur Utama

- ✅ Enkripsi end-to-end (RSA + AES)
- 💬 Chat pribadi dan global
- ✉️ Sistem undangan terenkripsi
- 🧠 Penyimpanan profil lokal
- 🖥️ GUI responsif (PyQt6)
- 📟 CLI ringan (terminal)
- 🌐 Supabase sebagai backend realtime

## 🛠️ Instalasi

### 1. Clone repositori

```bash
git clone https://github.com/muhammadzili/PearPeak.git
cd PearPeak
```

### 2. Instal dependensi

```bash
pip install -r requirements.txt
```

## 🚀 Menjalankan Aplikasi

### Mode GUI (PyQt6)

```bash
python3 gui.py
```

### Mode CLI

```bash
python3 main.py
```

## 🧠 Struktur Proyek

- `requirements.txt` – Dependensi
- `main.py` – Antarmuka CLI, cocok untuk pengguna terminal
- `gui.py` – Antarmuka grafis dengan PyQt6
- `user.dat` – Data pengguna terenkripsi (disimpan lokal)
- Supabase – Backend untuk pesan, pengguna, room

## 👨‍💻 Pengembang & Kontribusi

Proyek ini dikembangkan oleh **Muhammad Zili**, seorang pengembang independen yang berfokus pada privasi, enkripsi, dan aplikasi terdistribusi.

Temui saya lebih lanjut di:

- 👤 [Portofolio](https://mzili.my.id)
- 🌐 [Instagram](https://instagram.com/mhmdszuli)
- 🧑‍💻 [Dev.to](https://dev.to/muhammadzili)
- 🐦 [X (Twitter)](https://x.com/ohhzilitoh)

Kontribusi, saran, atau kolaborasi sangat diterima!

## 🧾 Lisensi

MIT License © 2025
