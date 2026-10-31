Panduan Lengkap Menjalankan CVE BSSN Toolkit

Berdasarkan main.py dan requirements.txt, ini bukan proyek Python biasa — ini adalah toolkit pentest multi-mode dengan guardrails. Berikut panduan lengkapnya.

---

⚠️ PERINGATAN HUKUM & ETIKA

Toolkit ini punya 3 mode, dan exploit adalah High Risk (RCE, SQLi, reverse shell via pwntools). Hanya jalankan pada:

· Sistem milik sendiri
· Lab terisolasi (VM tanpa akses internet)
· Target dengan izin tertulis eksplisit (pentest engagement)

Penggunaan tanpa izin = tindak pidana (UU ITE Pasal 30/46 di Indonesia, CFAA di AS, dll).

---

1. Prasyarat Sistem

Kebutuhan Detail
Python 3.8+ (wajib, disebutkan di requirements.txt)
OS Linux (disarankan) / macOS / WSL2. Windows native kurang ideal untuk pwntools
Git Untuk clone repo
Jaringan Untuk instalasi dependensi saja; mode exploit sebaiknya di lab offline

Cek versi Python:

```bash
python3 --version   # harus >= 3.8
```

---

2. Clone & Siapkan Direktori

```bash
git clone https://github.com/burpboy/bssn.git
cd bssn
```

Struktur yang wajib ada (berdasarkan import di main.py):

```
bssn/
├── main.py
├── config.py
├── allowlists.txt
├── requirements.txt
├── core/
│   ├── logger.py          ← setup_logger()
│   └── guardrails.py      ← check_allowlist(), get_risk_level()
├── modules/
│   └── deep_verify.py     ← deep_verify_engine()
├── modules_offensive/
│   └── base_exploit.py    ← BaseExploit
├── core_offensive/
├── payloads/shells/
├── evidence/logs/         ← dibuat otomatis saat run
└── output/
```

Catatan penting: main.py meng-import file-file ini di level modul. Jika salah satu tidak ada, program akan langsung exit dengan pesan [!] Error loading dependencies. Repo di GitHub hanya menampilkan folder, jadi pastikan file .py di dalamnya benar-benar ada setelah clone.

---

3. Buat Virtual Environment (WAJIB disarankan)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
```

---

4. Instal Dependensi

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Yang akan terinstal:

· requests, beautifulsoup4, lxml → HTTP & parsing
· Jinja2 → report generator
· pwntools + paramiko → reverse shell & SSH (ini yang membuat toolkit bisa "ofensif")
· colorama, tqdm → UI/logging
· pydantic → validasi config
· python-whois, geoip2 → recon

Troubleshooting pwntools:

```bash
# Jika gagal karena binutils/native build:
sudo apt install -y python3-dev build-essential binutils
# atau install terpisah dulu:
pip install pwntools --no-cache-dir
```

---

5. Konfigurasi Sebelum Menjalankan

a. config.py

Di-load oleh load_config() (meski di snippet tidak dipakai langsung, ada baiknya diperiksa). Pastikan berisi setting seperti timeout, user-agent, dsb.

b. allowlists.txt — KRITIS

Fungsi check_allowlist(target_url) di core/guardrails.py akan mengecek file ini. Tambahkan hanya target lab Anda, contoh isi:

```
127.0.0.1
localhost
192.168.56.10
lab.local
```

Jika target tidak ada di allowlist, mode exploit akan memberi warning (tapi di kode masih lanjut — jadi disiplin Anda yang menentukan).

c. Cek core/guardrails.py

Pastikan fungsi get_risk_level() mengembalikan level yang Anda harapkan (mis. LOW/HIGH). Baca dulu isinya sebelum eksekusi.

---

6. Cara Menjalankan — Sintaks CLI

Berdasarkan argparse di main.py:

```
python3 main.py --mode {scan|probe|exploit} --target URL [opsi]
```

Argumen Lengkap

Argumen Wajib Default Fungsi
--mode ✅ — scan, probe, atau exploit
--target ✅ — URL target, mis. https://lab.local
--payload ❌ default Tipe payload (khusus mode exploit)
--output ❌ None (print ke stdout) Simpan hasil ke file JSON
--verbose / -v ❌ False Logging detail + traceback
--dry-run ❌ False ⚠️ Didefinisikan tapi TIDAK dipakai di kode — jangan andalkan ini sebagai pengaman!

---

7. Contoh Eksekusi Tiap Mode

🔹 Mode 1: scan — Paling Aman

Passive recon + deep verification. Hanya pakai modules/ dan modules/deep_verify.py.

```bash
python3 main.py --mode scan --target https://lab.local --output output/scan_lab.json -v
```

🔹 Mode 2: probe — Low Risk

Probe aktif untuk CVE (contoh di kode: Elementor RCE, AIOSEO SQLi).

```bash
python3 main.py --mode probe --target https://lab.local --output output/probe_lab.json
```

🔹 Mode 3: exploit — HIGH RISK ⚠️

Eksekusi payload penuh + reverse shell. Hanya di lab.

```bash
# Pastikan target ada di allowlists.txt dulu!
python3 main.py --mode exploit --target https://lab.local --payload default --output output/exploit_lab.json -v
```

---

8. Output & Log

· Log: otomatis disimpan ke evidence/logs/bssn_<mode>_<YYYYMMDD_HHMMSS>.log
· Hasil JSON: ke path --output, atau tercetak ke stdout jika tidak diset
· Format: { "mode", "target", "timestamp", "status", "data"/"logs"/"message" }

Contoh output scan:

```json
{
  "mode": "scan",
  "target": "https://lab.local",
  "timestamp": "2026-10-31T10:00:00",
  "status": "success",
  "data": {
    "deep_verify": { "cves": [ ... ] }
  }
}
```

---

9. Alur Kerja yang Disarankan (Best Practice)

```
1. Siapkan VM lab terisolasi (host-only network)
2. Clone repo di VM
3. Aktifkan venv + install requirements
4. Isi allowlists.txt HANYA dengan IP lab
5. Baca core/guardrails.py & config.py dulu
6. Jalankan: scan → probe → (review manual) → exploit
7. Simpan semua output JSON + log sebagai bukti
```

---

10. Troubleshooting Umum

Masalah Solusi
[!] Error loading dependencies File di core/, modules/, modules_offensive/ tidak lengkap. Cek isi folder repo.
ModuleNotFoundError: pwntools pip install pwntools --no-cache-dir + apt install binutils
argparse: error: the following arguments are required Lupa --mode atau --target
Warning "not in allowlist" Tambahkan target ke allowlists.txt
Log tidak muncul Cek core/logger.py; pastikan folder evidence/logs writable
--dry-run tidak mencegah eksekusi Bug di kode — flag ini didefinisikan tapi tidak dipakai. Jangan bergantung padanya.

---

11. Catatan Penting dari Review Kode

Saya menemukan beberapa hal yang perlu Anda waspadai:

1. --dry-run tidak berfungsi — didefinisikan di parser tapi tidak pernah dibaca. Semua mode tetap mengeksekusi penuh.
2. Guardrail hanya warning, bukan block — di run_exploit_mode, jika check_allowlist gagal, kode hanya logger.warning lalu tetap lanjut ke eksekusi payload. Pengaman sebenarnya ada di modules_offensive/exploits/ yang tidak terlihat.
3. Import di level modul — jika salah satu file dependency hilang, program crash total sebelum CLI sempat berjalan.
4. Banyak kode contoh masih di-comment (# from modules...) — artinya fungsi inti bergantung pada file yang tidak ditampilkan di README. Anda perlu memeriksa isi folder modules/ dan modules_offensive/ untuk melihat implementasi sebenarnya.

---

12. Ringkasan Perintah Cepat

```bash
git clone https://github.com/burpboy/bssn.git && cd bssn
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# edit allowlists.txt → tambah IP lab Anda
python3 main.py --mode scan   --target https://lab.local -v
python3 main.py --mode probe  --target https://lab.local -v
python3 main.py --mode exploit --target https://lab.local --payload default -v   # ⚠️ LAB ONLY
```
