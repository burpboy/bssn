Lab Environment — CVE Pentest & BSSN Toolkit

Folder lab/ menyediakan lingkungan uji lokal yang terisolasi untuk menjalankan seluruh toolkit (cve_pentest_bssn) dengan aman sebelum digunakan pada target yang sah. Semua eksperimen di sini hanya boleh dilakukan terhadap container yang disediakan.

⚠️ Peringatan Etika & Hukum
Toolkit ini dibuat untuk keperluan audit keamanan yang sah, riset, dan pelatihan. Menjalankan modul --mode=probe atau --mode=exploit terhadap sistem tanpa izin tertulis adalah pelanggaran hukum. Gunakan hanya di lab ini atau target yang tercantum dalam allowlist.txt.

---

1. Tujuan Lab

Lab ini dirancang untuk:

· Menyediakan target WordPress rentan (Core, Elementor Pro, Astra, AIOSEO) secara lokal.
· Menguji alur scan → probe → exploit tanpa menyentuh sistem produksi.
· Memverifikasi bahwa guardrails, rate limit, dan cleanup bekerja sebelum dipakai di lapangan.
· Menjadi tempat reproduksi CVE (PoC) yang aman dan dapat diulang.

---

2. Prasyarat

Komponen Versi Minimum Keterangan
Docker Engine 20.10+ Wajib
Docker Compose v2 (docker compose) Wajib
Python 3.10+ Untuk menjalankan toolkit host
RAM 4 GB Disarankan 8 GB
OS Linux / macOS / WSL2 Windows native tidak didukung penuh

Pastikan port berikut kosong di host: 8080, 8081, 8082, 3306, 2222.

---

3. Struktur Folder Lab

```
lab/
├── docker-compose.yml      # Definisi semua service lab
├── README.md               # Dokumen ini
└── results/                # Output scan & log lab (gitignored)
```

Semua artefak hasil uji (report JSON, log exploit, evidence) wajib disimpan di lab/results/, bukan di root toolkit.

---

4. Quick Start

```bash
# 1. Masuk ke folder lab
cd cve_pentest_bssn/lab

# 2. Nyalakan seluruh stack lab
docker compose up -d

# 3. Tunggu inisialisasi (±60 detik pada run pertama)
docker compose ps        # semua service harus "healthy"

# 4. Verifikasi target dapat diakses
curl -I http://localhost:8080   # WordPress target utama
curl -I http://localhost:8081   # Elementor Pro target
curl -I http://localhost:8082   # AIOSEO target
```

Setelah stack aktif, jalankan toolkit dari root proyek (bukan dari lab/):

```bash
cd ..
python main.py --mode=scan --target=http://localhost:8080
```

---

5. Service di docker-compose.yml

Service Port Host Port Container Peran
wp-core-vuln 8080 80 WordPress Core versi rentan (CVE target wp_core)
wp-elementor-vuln 8081 80 WordPress + Elementor Pro rentan (elementor_rce)
wp-astra-vuln 8082 80 WordPress + Astra Theme rentan (astra_privesc)
wp-aioseo-vuln 8083 80 WordPress + AIOSEO rentan (aioseo_sqli)
mysql-vuln 3306 3306 DB pendukung untuk dump SQL
victim-ssh 2222 22 Target untuk reverse shell / command exec
victim-listener — internal Container pemantau koneksi balik (tcpdump)

Detail credential default tiap service dicantumkan pada komentar di docker-compose.yml (mis. admin / admin_lab_2024).

---

6. Alur Uji yang Direkomendasikan

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  MODE SCAN   │ → │  MODE PROBE  │ → │ MODE EXPLOIT │
│ (pasif/verif)│   │ (low risk)   │   │ (full risk)  │
└──────────────┘   └──────────────┘   └──────────────┘
```

6.1 Mode Scan (Aman)

```bash
python main.py --mode=scan --target=http://localhost:8080 \
               --output=lab/results/scan_report.json
```

Modul yang aktif: recon.py, wp_core.py, elementor.py, astra.py, aioseo.py, envoy.py, wp_readme.py, rest_probe.py. Tidak ada payload aktif.

6.2 Mode Probe (Konfirmasi Kerentanan)

```bash
# Contoh: konfirmasi endpoint RCE Elementor
python main.py --mode=probe --target=http://localhost:8081 \
               --module=elementor_rce_probe \
               --output=lab/results/deep_verify.json
```

Probe tidak mengeksekusi shell, hanya memastikan endpoint/error signature dapat dijangkau. Hasil dipakai sebagai syarat untuk eskalasi ke mode exploit.

6.3 Mode Exploit (Risiko Penuh)

Mode ini mewajibkan 4 flag dari core_offensive/guard.py:

```bash
python main.py --mode=exploit --target=http://localhost:8081 \
               --module=elementor_rce_exec \
               --i-have-authorization \
               --lab-only \
               --allow-destructive \
               --confirm-domain=localhost \
               --allowlist=allowlist.txt \
               --output=lab/results/exploit_logs.json
```

Flag wajib:

1. --i-have-authorization — konfirmasi izin.
2. --lab-only — mengunci target ke localhost / 127.0.0.1 / network lab.
3. --allow-destructive — menyatakan efek samping (upload shell, dump DB) disadari.
4. --confirm-domain=<host> — harus cocok dengan host target dan allowlist.txt.

Seluruh langkah dicatat ke exploit_logs.json (JSONL, chain of evidence).

---

7. Emergency Stop & Cleanup

Jika terjadi hal tak terduga saat mode exploit:

```bash
# 1. Hentikan toolkit (Ctrl+C pada terminal main.py)
# 2. Hentikan seluruh lab & buang volume
docker compose down -v

# 3. Bersihkan artefak (opsional)
rm -rf lab/results/* evidence/logs/* evidence/screenshots/*
```

core_offensive/cleanup.py akan otomatis mencoba menghapus shell yang di-upload dan mengembalikan DB hanya jika dipanggil manual (mis. python -m core_offensive.cleanup --run-id=<id>) — cleanup tidak otomatis agar audit trail tidak hilang.

---

8. Batasan Rate & Guardrails

· Maksimum 10 request/detik dan 500 request total per sesi (lihat core_offensive/ratelimit.py).
· Semua target non-localhost ditolak kecuali terdaftar di allowlist.txt.
· Modul exploit akan menolak berjalan jika salah satu dari 4 flag wajib tidak disertakan.
· config.py mengatur timeout=10s dan max_retry=2 — jangan diubah saat sesi exploit berlangsung.

---

9. Mereset Lab

```bash
# Reset penuh (hapus semua data & container)
docker compose down -v --remove-orphans

# Bangun ulang dari image bersih
docker compose build --no-cache
docker compose up -d
```

Jika ingin mempertahankan image namun mereset state: docker compose down && docker compose up -d.

---

10. Troubleshooting

Gejala Penyebab Umum Solusi
docker compose up gagal karena port Port host terpakai Matikan service lain atau ubah mapping port di compose
wp-core-vuln unhealthy Volume db belum terinisasi docker compose down -v lalu up -d kembali
Toolkit timeout ke localhost:8080 Stack belum siap Tunggu healthcheck, lalu curl -I manual
Mode exploit ditolak Salah satu dari 4 flag tidak ada, atau domain tidak cocok allowlist.txt Periksa pesan error dari core_offensive/guard.py
ModuleNotFoundError di host Dependency belum terpasang pip install -r ../requirements.txt
Reverse shell tidak masuk victim-listener tidak berjalan docker compose logs victim-listener

---

11. Hasil Uji (Contoh)

```
lab/results/
├── scan_report.json          # Output --mode=scan
├── deep_verify.json          # Output --mode=probe
├── offensive_results.json    # Output --mode=exploit
└── exploit_logs.json         # Chain of evidence (JSONL)
```

Salin artefak ke evidence/logs/ dan evidence/screenshots/ hanya jika Anda akan menyusun laporan resmi. Jangan commit ke repositori.

---

12. Daftar Periksa Sebelum Menggunakan di Luar Lab

☐ allowlist.txt hanya berisi domain yang memiliki izin tertulis.
☐ config.py memiliki timeout dan rate limit yang wajar.
☐ Backup database target sudah dibuat.
☐ Kontak PIC target tersedia untuk emergency stop.
☐ Rencana cleanup (manual) sudah disepakati.
☐ Log exploit_logs.json akan diserahkan ke auditor setelah sesi selesai.

---

13. Referensi

· ../README.md — instalasi & penggunaan toolkit utama.
· ../config.py — konfigurasi global (API key, timeout, log path).
· ../core_offensive/guard.py — implementasi 4 flag wajib.
· ../modules/ — modul deteksi pasif.
· ../modules_offensive/probes/ & ../modules_offensive/exploits/ — modul aktif (hanya untuk mode probe/exploit).

---

Maintainer: Tim Keamanan BSSN — Divisi Pentest
Lisensi penggunaan: Internal / Authorized Testing Only.