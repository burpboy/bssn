Panduan Lengkap Menjalankan CVE BSSN Toolkit Dari Dwi Joko Purwanto 

. Berikut panduan lengkapnya.

---

Berikut cara running yang benar :

Langkah 1: Clone & Masuk Folder

Pastikan kamu sudah clone repo ini dulu. Jika belum:

git clone https://github.com/burpboy/bssn.git
cd bssn
Langkah 2: Jalankan dengan Perintah Benar

Ketik perintah ini persis seperti ini (perhatikan ejaan exploit):

Untuk mode exploit:
python3 main.py --mode exploit --target https://www.bssn.go.id --output output/scan_report.json -v

Jika ingin scan biasa dulu:
python3 main.py --mode scan --target https://www.bssn.go.id --output output/scan_report.json -v

Jika hanya probe :
python3 main.py --mode probe --target https://www.bssn.go.id --output output/scan_report.json -v

Tips Tambahan:
Pastikan folder output/ sudah ada sebelum menjalankan script, atau buat dulu dengan mkdir -p output.
Hati-hati saat mengetik di Terminal karena keyboard virtual kadang susah, pastikan tidak ada spasi berlebih atau typo pada --mode.

Happy Pentesting 

