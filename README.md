# ReconSub - Alat Reconnaissance Subdomain Menggunakan Multiple Sumber Data
ReconSub adalah skrip Python untuk menemukan subdomain dari sebuah domain dengan mengumpulkan data dari berbagai sumber termasuk log transparansi sertifikat dan API keamanan. Alat ini berguna untuk pentesting dan bug bounty hunting.

## Fitur
- Pencarian subdomain dari 4 sumber berbeda:
  - crt.sh (Log Transparansi Sertifikat)
  - SecurityTrails API
  - VirusTotal API
  - Shodan API
- Menggabungkan dan menghapus duplikat hasil
- Menyimpan hasil ke file teks
- Antarmuka baris perintah sederhana

## Persyaratan

- Python 3.x
- Kunci API untuk:
  - [SecurityTrails](https://securitytrails.com/)
  - [VirusTotal](https://www.virustotal.com/)
  - [Shodan](https://www.shodan.io/)

## Instalasi

1. Clone repositori:
```bash
git clone https://github.com/lamcodeofpwnosec/reconsub.git
cd reconsub
```
2. Install dependensi yang diperlukan:
```
pip install requests shodan
```
## Konfigurasi
1. Dapatkan API key dari:
  - SecurityTrails: https://securitytrails.com/
  - VirusTotal: https://developers.virustotal.com/
  - Shodan: https://developer.shodan.io/

2. Konfigurasikan `main.py` dan ganti API key placeholder:
```js
api_key_securitytrails = "API_KEY_SECURITYTRAILS_ANDA"
api_key_virustotal = "API_KEY_VIRUSTOTAL_ANDA" 
api_key_shodan = "API_KEY_SHODAN_ANDA"
```
## Used / Cara Penggunaan
```
python main.py
```
Masukkan domain target ketika diminta (contoh: `example.com`).

Contoh output:
```
Masukkan domain yang ingin di-scan: example.com

[+] Memulai proses scanning subdomain...

[+] Menggunakan crt.sh...
  -> Ditemukan 150 subdomain dari crt.sh

[+] Menggunakan SecurityTrails API...
  -> Ditemukan 200 subdomain dari SecurityTrails

[+] Menggunakan VirusTotal API...
  -> Ditemukan 100 subdomain dari VirusTotal

[+] Menggunakan Shodan API...
  -> Ditemukan 50 subdomain dari Shodan

[+] Proses scanning selesai!
[+] Total subdomain yang ditemukan: 400

[+] Hasil scan telah disimpan ke result.txt
```

## Output
Hasil akan disimpan di `result.txt` dengan format satu subdomain per baris:
```
sub1.example.com
sub2.example.com
```

## Disclaimer
- Alat ini hanya untuk tujuan edukasi dan testing yang sah
- Patuhi batas rate limit dari masing-masing layanan API
- Pengembang tidak bertanggung jawab atas penyalahgunaan alat ini
- Hapus/redaksi API key sebelum push ke repository publik

## Selamat Berrecon! 🕵️♂️

