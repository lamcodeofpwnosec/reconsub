import requests
import shodan
import json

def crt_sh_query(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def securitytrails_api(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def virustotal_api(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def shodan_api(domain, api_key):
    try:
        api = shodan.Shodan(api_key)
        results = api.search(f"hostname:{domain}")
        subdomains = set()
        for result in results['matches']:
            subdomains.add(result['hostnames'][0])
        return list(subdomains)
    except shodan.APIError as e:
        print(f"Error Shodan: {e}")
        return None

def save_results(subdomains, filename="result.txt"):
    with open(filename, "w") as file:
        for subdomain in subdomains:
            file.write(subdomain + "\n")
    print(f"Hasil scan telah disimpan ke {filename}")

def main():
    domain = input("Masukkan domain yang ingin di-scan: ")
    api_key_securitytrails = "API_KEY_SECURITYTRAILS"  # Ganti dengan API key SecurityTrails Anda
    api_key_virustotal = "API_KEY_VIRUSTOTAL"  # Ganti dengan API key VirusTotal Anda
    api_key_shodan = "API_KEY_SHODAN"  # Ganti dengan API key Shodan Anda

    subdomains = set()

    print("\n[+] Memulai proses scanning subdomain...\n")

    # Query crt.sh
    print("[+] Menggunakan crt.sh...")
    crt_sh_results = crt_sh_query(domain)
    if crt_sh_results:
        for entry in crt_sh_results:
            subdomains.add(entry['name_value'])
        print(f"  -> Ditemukan {len(crt_sh_results)} subdomain dari crt.sh")
    else:
        print("  -> Gagal mendapatkan data dari crt.sh")

    # Query SecurityTrails API
    print("\n[+] Menggunakan SecurityTrails API...")
    securitytrails_results = securitytrails_api(domain, api_key_securitytrails)
    if securitytrails_results:
        for subdomain in securitytrails_results['subdomains']:
            subdomains.add(f"{subdomain}.{domain}")
        print(f"  -> Ditemukan {len(securitytrails_results['subdomains'])} subdomain dari SecurityTrails")
    else:
        print("  -> Gagal mendapatkan data dari SecurityTrails")

    # Query VirusTotal API
    print("\n[+] Menggunakan VirusTotal API...")
    virustotal_results = virustotal_api(domain, api_key_virustotal)
    if virustotal_results:
        for subdomain in virustotal_results['data']:
            subdomains.add(subdomain['id'])
        print(f"  -> Ditemukan {len(virustotal_results['data'])} subdomain dari VirusTotal")
    else:
        print("  -> Gagal mendapatkan data dari VirusTotal")

    # Query Shodan API
    print("\n[+] Menggunakan Shodan API...")
    shodan_results = shodan_api(domain, api_key_shodan)
    if shodan_results:
        for subdomain in shodan_results:
            subdomains.add(subdomain)
        print(f"  -> Ditemukan {len(shodan_results)} subdomain dari Shodan")
    else:
        print("  -> Gagal mendapatkan data dari Shodan")

    # Menampilkan hasil akhir
    print("\n[+] Proses scanning selesai!")
    print(f"[+] Total subdomain yang ditemukan: {len(subdomains)}\n")

    # Menyimpan hasil ke file
    save_results(subdomains)

    # Menampilkan hasil di terminal
    print("\n[+] Daftar subdomain yang ditemukan:")
    for subdomain in subdomains:
        print(f"  -> {subdomain}")

if __name__ == "__main__":
    main()
