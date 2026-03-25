# 🛡️ IOC Intelligence Hub

Platform analisis Indicator of Compromise (IOC) berbasis Streamlit dengan integrasi 7 sumber threat intelligence.

---

## 🚀 Cara Menjalankan

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Konfigurasi API Keys

Buat file `.streamlit/secrets.toml`:

```toml
[api_keys]
virustotal    = "YOUR_KEY"
abuseipdb     = "YOUR_KEY"
shodan        = "YOUR_KEY"
otx           = "YOUR_KEY"
urlscan       = "YOUR_KEY"
greynoise     = "YOUR_KEY"
ipinfo        = "YOUR_KEY"
```

> ⚠️ Tambahkan `.streamlit/secrets.toml` ke `.gitignore`

### 3. Jalankan aplikasi

```bash
streamlit run app.py
```

---

## 🔌 Sumber Threat Intelligence

| Platform | IOC Types | Free Tier |
|---|---|---|
| VirusTotal | IP, Domain, URL, Hash | 4 req/min, 500/day |
| AbuseIPDB | IP | 1,000 req/day |
| Shodan | IP | 1 req/sec |
| OTX AlienVault | IP, Domain, URL, Hash | Rate limited |
| URLScan.io | URL, Domain | 100 scan/hr |
| GreyNoise | IP | Community free |
| IPInfo | IP | 50K req/month |

---

## 🎯 Fitur

- **Single IOC Check** — Analisis mendalam satu IOC dengan gauge score, donut chart deteksi VT, dan tab per sumber
- **Bulk IOC Check** — Analisis banyak IOC sekaligus, export ke CSV
- **Threat Scoring** — Agregasi skor 0-100 dari semua sumber (CLEAN → LOW → MEDIUM → HIGH → CRITICAL)
- **Auto IOC Detection** — Otomatis deteksi tipe: IPv4/IPv6, Domain, URL, MD5/SHA1/SHA256/SHA512, Email, CIDR
- **History** — Log semua pengecekan selama sesi
- **API Config Guide** — Panduan setup API in-app

---

## 📂 Struktur File

```
ioc_checker/
├── app.py
├── requirements.txt
├── README.md
└── .streamlit/
    └── secrets.toml   ← JANGAN COMMIT INI!
```
