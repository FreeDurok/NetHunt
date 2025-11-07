# 🔍 NetHunt

**NetHunt** è uno strumento avanzato per l'analisi forense di traffico di rete (PCAP) che combina multiple fonti di intelligence per fornire un'analisi completa delle catture di rete.

## ✨ Funzionalità

NetHunt analizza file PCAP e fornisce:

- **📁 Estrazione File**: Estrae automaticamente file da HTTP, FTP e SMB
- **🚨 Rilevamento Beaconing**: Identifica potenziali attività di malware C2 (Command & Control)
- **🌐 Analisi HTTP**: Estrae URL, metodi, status codes, user-agents e hosts
- **🔎 Analisi DNS**: Raccoglie queries DNS e risposte
- **🔒 Analisi TLS/SSL**: Identifica certificati, SNI e JA3 fingerprints
- **📊 Report HTML**: Genera report moderni, responsive e facilmente consultabili
- **🧹 Deduplicazione**: Rimuove automaticamente file duplicati e spazzatura

## 🛠️ Strumenti Utilizzati

NetHunt integra i seguenti tool di analisi:

| Tool | Scopo | Deployment |
|------|-------|------------|
| **Zeek** | Network Security Monitor - logging dettagliato e estrazione file | Docker 🐳 |
| **Suricata** | IDS/IPS - detection engine con EVE JSON logging | Native |
| **Tshark** | Wireshark CLI - export di oggetti HTTP/FTP/SMB | Native |

**Nota:** Zeek viene eseguito tramite Docker per semplificare l'installazione su Kali Linux, dove la compilazione nativa può essere complessa.

## 📦 Installazione

### Su Kali Linux (Raccomandato)

```bash
# 1. Clona o scarica NetHunt
cd NetHunt

# 2. Installa i tool necessari (richiede sudo)
sudo ./install-tools.sh

# 3. Pronto!
python3 net-hunt.py --help
```

### Installazione Manuale

```bash
sudo apt update

# Installa Docker per Zeek
sudo apt install -y docker.io
sudo systemctl enable docker && sudo systemctl start docker
sudo docker pull zeek/zeek:latest

# Installa gli altri tool
sudo apt install -y suricata tshark wireshark-common

# Aggiungi il tuo utente al gruppo docker
sudo usermod -aG docker $USER
# Logout e login per applicare le modifiche
```

## 🚀 Utilizzo

### Esempio Base

```bash
python3 net-hunt.py capture.pcap -o output
```

### Opzioni Avanzate

```bash
# Chunking per PCAP grandi (divide in blocchi da 5000 pacchetti)
python3 net-hunt.py large.pcap -o output --chunk 5000

# Specificare directory di output personalizzata
python3 net-hunt.py capture.pcap -o /path/to/analysis_results
```

### Parametri

```
usage: net-hunt.py [-h] [-o OUT] [--chunk CHUNK] pcap

NetHunt: Advanced PCAP analysis with beaconing detection, file extraction, and comprehensive reporting

positional arguments:
  pcap           Path to PCAP file to analyze

optional arguments:
  -h, --help     Show this help message and exit
  -o, --out OUT  Output directory (default: out)
  --chunk CHUNK  Split PCAP into chunks of N packets (requires editcap)

Zeek runs via Docker for easy deployment on Kali Linux. Ensure Docker is installed: sudo ./install-tools.sh
```

## 📂 Output

Dopo l'esecuzione, NetHunt genera:

```
output/
├── report.html          # Report HTML moderno e interattivo ⭐
├── report.json          # Report JSON con tutti i dati
└── work_1/              # Dati grezzi dell'analisi
    ├── conn.log         # Log connessioni Zeek
    ├── http.log         # Log HTTP Zeek
    ├── dns.log          # Log DNS Zeek
    ├── ssl.log          # Log TLS/SSL Zeek
    ├── extracted/       # File estratti da Zeek
    ├── export_http/     # File estratti da HTTP (tshark)
    ├── export_ftp/      # File estratti da FTP (tshark)
    ├── export_smb/      # File estratti da SMB (tshark)
    └── suricata/
        ├── eve.json     # Log EVE di Suricata
        └── files/       # File estratti da Suricata
```

### Report HTML

Il **report.html** è il punto focale dell'analisi e include:

- **Dashboard con statistiche**: Files, HTTP requests, DNS queries, TLS connections
- **Beaconing Detection**: Tabella con potenziali comunicazioni C2
- **File Estratti**: Lista completa con hash SHA256, dimensioni e tipo
- **HTTP Analysis**: URLs, hosts più contattati, user-agents, metodi HTTP
- **DNS Analysis**: Query più frequenti, tipi di query
- **TLS/SSL Analysis**: Server names, JA3 fingerprints, versioni TLS

## 🎯 Caso d'Uso: Analisi Malware

```bash
# 1. Cattura traffico sospetto o usa PCAP esistente
# 2. Analizza con NetHunt
python3 net-hunt.py suspicious.pcap -o malware_analysis

# 3. Apri il report HTML
firefox malware_analysis/report.html

# 4. Cerca:
#    - Beaconing (comunicazioni periodiche verso IP esterni)
#    - URLs sospetti (download di payload)
#    - DNS queries verso domini C2
#    - File estratti (analizza con strumenti antivirus)
```

## 📊 Esempio Report

Il report HTML mostra:

```
🔍 NetHunt Analysis Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Statistics
├── Total Files: 63
├── HTTP Requests: 1,245
├── DNS Queries: 432
├── TLS Connections: 89
├── Unique URLs: 47
└── Beacons Detected: 2 ⚠️

🚨 Beaconing Detection
┌────────────┬──────────────┬──────┬──────────┬──────┐
│ Source IP  │ Dest IP      │ Port │ Interval │ Score│
├────────────┼──────────────┼──────┼──────────┼──────┤
│ 10.0.1.15  │ 93.184.1.42  │ 443  │ 60.2s    │ 12.5 │
└────────────┴──────────────┴──────┴──────────┴──────┘

📁 Extracted Files
┌────────────┬─────────────────┬──────────┬──────────────┐
│ Source     │ Filename        │ Size     │ SHA256       │
├────────────┼─────────────────┼──────────┼──────────────┤
│ tshark_http│ payload.exe     │ 2.3 MB   │ a3f5b2c1...  │
│ zeek       │ script.ps1      │ 15.2 KB  │ 8d2e9f1a...  │
└────────────┴─────────────────┴──────────┴──────────────┘
```

## 🔧 Troubleshooting

### Docker non disponibile

```bash
# Installa Docker
sudo apt install docker.io
sudo systemctl start docker

# Verifica installazione
docker --version

# Aggiungi utente al gruppo docker per evitare sudo
sudo usermod -aG docker $USER
# Logout e login per applicare
```

### Zeek Docker non funziona

```bash
# Verifica che Docker sia in esecuzione
sudo systemctl status docker

# Scarica manualmente l'immagine Zeek
docker pull zeek/zeek:latest

# Testa l'immagine
docker run --rm zeek/zeek:latest --version

# Se ci sono problemi di permessi
sudo chmod 666 /var/run/docker.sock  # Temporaneo, o aggiungi utente al gruppo docker
```

### Errore "permission denied" con Docker

```bash
# Soluzione permanente: aggiungi utente al gruppo docker
sudo usermod -aG docker $USER

# Poi logout/login, oppure:
newgrp docker

# Soluzione temporanea: usa sudo
sudo python3 net-hunt.py capture.pcap -o output
```

### Suricata non funziona

```bash
# Verifica installazione
which suricata

# Reinstalla se necessario
sudo apt install --reinstall suricata
```

### PCAP troppo grande

```bash
# Usa il chunking per dividere in blocchi più piccoli
python3 net-hunt.py large.pcap -o output --chunk 10000
```

### Container Docker rimane in esecuzione

NetHunt usa `--rm` per rimuovere automaticamente i container, ma se qualcosa va storto:

```bash
# Lista container in esecuzione
docker ps

# Ferma tutti i container Zeek
docker stop $(docker ps -q --filter ancestor=zeek/zeek:latest)
```

## 📝 Note

- **Docker**: Zeek viene eseguito in container Docker isolato per semplicità e sicurezza
- **File duplicati**: NetHunt rimuove automaticamente file duplicati basandosi su hash SHA256
- **File vuoti**: I file di dimensione 0 vengono automaticamente scartati
- **Privacy**: Tutti i dati rimangono locali, nessun upload verso servizi esterni
- **Performance**: Per PCAP > 1GB, usa l'opzione `--chunk` per migliorare le prestazioni
- **Permessi**: Se Docker richiede sudo, aggiungi il tuo utente al gruppo docker (vedi Troubleshooting)

## 🎓 Risorse

- **Zeek**: https://zeek.org/
- **Suricata**: https://suricata.io/
- **Wireshark/Tshark**: https://www.wireshark.org/

## 📄 Licenza

Questo tool è fornito "as-is" per scopi educativi e di ricerca in sicurezza informatica.

## 🤝 Contributi

Contributi, suggerimenti e miglioramenti sono benvenuti!

---

**Nota**: NetHunt è stato progettato per analisi forense e incident response. Utilizzalo solo su traffico di rete che hai il permesso di analizzare.
