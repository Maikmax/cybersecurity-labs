# Cybersecurity Labs

> **Marcus Paula** | IT Engineer — TikTok EMEA | Dublin, Ireland
> HackTheBox: MaikPro | Zero Days CTF — 4th Place (Solo)

Hands-on security research through CTF competitions and HackTheBox machines.
Offensive techniques applied directly to strengthen defensive operations,
reduce risk exposure and improve incident detection across enterprise environments.

---

## Operational Relevance

Understanding attacker techniques informs better defensive decisions.
Each lab maps to real-world controls and IT Operations outcomes:

| KPI | Application |
|-----|-------------|
| **Risk Exposure Index** | Identifying misconfiguration patterns (SUDO, NFS, wildcard injection) before attackers do |
| **Security Incident Rate** | Recognising lateral movement TTPs used in real incidents (MITRE ATT&CK) |
| **Change Success Rate** | Exploit path awareness drives safer change management and hardening procedures |
| **Automation Rate** | Detection scripts derived from lab techniques applied in production monitoring |

---

## CTF Performance

| Event | Result |
|-------|--------|
| **Zero Days CTF** | **4th Place — Solo competitor** |
| HackTheBox | Active — [MaikPro](https://app.hackthebox.com/profile/MaikPro) |
| TryHackMe | Active — forensics and incident response labs |
| AttackIQ | MITRE ATT&CK practitioner |

---

## HackTheBox Writeups

| Machine | Difficulty | OS | Key Techniques |
|---------|-----------|-----|----------------|
| [Joker](./hackthebox/joker/) | Hard | Linux | TFTP, Squid proxy, Werkzeug RCE, sudoedit CVE-2015-5602, tar wildcard |
| [Falafel](./hackthebox/falafel/) | Hard | Linux | Blind SQLi, PHP type juggling, wget truncation, framebuffer, debugfs |
| [Jail](./hackthebox/jail/) | Insane | Linux | Stack BOF, NFS UID spoofing, rvim escape, RSA Wiener attack |
| [Calamity](./hackthebox/calamity/) | Hard | Linux | PHP eval RCE, audio steganography, ret2mprotect ROP chain |

---

## Techniques Mapped to MITRE ATT&CK

| Technique | ATT&CK ID | Seen In |
|-----------|-----------|---------|
| Sudo exploitation | T1548.003 | Joker, Jail |
| Wildcard injection via cron | T1053.003 | Joker |
| NFS share abuse | T1039 | Jail |
| Web shell upload | T1505.003 | Falafel, Calamity |
| Credential access via config files | T1552.001 | Falafel, Joker |
| Steganography | T1027.003 | Calamity |
| Buffer overflow | T1203 | Jail, Calamity |

---

## Certifications

- Foundations of Operationalizing MITRE ATT&CK (AttackIQ)
- Computer Forensic — First Learning Activity (TryHackMe)
- Certified Network Security Specialist (DefensityOne)

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Marcus_Paula-0077B5?style=flat-square&logo=linkedin)](https://linkedin.com/in/marcuspaula)
[![GitHub](https://img.shields.io/badge/GitHub-Maikmax-181717?style=flat-square&logo=github)](https://github.com/Maikmax)
