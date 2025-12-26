# Mimikatz Attack Generator

Parses mimikatz output and generates ready-to-use attack commands.

## Usage

```bash
python3 mimikatz_attack_generator.py <mimikatz_output.txt> [-t TARGET] [-d DC_IP] [-o OUTPUT]
```

| Flag | Description |
|------|-------------|
| `-t` | Target IP/hostname (replaces `<TARGET>`) |
| `-d` | Domain Controller IP (replaces `<DC_IP>`) |
| `-o` | Save output to file |

## Parsed Data

- `sekurlsa::logonpasswords` - NTLM, passwords, AES keys, DPAPI
- `lsadump::sam` - Local SAM entries
- `lsadump::secrets` - LSA secrets, service passwords
- `lsadump::dcsync` - DCSync output
- `lsadump::trust` - Domain trust keys
- `sekurlsa::tickets` - Kerberos tickets
- `dpapi::masterkey` - DPAPI masterkeys
- Machine accounts & credentials

## Generated Attacks

- Pass-the-Hash (Impacket, CME, NetExec, Evil-WinRM, Mimikatz, Rubeus)
- Pass-the-Key (AES)
- Overpass-the-Hash
- Silver/Golden Tickets
- DCSync
- Kerberoasting & AS-REP Roasting
- Lateral Movement (WMI, DCOM, PSRemoting)
- Persistence (Skeleton Key, Scheduled Tasks, WMI)
- Credential Spraying
- Hash Cracking (hashcat, john)

## Example

```bash
python3 mimikatz_attack_generator.py dump.txt -t 10.10.10.5 -d 10.10.10.1 -o attacks.txt
```
