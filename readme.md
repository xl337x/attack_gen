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
#for the 2mimika
# Mimikatz Parser - Quick Usage

## Basic Usage
```bash
python3 mimikatz_parser_enhanced.py <mimikatz_output.txt>
```

## With Options
```bash
python3 mimikatz_parser_enhanced.py output.txt -t 172.16.10.5 -d 172.16.10.5 -o attacks.txt
```

## Options
| Flag | Description |
|------|-------------|
| `-t` | Target IP/hostname |
| `-d` | Domain Controller IP |
| `-o` | Output file (default: stdout) |

## Examples
```bash
# Parse and print to screen
python3 mimikatz_parser_enhanced.py dcsync.txt

# Full options
python3 mimikatz_parser_enhanced.py dcsync.txt -t 10.10.10.5 -d 10.10.10.1 -o pwn.txt

# Pipe to less
python3 mimikatz_parser_enhanced.py dcsync.txt | less
```

## Supported Input
- `sekurlsa::logonpasswords`
- `lsadump::dcsync /all /csv`
- `lsadump::sam`
- `lsadump::secrets`
- `lsadump::trust`

## Output Sections
1. **Summary** - Extracted creds overview
2. **PTH Attacks** - Impacket, CME, Evil-WinRM
3. **PTK Attacks** - AES-based (stealthier)
4. **Lateral Movement** - All 9 methods
5. **DCSync** - Dump domain hashes
6. **Golden/Silver Tickets** - Persistence
7. **Kerberoasting** - Service account hashes
8. **Persistence** - 10 techniques
9. **Data Exfil** - LAPS, GPP, BloodHound
10. **Defense Evasion** - Logs, AMSI, Defender
11. **Quick Wins** - Copy/paste ready commands
12. **Hash Cracking** - Hashcat commands
