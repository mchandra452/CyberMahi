---
tags: [oscp, active-directory]
---
# Active Directory

## Tools & Syntax
- **crackmapexec** - `crackmapexec smb <IP> -u user -p pass`
- **evil-winrm** - `evil-winrm -i <IP> -u user -p pass`
- **GetUserSPNs.py** - `GetUserSPNs.py domain/user:pass -dc-ip <IP>`
- **secretsdump.py** - `secretsdump.py domain/user:pass@<IP>`
- **bloodhound-python** - `bloodhound-python -u user -p pass -ns <IP> -d domain -c all`

## Tips
- Enumerate Kerberoastable accounts.
- Leverage SMB signing settings.
- Ingest BloodHound data to visualize paths.
