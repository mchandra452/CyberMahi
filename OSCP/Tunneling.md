---
tags: [oscp, tunneling]
---
# Tunneling

## Tools & Syntax
- **ssh local port forward** - `ssh -L 8080:127.0.0.1:80 user@host`
- **ssh remote port forward** - `ssh -R 9001:127.0.0.1:9001 user@host`
- **chisel** - `chisel client <attacker>:8000 R:1080:socks`
- **plink** - `plink -ssh -l user -pw pass -R 1337:localhost:1337 host`
- **socat** - `socat TCP-LISTEN:9001,fork TCP:<IP>:9001`

## Tips
- Use SOCKS proxies with `proxychains` for pivoting.
- Combine tunnels to reach isolated networks.
- Remember to secure tunnels with authentication.
