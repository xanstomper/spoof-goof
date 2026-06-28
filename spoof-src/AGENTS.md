# SPOF — Red Team Opsec Launcher

## Purpose

`spoof` is a single-binary TUI (Terminal User Interface) that launches and manages all red team operational security protections. It chains VPN rotation, Tor routing, Docker isolation, honeypot detection, and anti-forensics into one command.

## Usage

### TUI Mode (Interactive Menu)
```bash
spoof
```
Opens a full-screen interactive menu. Navigate with arrow keys or j/k, press Enter to select, q to quit.

### CLI Mode (Direct Commands)
```bash
spoof up              # Launch full protected environment
spoof down            # Tear down everything
spoof status          # Show all protection status
spoof scan <target>   # Honeypot check before engaging
spoof vpn             # Rotate VPN IP
spoof wipe            # Clean traces (quick)
spoof wipe full       # Clean traces (full)
spoof wipe nuclear    # Nuclear option — complete cleanup
spoof help            # Show help
```

## What It Protects Against

| Threat | Protection |
|--------|-----------|
| IP exposure | VPN rotation (VPNGate 6000+ servers) + Tor |
| DNS leaks | dnscrypt-proxy with DNS-over-HTTPS |
| Honeypots | 8-point detection (banners, timing, SSL, behavioral) |
| Host fingerprinting | Docker isolation with dropped capabilities |
| MAC tracking | Automatic MAC randomization |
| Network scanning | UFW default-deny + iptables scan-proof rules |
| Kernel exploits | Sysctl hardening (redirects, SYN cookies, etc.) |
| Data leaks | Anti-forensics (quick/full/nuclear wipe modes) |
| SSH attacks | Hardened SSH (no root, no password, rate limiting) |
| Service fingerprinting | Unnecessary services disabled (BT, webcam, audio) |

## Architecture

```
spoof
 ├── VPN Layer      → vpncate auto-rotation (every 5min)
 ├── Tor Layer      → proxychains4 routing
 ├── Isolation      → Docker container (resource-limited, cap-dropped)
 ├── Detection      → honeypot-detect.sh + checkpot
 ├── Firewall       → UFW + iptables
 ├── DNS            → dnscrypt-proxy (Cloudflare/Google/Quad9)
 └── Cleanup        → anti-forensics.sh (3 modes)
```

## Integration with AI Agents

When an AI agent or tool needs to launch the red team environment:

```bash
# Full environment
spoof up

# Check if target is a honeypot
spoof scan 192.168.1.1

# Rotate identity mid-engagement
spoof vpn

# Clean up after engagement
spoof wipe full

# Tear down everything
spoof down
```

## File Locations

| File | Path |
|------|------|
| Binary | `/usr/local/bin/spoof` |
| Source | `~/spoof/` |
| Opsec scripts | `~/.opsec/` |
| Docker configs | `~/.opsec/vm/` |
| Reports | `~/.opsec/reports/` |
| Scope file | `~/.opsec/scope.txt` |
| Honeypot tool | `~/.opsec/tools/checkpot/` |

## Dependencies

- Docker (running)
- Tor (install: `sudo apt install tor`)
- proxychains4 (install: `sudo apt install proxychains4`)
- nmap (for honeypot detection)
- curl (for IP checks)
