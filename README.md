# SPOF — Red Team Opsec Suite

A complete operational security toolkit for red teaming. Single binary launcher (`spoof`) with TUI, Docker isolation, honeypot detection, VPN rotation, and anti-forensics.

## Quick Start

```bash
# Install
sudo cp spoof /usr/local/bin/spoof
sudo chmod +x /usr/local/bin/spoof

# Launch TUI
spoof

# Or use CLI
spoof up              # Full protected environment
spoof scan 1.2.3.4    # Honeypot check
spoof vpn             # Rotate IP
spoof wipe            # Clean traces
spoof down            # Tear down
```

## What's Included

| Layer | Script | Protection |
|-------|--------|-----------|
| Launcher | `spoof` (Go binary) | TUI + CLI for all commands |
| VPN | `vpn-rotate.sh` | VPNGate auto-rotation (6000+ servers) |
| Tor | `tor.sh` | Tor + proxychains4 routing |
| Isolation | `vm/docker-compose.yml` | Hardened Docker container |
| Honeypot | `honeypot-detect.sh` | 8-point detection scan |
| Firewall | `firewall.sh` | UFW + iptables hardening |
| DNS | `dns.sh` | dnscrypt-proxy DNS-over-HTTPS |
| MAC | `mac.sh` | Address randomization |
| Kernel | `harden.sh` | Sysctl + service lockdown |
| Anti-Forensics | `anti-forensics.sh` | Quick/full/nuclear wipe |
| Posture | `check.sh` | 25-point security audit |

## Requirements

- Linux (tested on Ubuntu/Mint)
- Docker
- nmap, curl, tor

## Usage

```bash
# First time setup
sudo bash ~/.opsec/install.sh

# Daily use
spoof                    # TUI menu
sudo bash ~/.opsec/check.sh  # Check posture

# Before engagement
spoof scan <target>      # Honeypot check
spoof vpn                # Rotate identity

# After engagement
spoof wipe               # Clean traces
spoof down               # Tear down
```

## File Structure

```
.opsec/
├── spoof                  # Go binary (TUI + CLI)
├── launch.sh              # Master launcher
├── vpn-rotate.sh          # VPNGate rotation
├── tor.sh                 # Tor + proxychains
├── isolate.sh             # Network namespace isolation
├── honeypot-detect.sh     # Honeypot detection
├── firewall.sh            # UFW + iptables
├── dns.sh                 # DNS leak protection
├── mac.sh                 # MAC randomization
├── harden.sh              # System hardening
├── anti-forensics.sh      # Trace cleanup
├── check.sh               # Posture validator
├── install.sh             # Full setup
├── scope.txt              # Authorized targets
├── authorization.md       # Engagement authorization
├── vm/
│   ├── Dockerfile         # Isolated container
│   └── docker-compose.yml # Container orchestration
└── tools/
    └── checkpot/          # Honeynet honeypot checker
```

## Spoof Binary

Built with Go + Bubbletea. Source in `~/spoof/`.

```bash
# Rebuild
cd ~/spoof && go build -ldflags="-s -w" -o spoof .
sudo cp spoof /usr/local/bin/spoof
```

## License

MIT
