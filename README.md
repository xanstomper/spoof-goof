# SPOF

operational security suite for red teaming. one binary, full protection.

i got tired of juggling 15 different tools, configs, and scripts every time i wanted to do an engagement safely. so i built this. everything i need to stay hidden, detect honeypots, rotate identities, and clean up after myself — wrapped into a single binary with a TUI.

## what this actually does

SPOF chains together multiple layers of protection so you don't have to think about them individually. when you run `spoof`, it:

1. spins up VPN rotation through VPNGate (6000+ free servers, auto-rotates every 5 minutes)
2. routes traffic through Tor via proxychains4
3. drops you into an isolated Docker container with all your tools (nmap, hydra, john, socat, impacket, scapy, etc.)
4. runs honeypot detection against your target before you touch it
5. hardens your kernel, firewall, SSH, and kills services that leak your identity
6. gives you anti-forensics to wipe everything when you're done

the whole thing is controlled through a single `spoof` command — either a TUI menu or direct CLI flags.

## why i built it

every opsec guide i followed was scattered across 20 blog posts and reddit threads. "use tor for this, vpn for that, macchanger here, firewall there." nobody put it all together in one place that actually works out of the box.

i'm not a corporation. i'm one person who needed this to work, so i built it to work. no telemetry, no accounts, no bullshit. just tools that do what they say.

## tools included

| script | what it does |
|--------|-------------|
| `spoof` | go binary with bubbletea TUI. single entry point for everything |
| `launch.sh` | master launcher — chains VPN, Tor, Docker, and honeypot detection |
| `vpn-rotate.sh` | pulls VPNGate server list, auto-rotates every 5 min, picks fastest servers |
| `tor.sh` | installs + configures Tor + proxychains4 |
| `honeypot-detect.sh` | 8-point scan: port analysis, service fingerprinting, timing, TTL, HTTP headers, SSL certs, behavioral analysis |
| `firewall.sh` | UFW default-deny + iptables scan-proof rules + sysctl hardening |
| `dns.sh` | dnscrypt-proxy with Cloudflare/Google/Quad9 DNS-over-HTTPS |
| `mac.sh` | MAC address randomization with auto-restore and boot service |
| `harden.sh` | kernel module blacklisting, SSH lockdown, service disabling, audit logging, file integrity monitoring |
| `anti-forensics.sh` | three modes: quick (session traces), full (deep clean), nuclear (everything) |
| `check.sh` | 25-point security posture validator — tells you exactly what's exposed |
| `isolate.sh` | network namespace isolation for running tools completely separately from host |
| `install.sh` | one-command setup for the entire suite |

## how the honeypot detection works

this is the part i'm most proud of. before you engage a target, SPOF runs an 8-point scan to figure out if you're walking into a trap:

- **port scanning** — finds open ports, checks for SSH honeypot banners (cowrie, kippo, dionaea, etc.)
- **service fingerprinting** — detects mixed OS services (windows + linux on same box = red flag)
- **timing analysis** — measures ping response variance. suspiciously consistent times = virtualized environment
- **TTL analysis** — checks hop count. unusual TTL values can indicate proxied/virtualized targets
- **HTTP header analysis** — looks for honeypot server headers, unrealistic IIS versions, missing security headers
- **SSL/TLS analysis** — self-signed certs, target-matching subjects, short-lived certificates
- **behavioral analysis** — tests unlikely ports (31337, 4444, 6666), checks for tarpitting
- **risk scoring** — aggregates findings into a 0-100 score with clear PASS/WARN/FAIL verdict

it also integrates with checkpot from the Honeynet Project for deeper honeypot configuration analysis.

## the isolation model

the Docker container runs with serious restrictions:

```
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
cap_add:
  - NET_RAW        (nmap needs this)
  - NET_ADMIN       (network tools)
  - SYS_PTRACE      (debugging)
```

memory capped at 4GB, CPU capped at 2 cores, DNS forced through Tor, all traffic isolated on its own bridge network. even if something goes wrong inside the container, your host machine stays clean.

the container has: nmap, hydra, john, socat, impacket, scapy, python3, curl, wget, nikto, ffuf, sqlmap, whatweb, tcpdump, tshark, and more.

## the spoof binary

built in Go with bubbletea for the TUI. static binary, no dependencies, ~3MB.

```
spoof              # launch TUI menu
spoof up           # start everything
spoof down         # tear down
spoof status       # check what's running
spoof scan 1.2.3.4 # honeypot check
spoof vpn          # rotate IP
spoof wipe         # clean traces (quick)
spoof wipe full    # deep clean
spoof wipe nuclear # nuke everything
```

the TUI uses arrow keys / j/k to navigate, enter to select, q to quit. each menu item shows what it does.

## installation

```bash
git clone https://github.com/xanstomper/spof.git
cd spof

# install the binary
sudo cp spoof-bin /usr/local/bin/spoof
sudo chmod +x /usr/local/bin/spoof

# run the full setup (installs tor, proxychains, macchanger, configures everything)
sudo bash install.sh

# check your posture
sudo bash check.sh
```

or just run individual scripts as needed — they all work standalone.

## kernel hardening

SPOF applies these sysctl parameters on setup:

```
net.ipv4.conf.all.accept_redirects = 0      # no ICMP redirects (MITM prevention)
net.ipv4.conf.all.send_redirects = 0         # don't send redirects
net.ipv4.conf.all.rp_filter = 1             # strict reverse path filtering
net.ipv4.tcp_syncookies = 1                 # SYN flood protection
net.ipv4.conf.all.log_martians = 1          # log spoofed packets
net.ipv6.conf.all.disable_ipv6 = 1          # kill IPv6 (reduces attack surface)
net.ipv6.conf.all.accept_redirects = 0      # no IPv6 redirects
```

## anti-forensics

three modes depending on how paranoid you are:

**quick** — wipes shell history, system logs, browser caches, package manager caches, scan reports, Docker container data. takes a few seconds.

**full** — everything in quick plus: auth logs, syslog, kernel logs, dmesg, audit logs, Tor logs, VPN logs, /tmp, /dev/shm, DNS cache, ARP cache, MAC rotation.

**nuclear** — everything in full plus: Docker system prune, all .log files system-wide, swap wipe recommendation, complete memory flush.

## what's NOT included (and why)

- no credential stuffing tools (that's not what this is for)
- no phishing kits (wrong tool for that)
- no custom malware (this is defense and recon, not offense)
- no paid VPN requirements (VPNGate is free and academic)

this is about protecting yourself while doing authorized security work. not about doing anything illegal.

## scope

always add your authorized targets to `scope.txt` before engaging:

```
# scope.txt
192.168.1.0/24
10.0.0.5
target.example.com
```

the posture checker will warn you if you're scanning targets outside your scope.

## about me

just a guy who got into security because i was tired of being the one getting owned. started withCTFs, moved into bug bounties, now i do red team engagements when i can find the time. built this because i needed it and nobody else had put it all together.

i'm not a company. i don't have a team. this is one person's collection of scripts and tools that i actually use in the field. if it works for you, cool. if it doesn't, fix it and submit a PR.

find me on github: [xanstomper](https://github.com/xanstomper)

## contributing

PRs welcome. if you find a bug, open an issue. if you have a better way to do something, show me. if you want to add a new detection method to the honeypot scanner, even better.

just don't submit anything that's用于恶意目的. this tool is for defensive security and authorized red teaming only.

## license

MIT. use it however you want. just don't blame me if you do something stupid with it.
