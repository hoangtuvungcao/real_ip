```
  ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
 ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                        --- TITAN GOD 2027 RELOADED ---
```

# OriginReaper

Cloudflare origin IP discovery tool. Written in Go. Single binary, no runtime dependencies.

Combines multiple recon vectors to find the real server IP behind Cloudflare-protected domains.

## Features

- **Shodan OSINT** — queries historical database for hostname and SSL certificate leaks
- **Crt.sh** — extracts subdomains from Certificate Transparency logs
- **HackerTarget** — harvests historical DNS records from passive database
- **Subdomain brute-force** — 24,000+ embedded wordlist, 500 concurrent workers
- **Subnet /24 scan** — scans entire IP block around discovered origins with uTLS verification
- **Timing side-channel** — measures RTT deltas to map network proximity to origin
- **uTLS Chrome mimicry** — spoofs JA3/JA4 TLS fingerprints to bypass WAF bot detection
- **Cloudflare auto-filter** — dynamically fetches and filters all CF IP ranges

## Install

Download binaries from [Releases](../../releases), or build from source:

```bash
git clone https://github.com/hoangtuvungcao/real_ip.git
cd real_ip

# linux
go build -o origin main.go

# windows (cross-compile)
GOOS=windows GOARCH=amd64 go build -o origin.exe main.go
```

Requires Go 1.21+

## Usage

```bash
./origin example.com
```

Select `7` for full auto recon (runs all vectors):

```
 ╔════════ TITAN GOD CONTROL CENTER ════════╗
 ║ 1. Open Source Intelligence (Shodan)     ║
 ║ 2. Deep OSINT (Crt.sh & HackerTarget)   ║
 ║ 3. Tactical Subdomain Extraction         ║
 ║ 4. Network Surveillance (Subnet /24)     ║
 ║ 5. Timing Side-Channel Analysis          ║
 ║ 6. Deep SSL Handshake (uTLS Chrome)      ║
 ║ 7. FULL AUTO RECON (ULTIMATE)            ║
 ║ 0. EXIT SYSTEM                           ║
 ╚══════════════════════════════════════════╝
```

## Example

```
 [PHASE 0.2] HackerTarget Historical DNS Recon
 └── [OK] Discovered 1 historical origins.

 [PHASE 1] Hyper-Massive Subdomain Recon (24447 keys)
 ⚡ [FOUND] 103.92.26.115 (Subdomain Leak)
 └── [DONE] Subdomain scan complete.

 [PHASE 2] Subnet Surveillance (CIDR /24)
 📡 Deep Scanning Segment: 103.92.26.0/24...

 ┌──────────────────── TARGET REPORT ────────────────────┐
 │ VERIFIED  │ 103.92.26.115   │ Subdomain Leak     │
 └──────────────────────────────────────────────────────┘
```

## How it works

The tool uses a round-robin UDP DNS cluster across 6 public resolvers (Cloudflare, Google, Quad9, OpenDNS) to prevent local DNS saturation during brute-force. The 24k wordlist is compiled into the binary via `go:embed`.

All discovered IPs are filtered against Cloudflare's published IP ranges. Only non-CF IPs are reported. uTLS handshake verification confirms the origin serves the target domain.

## Dependencies

- [fatih/color](https://github.com/fatih/color) — terminal colors
- [refraction-networking/utls](https://github.com/refraction-networking/utls) — TLS fingerprint spoofing

## Disclaimer

For authorized security testing only. Get permission before scanning any target.

## License

MIT
