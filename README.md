<p align="center">
  <img src="https://img.shields.io/badge/GO-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blueviolet?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Edition-TITAN%20GOD%202027-ff6600?style=for-the-badge"/>
</p>

```
  ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
 ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                        --- TITAN GOD 2027 RELOADED ---
```

# OriginReaper — Titan God Edition 2027

> 🔥 **The most advanced Cloudflare origin IP discovery tool.** Built in pure Go with zero external dependencies at runtime. Single binary, maximum firepower.

OriginReaper is a high-performance reconnaissance framework designed to uncover the **real origin IP address** behind Cloudflare-protected domains using multi-vector OSINT intelligence, subdomain brute-forcing, timing side-channel analysis, and uTLS browser mimicry.

---

## ⚡ Features

| Module | Description |
|---|---|
| 🕵️ **Shodan OSINT** | Queries Shodan's historical database for hostname & SSL certificate leaks |
| 📜 **Crt.sh Transparency** | Extracts subdomains from global Certificate Transparency logs |
| 🌐 **HackerTarget DNS** | Harvests historical DNS records from HackerTarget's passive database |
| 🔍 **Subdomain Brute-Force** | 24,000+ embedded wordlist with 500 concurrent goroutine workers |
| 📡 **Subnet /24 Scan** | Scans the entire IP block around discovered origins with uTLS verification |
| ⏱️ **Timing Side-Channel** | Measures millisecond RTT deltas to map network proximity to the origin |
| 🛡️ **uTLS Chrome Mimicry** | Spoofs JA3/JA4 TLS fingerprints (Chrome browser) to bypass WAF bot detection |
| ☁️ **Cloudflare Auto-Filter** | Dynamically fetches and filters all Cloudflare IP ranges (IPv4 + IPv6) |

---

## 🚀 Quick Start

### Pre-built Binaries

Download from [Releases](../../releases):

```bash
# Linux
chmod +x origin
./origin <domain>

# Windows
origin.exe <domain>
```

### Build from Source

```bash
# Requirements: Go 1.21+
git clone https://github.com/hoangtuvungcao/real_ip.git
cd real_ip

# Linux
go build -o origin main.go

# Windows (cross-compile from Linux)
GOOS=windows GOARCH=amd64 go build -o origin.exe main.go
```

---

## 🎯 Usage

```bash
./origin example.com
```

The interactive menu will appear:

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

> **💡 Recommended:** Select **`7`** for FULL AUTO RECON — executes all reconnaissance vectors in sequence for maximum coverage.

### Example Output

```
 ┌── [ PHASE 0 ] Shodan Intelligence Leak Search
 └── No historical data found in Shodan.

 ┌── [ PHASE 0.1 ] Crt.sh Certificate Transparency Recon
 └── [OK] Discovered 2 potential origins via Crt.sh

 ┌── [ PHASE 0.2 ] HackerTarget Historical DNS Recon
 └── [OK] Discovered 1 historical origins.

 ┌── [ PHASE 1 ] Hyper-Massive Subdomain Recon (24447 keys)
 ⚡ [FOUND] 103.92.26.115 (Subdomain Leak)
 └── [DONE] Subdomain scan complete.

 ┌── [ PHASE 2 ] Subnet Surveillance (CIDR /24)
 📡 Deep Scanning Segment: 103.92.26.0/24...

 ┌── [ PHASE 3 ] Timing Side-Channel Delta Analysis

 ┌──────────────────── TARGET REPORT ────────────────────┐
 │ VERIFIED  │ 103.92.26.115   │ Subdomain Leak     │
 └──────────────────────────────────────────────────────┘
```

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │   OriginReaper Engine    │
                    │    (Single Go Binary)    │
                    └────────────┬────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
    ┌─────▼─────┐          ┌─────▼─────┐          ┌─────▼─────┐
    │   OSINT   │          │  DNS BF   │          │  Network  │
    │  Layer    │          │  Engine   │          │  Probing  │
    ├───────────┤          ├───────────┤          ├───────────┤
    │ Shodan    │          │ 500 Gortn │          │ Subnet/24 │
    │ Crt.sh    │          │ 6 Public  │          │ uTLS SNI  │
    │ HTarget   │          │ DNS Nodes │          │ Timing Δ  │
    └─────┬─────┘          └─────┬─────┘          └─────┬─────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Cloudflare IP Filter   │
                    │  (Dynamic IPv4/v6)      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   TARGET REPORT         │
                    │   VERIFIED / POTENTIAL   │
                    └─────────────────────────┘
```

### DNS Resolution Cluster

The subdomain scanner uses a **round-robin UDP DNS cluster** distributed across 6 public resolvers to prevent local DNS saturation:

| Resolver | Provider |
|---|---|
| `1.1.1.1` | Cloudflare DNS |
| `1.0.0.1` | Cloudflare DNS (Secondary) |
| `8.8.8.8` | Google Public DNS |
| `8.8.4.4` | Google Public DNS (Secondary) |
| `9.9.9.9` | Quad9 |
| `208.67.222.222` | OpenDNS |

---

## 📦 Standalone Binary

The entire 24,000+ subdomain wordlist is **compiled directly into the binary** using Go's `embed` package. No external files needed — just the single executable.

```go
//go:embed subdomains.txt
var wordlist embed.FS
```

---

## 🔧 Dependencies

| Package | Purpose |
|---|---|
| [`github.com/fatih/color`](https://github.com/fatih/color) | Terminal colors & styled output |
| [`github.com/refraction-networking/utls`](https://github.com/refraction-networking/utls) | TLS fingerprint spoofing (JA3/JA4) |

---

## ⚠️ Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning any target. The author assumes no liability for misuse of this software.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Built with 🔥 by the OriginReaper Team — Titan God 2027</b>
</p>
