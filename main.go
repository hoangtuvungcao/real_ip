package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	utls "github.com/refraction-networking/utls"
)

//go:embed subdomains.txt
var wordlist embed.FS

const (
	CloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"
	CloudflareIPv6URL = "https://www.cloudflare.com/ips-v6"
	Workers           = 500
	Timeout           = 3 * time.Second
	ShodanAPIKey      = "aCfjD5pzHZv60uzUXbdNf4SCTExJUt0s"
)

var (
	totalTested  int64
	dnsErrors    int64
	DNSResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "1.0.0.1:53", "8.8.4.4:53", "208.67.222.222:53"}
	cyan         = color.New(color.FgCyan).Add(color.Bold)
	green        = color.New(color.FgGreen).Add(color.Bold)
	yellow       = color.New(color.FgYellow).Add(color.Bold)
	red          = color.New(color.FgRed).Add(color.Bold)
	magenta      = color.New(color.FgMagenta).Add(color.Bold)
	blue         = color.New(color.FgBlue).Add(color.Bold)
	white        = color.New(color.FgWhite).Add(color.Bold)
	hiGreen      = color.New(color.FgHiGreen).Add(color.Bold)
	hiRed        = color.New(color.FgHiRed).Add(color.Bold)
	hiMagenta    = color.New(color.FgHiMagenta).Add(color.Bold)
	hiYellow     = color.New(color.FgHiYellow).Add(color.Bold)

	vitalStyle   = color.New(color.FgHiGreen).Add(color.Underline).Add(color.Bold)
	headerStyle  = color.New(color.FgHiMagenta).Add(color.Bold)
	bracketStyle = color.New(color.FgHiWhite).Add(color.Bold)
)

type ShodanResponse struct {
	Matches []struct {
		IPStr string `json:"ip_str"`
		Data  string `json:"data"`
	} `json:"matches"`
	Total int `json:"total"`
}

type OriginCandidate struct {
	IP        string
	Vector    string
	Latency   time.Duration
	Verified  bool
	Confirmed bool
	Details   string
}

type OriginReaper struct {
	Domain       string
	Subdomains   []string
	CFNetworks   []*net.IPNet
	Results      map[string]*OriginCandidate
	FaviconHash  string
	DOMStructure string
	CFLatency    time.Duration
	mu           sync.Mutex
}

func NewOriginReaper(domain string) *OriginReaper {
	return &OriginReaper{
		Domain:  domain,
		Results: make(map[string]*OriginCandidate),
	}
}

func (r *OriginReaper) IsNoiseIP(ipStr string) bool {
	ptrs, _ := net.LookupAddr(ipStr)
	for _, ptr := range ptrs {
		ptr = strings.ToLower(ptr)
		noiseProviders := []string{"protonmail", "google", "outlook", "microsoft", "amazon", "aws", "akamai", "fastly", "cloudflare", "sucuri", "incapsula", "mimecast"}
		for _, noise := range noiseProviders {
			if strings.Contains(ptr, noise) {
				return true
			}
		}
	}
	return false
}

func (r *OriginReaper) FetchCloudflareIPs() {
	cyan.Print(" ┌── ")
	white.Print("Fetching Cloudflare Networks...")
	fmt.Println()
	urls := []string{CloudflareIPv4URL, CloudflareIPv6URL}
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			r.CFNetworks = append(r.CFNetworks, ipnet)
		}
	}
	green.Printf(" └── [OK] Loaded %d Cloudflare ranges\n", len(r.CFNetworks))
}

func (r *OriginReaper) IsCloudflareIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, nr := range r.CFNetworks {
		if nr.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *OriginReaper) LoadSubdomains() {
	data, err := wordlist.ReadFile("subdomains.txt")
	if err != nil {
		r.Subdomains = []string{"mail", "ftp", "api", "dev", "webmail"}
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub != "" {
			r.Subdomains = append(r.Subdomains, sub)
		}
	}
}

func (r *OriginReaper) AddCandidate(ip, vector string) bool {
	if r.IsCloudflareIP(ip) {
		return false
	}
	if r.IsNoiseIP(ip) {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.Results[ip]; !ok {
		green.Printf("\x1b[2K\r ⚡ [FOUND] %s (%s)\n", ip, vector)
		r.Results[ip] = &OriginCandidate{IP: ip, Vector: vector}
		return true
	}
	return false
}

func (r *OriginReaper) ShodanOSINT() {
	headerStyle.Println("\n ┌── [ PHASE 0 ] Shodan Intelligence Leak Search")
	query := fmt.Sprintf("hostname:%s", r.Domain)
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", ShodanAPIKey, query)

	c := &http.Client{Timeout: Timeout}
	res, err := c.Get(url)
	if err != nil {
		return
	}
	defer res.Body.Close()

	var data ShodanResponse
	json.NewDecoder(res.Body).Decode(&data)

	if data.Total > 0 {
		found := 0
		for _, m := range data.Matches {
			if r.AddCandidate(m.IPStr, "Shodan OSINT") {
				found++
			}
		}
		if found > 0 {
			hiGreen.Printf(" └── [OK] %d non-CF origins via Shodan.\n", found)
		} else {
			yellow.Println(" └── Shodan data found, but all IPs are Cloudflare.")
		}
	} else {
		yellow.Println(" └── No historical data found in Shodan.")
	}
}

func (r *OriginReaper) SearchCrtSh() {
	headerStyle.Println("\n ┌── [ PHASE 0.1 ] Certificate Transparency Recon")

	// Try crt.sh JSON API first
	crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", r.Domain)
	client := &http.Client{Timeout: 10 * time.Second}

	seen := make(map[string]bool)
	found := 0

	resp, err := client.Get(crtURL)
	if err == nil && resp.StatusCode == 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var results []struct {
			NameValue  string `json:"name_value"`
			CommonName string `json:"common_name"`
		}
		if json.Unmarshal(bodyBytes, &results) == nil {
			for _, res := range results {
				for _, sub := range strings.Split(res.NameValue, "\n") {
					sub = strings.TrimSpace(sub)
					if sub == "" || strings.Contains(sub, "*") || seen[sub] {
						continue
					}
					seen[sub] = true
					ips, err := net.LookupHost(sub)
					if err == nil {
						for _, ip := range ips {
							if r.AddCandidate(ip, "Crt.sh Leak") {
								found++
							}
						}
					}
				}
			}
		}
	} else {
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Fallback: CertSpotter API (free, no auth)
	if found == 0 {
		spotURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", r.Domain)
		resp2, err := client.Get(spotURL)
		if err == nil && resp2.StatusCode == 200 {
			bodyBytes, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			var certs []struct {
				DNSNames []string `json:"dns_names"`
			}
			if json.Unmarshal(bodyBytes, &certs) == nil {
				for _, cert := range certs {
					for _, name := range cert.DNSNames {
						name = strings.TrimSpace(name)
						if name == "" || strings.Contains(name, "*") || seen[name] {
							continue
						}
						seen[name] = true
						ips, err := net.LookupHost(name)
						if err == nil {
							for _, ip := range ips {
								if r.AddCandidate(ip, "CertSpotter") {
									found++
								}
							}
						}
					}
				}
			}
		} else {
			if resp2 != nil {
				resp2.Body.Close()
			}
		}
	}

	if found == 0 {
		yellow.Println(" └── No CT data found (crt.sh + CertSpotter).")
	} else {
		hiGreen.Printf(" └── [OK] Discovered %d origins via CT logs.\n", found)
	}
}

func (r *OriginReaper) SearchHackerTarget() {
	headerStyle.Println("\n ┌── [ PHASE 0.2 ] HackerTarget Historical DNS Recon")
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", r.Domain)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		red.Println(" └── [!] HackerTarget connection failed.")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(bodyBytes)), "\n")

	found := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			ip := strings.TrimSpace(parts[1])
			if ip != "" {
				if r.AddCandidate(ip, "HackerTarget") {
					found++
				}
			}
		}
	}

	if found == 0 {
		fmt.Println(" └── No historical IP leaks found via HackerTarget.")
	} else {
		hiGreen.Printf(" └── [OK] Discovered %d historical origins.\n", found)
	}
}

func (r *OriginReaper) ResolveSubdomains() {
	headerStyle.Printf("\n ┌── [ PHASE 1 ] Hyper-Massive Subdomain Recon (%d keys)\n", len(r.Subdomains))
	var wg sync.WaitGroup
	jobs := make(chan string, len(r.Subdomains))
	atomic.StoreInt64(&totalTested, 0)

	for i := 0; i < Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Round-robin public DNS to avoid local DNS saturation
			addr := DNSResolvers[id%len(DNSResolvers)]
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", addr)
				},
			}
			for sub := range jobs {
				target := fmt.Sprintf("%s.%s", sub, r.Domain)
				ctx, cancel := context.WithTimeout(context.Background(), Timeout)
				ips, err := resolver.LookupHost(ctx, target)
				cancel()

				current := atomic.AddInt64(&totalTested, 1)
				if current%500 == 0 {
					pct := (float64(current) / float64(len(r.Subdomains))) * 100
					fmt.Printf("\r ⚡ Progress: [ %.1f%% ] %s  ", pct, target)
				}

				if err == nil {
					for _, ip := range ips {
						r.AddCandidate(ip, "Subdomain Leak")
					}
				}
			}
		}(i)
	}

	for _, s := range r.Subdomains {
		jobs <- s
	}
	close(jobs)
	wg.Wait()
	fmt.Printf("\r └── [DONE] Subdomain scan complete.                                   \n")
}

func (r *OriginReaper) VerifyUTLS(ip string) bool {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	defer conn.Close()

	uconn := utls.UClient(conn, &utls.Config{ServerName: r.Domain, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if uconn.Handshake() != nil {
		return false
	}

	state := uconn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		for _, n := range state.PeerCertificates[0].DNSNames {
			if strings.Contains(n, r.Domain) {
				vitalStyle.Printf("\n 💎 [DOMINANT MATCH] SNI Validated: %sカバー: %s\n", ip, n)
				r.mu.Lock()
				if existing, ok := r.Results[ip]; ok {
					if !existing.Verified {
						existing.Verified = true
						existing.Details = "SNI_VERIFIED"
					}
				} else {
					r.Results[ip] = &OriginCandidate{IP: ip, Vector: "SNI Verified", Verified: true, Details: "SNI_VERIFIED"}
				}
				r.mu.Unlock()
				return true
			}
		}
	}
	return false
}

func (r *OriginReaper) TimingAnalysis() {
	headerStyle.Println("\n ┌── [ PHASE 3 ] Timing Side-Channel Delta Analysis")
	r.mu.Lock()
	var candidates []*OriginCandidate
	for _, c := range r.Results {
		candidates = append(candidates, c)
	}
	r.mu.Unlock()

	for _, c := range candidates {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.IP, "443"), 3*time.Second)
		if err == nil {
			c.Latency = time.Since(start)
			conn.Close()
			diff := c.Latency - r.CFLatency
			if diff < 0 {
				diff = -diff
			}
			fmt.Printf(" └── IP: %-15s | RTT: %-12s | Δ: %s\n", c.IP, c.Latency, diff)
		}
	}
}

func (r *OriginReaper) HostHeaderVerify() {
	headerStyle.Println("\n ┌── [ PHASE 4 ] HTTP Host Header Origin Confirmation")
	r.mu.Lock()
	var ips []string
	for ip := range r.Results {
		ips = append(ips, ip)
	}
	r.mu.Unlock()

	if len(ips) == 0 {
		yellow.Println(" └── No candidates to verify.")
		return
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	confirmed := 0
	for _, ip := range ips {
		// Try HTTPS first, then HTTP
		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s/", scheme, ip)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				continue
			}
			req.Host = r.Domain
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			size := len(bodyBytes)
			title := ""
			re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
			matches := re.FindStringSubmatch(string(bodyBytes))
			if len(matches) > 1 {
				title = strings.TrimSpace(matches[1])
				// Truncate title if too long
				if len(title) > 30 {
					title = title[:27] + "..."
				}
			}

			code := resp.StatusCode
			if code == 200 || code == 301 || code == 302 || code == 403 {
				titleStr := ""
				if title != "" {
					titleStr = fmt.Sprintf(" | Title: %s", title)
				}
				vitalStyle.Printf(" └── [CONFIRMED] %s -> HTTP %d (%s) Host: %s%s [Size: %dB]\n", ip, code, scheme, r.Domain, titleStr, size)
				r.mu.Lock()
				if c, ok := r.Results[ip]; ok {
					c.Confirmed = true
					c.Verified = true
					if title != "" {
						c.Details = fmt.Sprintf("HTTP %d | %s", code, title)
					} else {
						c.Details = fmt.Sprintf("HTTP %d %s", code, scheme)
					}
				}
				r.mu.Unlock()
				confirmed++
				break
			} else {
				fmt.Printf(" └── %s -> HTTP %d (%s) - not a match\n", ip, code, scheme)
			}
		}
	}

	if confirmed == 0 {
		yellow.Println(" └── No IPs confirmed via Host Header.")
	} else {
		hiGreen.Printf(" └── [OK] %d origin(s) CONFIRMED via direct HTTP.\n", confirmed)
	}
}

func (r *OriginReaper) SubnetScan() {
	headerStyle.Println("\n ┌── [ PHASE 2 ] Subnet Surveillance (CIDR /24)")
	r.mu.Lock()
	var seeds []string
	for ip := range r.Results {
		seeds = append(seeds, ip)
	}
	r.mu.Unlock()

	var wg sync.WaitGroup
	scanned := make(map[string]bool)
	for _, s := range seeds {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			continue
		}
		sb := ip.Mask(net.CIDRMask(24, 32)).String()
		if scanned[sb] {
			continue
		}
		scanned[sb] = true
		fmt.Printf(" 📡 Deep Scanning Segment: %s/24...\n", sb)
		for i := 1; i < 255; i++ {
			tip := net.IPv4(ip[0], ip[1], ip[2], byte(i)).String()
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				if r.VerifyUTLS(t) {
					r.mu.Lock()
					if _, ok := r.Results[t]; !ok {
						r.Results[t] = &OriginCandidate{IP: t, Vector: "Subnet Discovery", Verified: true}
					}
					r.mu.Unlock()
				}
			}(tip)
		}
	}
	wg.Wait()
}

func printBanner() {
	fmt.Print("\n")
	hiMagenta.Println("  ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ ")
	hiMagenta.Println(" ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗")
	hiMagenta.Println(" ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝")
	hiMagenta.Println(" ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗")
	hiMagenta.Println(" ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║")
	hiMagenta.Println("  ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝")
	hiYellow.Println("                           --- TITAN GOD 2027 RELOADED ---")
	fmt.Println()
}

func main() {
	// Enable Windows Virtual Terminal Sequences and UTF-8
	if runtime.GOOS == "windows" {
		color.NoColor = false // Force colors on Windows
	}

	printBanner()
	if len(os.Args) < 2 {
		red.Println(" [!] ERR: Missing domain. Usage: ./origin <domain>")
		return
	}
	domain := os.Args[1]
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.Split(domain, "/")[0]
	domain = strings.TrimPrefix(domain, "www.")

	reaper := NewOriginReaper(domain)
	reaper.FetchCloudflareIPs()
	reaper.LoadSubdomains()

	cyan.Printf(" [*] Host Profile: %s\n", domain)
	start := time.Now()
	_, err := http.Get("https://" + domain)
	if err == nil {
		reaper.CFLatency = time.Since(start)
		cyan.Printf(" [*] Network Origin Context (Cloudflare Edge): %v\n", reaper.CFLatency)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		headerStyle.Println("\n ╔════════ TITAN GOD CONTROL CENTER ════════╗")
		fmt.Printf(" ║ %-40s ║\n", "1. Open Source Intelligence (Shodan)")
		fmt.Printf(" ║ %-40s ║\n", "2. Deep OSINT (Crt.sh & HackerTarget)")
		fmt.Printf(" ║ %-40s ║\n", "3. Tactical Subdomain Extraction")
		fmt.Printf(" ║ %-40s ║\n", "4. Network Surveillance (Subnet /24)")
		fmt.Printf(" ║ %-40s ║\n", "5. Timing Side-Channel Analysis")
		fmt.Printf(" ║ %-40s ║\n", "6. Deep SSL Handshake (uTLS Chrome)")
		fmt.Printf(" ║ %-40s ║\n", "7. FULL AUTO RECON (ULTIMATE)")
		fmt.Printf(" ║ %-40s ║\n", "0. EXIT SYSTEM")
		headerStyle.Println(" ╚══════════════════════════════════════════╝")
		fmt.Print(" ❯ Select Operation: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			reaper.ShodanOSINT()
		case "2":
			reaper.SearchCrtSh()
			reaper.SearchHackerTarget()
		case "3":
			reaper.ResolveSubdomains()
		case "4":
			reaper.SubnetScan()
		case "5":
			reaper.TimingAnalysis()
		case "6":
			headerStyle.Println("\n ┌── [ PHASE 5 ] Advanced SSL Handshake Validation")
			r := reaper.Results
			for ip := range r {
				reaper.VerifyUTLS(ip)
			}
		case "7":
			reaper.ShodanOSINT()
			reaper.SearchCrtSh()
			reaper.SearchHackerTarget()
			reaper.ResolveSubdomains()
			reaper.SubnetScan()
			reaper.TimingAnalysis()
			r := reaper.Results
			for ip := range r {
				reaper.VerifyUTLS(ip)
			}
			reaper.HostHeaderVerify()
		case "0":
			return
		}

		if len(reaper.Results) > 0 {
			white.Println("\n ┌──────────────────── TARGET REPORT ────────────────────┐")
			for ip, c := range reaper.Results {
				statusTag := "POTENTIAL "
				if c.Confirmed {
					statusTag = "CONFIRMED "
				} else if c.Verified {
					statusTag = "VERIFIED  "
				}
				detail := c.Vector
				if c.Details != "" {
					detail = c.Details
				}
				line := fmt.Sprintf(" │ %s │ %-15s │ %-18s │", statusTag, ip, detail)
				if c.Confirmed {
					hiGreen.Println(line)
				} else if c.Verified {
					cyan.Println(line)
				} else {
					hiYellow.Println(line)
				}
			}
			white.Println(" └──────────────────────────────────────────────────────┘")
		}
	}
}
