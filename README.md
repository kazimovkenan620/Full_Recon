Recon Automation Workflow

This project integrates multiple reconnaissance, crawling, and scanning tools into a single automated workflow.
The goal is to collect subdomains, crawl endpoints, extract JavaScript routes, detect secrets, run vulnerability scans, and gather external intelligence — all while filtering noise and reducing false positives.

🚀 Integrated Tools
🔍 Discovery & Enumeration

subfinder — passive subdomain discovery

httpx — live host probing, status codes, redirects, content length

waybackurls — historical URL extraction

🌐 Crawling & URL Collection

katana — high-performance crawler with JavaScript awareness

gospider — supplementary crawler for deeper traversal

🧩 JavaScript Analysis

LinkFinder — extract JS endpoints

SecretFinder — detect secrets, API keys, tokens inside JS files

🛡 Security Scanning

Nuclei — vulnerability scanning (background execution supported)

ParamSpider — parameter discovery for SSRF/XSS/open redirect vectors

CIRT.sh — configuration and security checks

🧪 Fuzzing

ffuf — directory and file fuzzing for hidden paths

📡 External Intelligence

SecurityTrails API — domain intel & subdomain enumeration

Shodan API — internet-facing service discovery

Censys API — host fingerprinting and network enumeration

VirusTotal API — domain reputation and threat enrichment

📁 What the Workflow Produces

Subdomain lists

Active hosts (httpx)

Crawled URLs + historical URLs

Filtered endpoints (API, login, admin, config, etc.)

JS endpoints + secrets

Fuzzing results (ffuf)

Vulnerability scan results (Nuclei)

External intelligence reports

False positives are reduced using response-length and content-fingerprint filtering.

🎯 Goal

To generate clean, structured, and actionable recon data that can be used directly for penetration testing, bug bounty, or continuous asset monitoring.
