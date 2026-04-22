# ActPass - Active & Passive Reconnaissance Framework

ActPass is a Bash-based reconnaissance framework for performing both passive and active information gathering against a target domain. It is designed for quick enumeration during recon phases and provides output with automatic logging of results.

## Features

- DNS record enumeration
  - A
  - AAAA
  - NS
  - MX
  - TXT
  - SOA
  - CNAME
  - SRV
  - CAA
- WHOIS lookup
- SPF / DMARC / DKIM checks
- SSL/TLS certificate inspection
- Geo-IP and ASN lookup
- Wayback Machine historical URL collection
- Certificate Transparency subdomain enumeration via crt.sh
- DNS zone transfer attempts
- Web technology discovery
- HTTP header analysis
- robots.txt and sitemap.xml checks
- Automatic result logging

## Script Overview

The script performs reconnaissance in two categories:

### Passive Reconnaissance
Passive checks collect publicly available information without directly interacting heavily with the target infrastructure.

Included passive modules:
- DNS reconnaissance
- WHOIS lookup
- Email security records (SPF, DMARC, DKIM)
- SSL/TLS certificate analysis
- Geo-IP / ASN lookup
- Wayback Machine URL harvesting
- crt.sh subdomain discovery

### Active Reconnaissance
Active checks directly interact with the target and may generate logs on the target side.

Included active modules:
- DNS zone transfer testing
- Web technology fingerprinting
- HTTP/HTTPS response header inspection
- Redirect behavior analysis
- robots.txt retrieval
- sitemap.xml existence check

## Requirements

Make sure the following tools are installed:

### Required
- bash
- dig
- curl
- openssl
- whois
- python3

### Optional but Recommended
- whatweb
- testssl.sh
- theHarvester

## Installation

Clone or download the script:

```bash
git clone https://github.com/tkMONK/ActPass.git
cd ActPass
chmod +x actpass.sh

<img width="1373" height="924" alt="image" src="https://github.com/user-attachments/assets/0eeaeba4-2f04-467f-9254-8d2fb393808e" />

