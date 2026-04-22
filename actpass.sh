#!/bin/bash
# =============================================================================
#   actpass.sh - Active & Passive Reconnaissance Framework
#   Author: Security Researcher
#   Usage: sudo bash actpass.sh
# =============================================================================

# ──────────────────────────────────────────────────────────────────────────────
# COLORS
# ──────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
RESET='\033[0m'

# ──────────────────────────────────────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────────────────────────────────────
banner(){
    clear
    echo -e "${CYAN}"
    echo '  ██████╗  ██████╗████████╗██████╗  █████╗ ███████╗███████╗'
    echo '  ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝'
    echo '  ███████║██║        ██║   ██████╔╝███████║███████╗███████╗ '
    echo '  ██╔══██║██║        ██║   ██╔═══╝ ██╔══██║╚════██║╚════██║'
    echo '  ██║  ██║╚██████╗   ██║   ██║     ██║  ██║███████║███████║'
    echo '  ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝'
    echo -e "${RESET}"
    echo -e "${WHITE}       Active & Passive Reconnaissance Framework${RESET}"
    echo -e "${YELLOW}       ─────────────────────────────────────────${RESET}"
    echo -e "${MAGENTA}       [~] Recon. Enumerate. Dominate.${RESET}"
    echo -e "${YELLOW}       ─────────────────────────────────────────${RESET}"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────────────────────────────────────
setup_log(){
    LOG_DIR="./recon_results"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${domain}_$(date +%Y%m%d_%H%M%S).log"
    echo -e "${GREEN}[+] Results will be saved to: ${WHITE}$LOG_FILE${RESET}"
    echo ""
    exec > >(tee -a "$LOG_FILE") 2>&1
}

# ──────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ──────────────────────────────────────────────────────────────────────────────
section(){
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║${WHITE}  $1${YELLOW}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${RESET}"
}

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[-]${RESET} $1"; }
result()  { echo -e "${WHITE}    $1${RESET}"; }

check_tool(){
    if ! command -v "$1" &>/dev/null; then
        warn "Tool not found: ${BOLD}$1${RESET} — skipping this check."
        return 1
    fi
    return 0
}

divider(){ echo -e "${BLUE}  ──────────────────────────────────────────────────────${RESET}"; }

# ──────────────────────────────────────────────────────────────────────────────
# DNS RECON (PASSIVE)
# ──────────────────────────────────────────────────────────────────────────────
dns_recon(){
    local record_type=$1
    local res
    res=$(dig +short "$record_type" "$domain" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$res" ]; then
        echo "$res"
    else
        echo "No $record_type records found"
    fi
}

run_dns_recon(){
    section "DNS RECONNAISSANCE (Passive)"

    for rtype in A AAAA NS MX TXT SOA CNAME SRV CAA; do
        info "Querying $rtype records..."
        res=$(dns_recon "$rtype")
        result "$rtype → $res"
        divider
    done
}

# ──────────────────────────────────────────────────────────────────────────────
# WHOIS (PASSIVE)
# ──────────────────────────────────────────────────────────────────────────────
run_whois(){
    section "WHOIS LOOKUP (Passive)"
    if check_tool whois; then
        info "Running WHOIS on $domain ..."
        whois "$domain" 2>/dev/null | grep -Ei \
            'Registrar|Creation|Expir|Updated|Name Server|Status|Registrant|Admin|Tech|Country|Email' \
            | sed 's/^/    /'
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# ZONE TRANSFER CHECK (Active)
# ──────────────────────────────────────────────────────────────────────────────
check_zone_transfer(){
    local ns_server=$1
    info "Attempting zone transfer from ${BOLD}$ns_server${RESET} ..."
    local zt
    zt=$(dig axfr "$domain" @"$ns_server" +noall +answer 2>/dev/null)
    if [ -n "$zt" ]; then
        success "Zone transfer SUCCESSFUL on $ns_server!"
        echo "$zt" | sed 's/^/    /'
    else
        warn "Zone transfer failed or not allowed on $ns_server"
    fi
}

run_zone_transfers(){
    section "DNS ZONE TRANSFER CHECK (Active)"
    local ipv4
    ipv4=$(dig +short A "$domain" 2>/dev/null | head -1)
    [ -n "$ipv4" ] && check_zone_transfer "$ipv4"

    local ns_list
    ns_list=$(dig +short NS "$domain" 2>/dev/null)
    if [ -n "$ns_list" ]; then
        while IFS= read -r ns; do
            [ -n "$ns" ] && check_zone_transfer "$ns"
        done <<< "$ns_list"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN ENUMERATION (Passive + Active)
# ──────────────────────────────────────────────────────────────────────────────
run_subdomain_enum(){
    section "SUBDOMAIN ENUMERATION (Passive)"

    # Passive: crt.sh certificate transparency
    info "Querying crt.sh (certificate transparency) ..."
    if check_tool curl; then
        curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null \
            | grep -oP '"name_value":"\K[^"]+' \
            | sort -u \
            | grep -v '\*' \
            | head -30 \
            | sed 's/^/    [crt.sh] /'
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# WEB TECHNOLOGY DISCOVERY (Passive/Active)
# ──────────────────────────────────────────────────────────────────────────────
run_web_recon(){
    section "WEB TECHNOLOGY DISCOVERY"

    # WhatWeb
    if check_tool whatweb; then
        info "Running WhatWeb ..."
        whatweb -a 3 "$domain" 2>/dev/null | sed 's/^/    /'
    fi

    divider

    # HTTP Headers
    if check_tool curl; then
        info "Fetching HTTP headers ..."
        curl -sI --max-time 10 "https://$domain" 2>/dev/null \
            | grep -Ei 'server:|x-powered-by:|content-type:|x-frame-options:|strict-transport:|x-xss|content-security' \
            | sed 's/^/    /'
        # Check HTTP vs HTTPS redirect
        info "Checking HTTP redirect behaviour ..."
        curl -sI --max-time 10 "http://$domain" 2>/dev/null | grep -i "location:" | sed 's/^/    /'
    fi

    divider

    # Robots.txt & Sitemap
    if check_tool curl; then
        info "Fetching robots.txt ..."
        curl -s --max-time 10 "https://$domain/robots.txt" 2>/dev/null \
            | grep -v "^#" | head -20 | sed 's/^/    /'

        info "Checking sitemap.xml ..."
        local sitemap_status
        sitemap_status=$(curl -o /dev/null -s -w "%{http_code}" --max-time 10 "https://$domain/sitemap.xml")
        result "sitemap.xml HTTP status: $sitemap_status"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# SSL/TLS ANALYSIS (Passive/Active)
# ──────────────────────────────────────────────────────────────────────────────
run_ssl_recon(){
    section "SSL/TLS CERTIFICATE ANALYSIS"
    if check_tool openssl; then
        info "Fetching SSL certificate info ..."
        echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null \
            | grep -E 'Subject:|Issuer:|Not Before:|Not After:|DNS:' \
            | sed 's/^/    /'
    fi

    divider

    # testssl.sh (optional)
    if check_tool testssl.sh; then
        info "Running testssl.sh for cipher & vulnerability checks ..."
        testssl.sh --quiet "$domain" 2>/dev/null | grep -E 'VULN|WARN|OK' | head -20 | sed 's/^/    /'
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# EMAIL / OSINT RECON (Passive)
# ──────────────────────────────────────────────────────────────────────────────
run_email_recon(){
    section "EMAIL & OSINT (Passive)"

    # SPF / DMARC / DKIM
    info "Checking SPF record ..."
    dig +short TXT "$domain" 2>/dev/null | grep -i "spf" | sed 's/^/    /'

    info "Checking DMARC record ..."
    dig +short TXT "_dmarc.$domain" 2>/dev/null | sed 's/^/    /'

    info "Checking DKIM (default selector) ..."
    dig +short TXT "default._domainkey.$domain" 2>/dev/null | sed 's/^/    /'

    divider

    # theHarvester
    if check_tool theHarvester; then
        info "Running theHarvester for emails/hosts (sources: bing, google) ..."
        theHarvester -d "$domain" -b bing,google -l 50 2>/dev/null \
            | grep -E '@|IP:|Host:' | head -20 | sed 's/^/    /'
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# WAYBACK MACHINE / URL HARVEST (Passive)
# ──────────────────────────────────────────────────────────────────────────────
run_wayback(){
    section "WAYBACK MACHINE / URL HARVEST (Passive)"
    if check_tool curl; then
        info "Querying Wayback CDX API for historical URLs ..."
        curl -s "https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey&limit=30" \
            2>/dev/null | head -30 | sed 's/^/    /'
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# GEO-IP & ASN LOOKUP (Passive)
# ──────────────────────────────────────────────────────────────────────────────
run_geoip(){
    section "GEO-IP & ASN LOOKUP (Passive)"
    if check_tool curl; then
        local ip
        ip=$(dig +short A "$domain" 2>/dev/null | head -1)
        if [ -n "$ip" ]; then
            info "Target IP: $ip"
            info "Querying ip-api.com for geo/ASN info ..."
            curl -s "http://ip-api.com/json/$ip?fields=country,regionName,city,isp,org,as,query" \
                2>/dev/null | python3 -m json.tool 2>/dev/null | sed 's/^/    /'
        else
            warn "Could not resolve IP for $domain"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
print_summary(){
    echo ""
    echo -e "${GREEN}"
    echo '  ╔══════════════════════════════════════════════════╗'
    echo '  ║           RECONNAISSANCE COMPLETE                ║'
    echo '  ╚══════════════════════════════════════════════════╝'
    echo -e "${RESET}"
    success "Target   : ${WHITE}$domain${RESET}"
    success "Log file : ${WHITE}$LOG_FILE${RESET}"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
main(){
    banner

    echo -ne "${CYAN}[+] Enter the target domain (e.g. example.com): ${RESET}"
    read -r domain

    if [ -z "$domain" ]; then
        error "No domain provided. Exiting."
        exit 1
    fi

    # Validate domain (basic check)
    if ! echo "$domain" | grep -qP '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'; then
        warn "Domain format looks unusual, proceeding anyway..."
    fi

    echo ""
    info "Target: ${BOLD}$domain${RESET}"
    setup_log

    # ── PASSIVE ──
    run_dns_recon
    run_whois
    run_email_recon
    run_ssl_recon
    run_geoip
    run_wayback
    run_subdomain_enum

    # ── ACTIVE ──
    run_zone_transfers
    run_web_recon

    print_summary
}

main
