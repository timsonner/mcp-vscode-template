from mcp.server.fastmcp import FastMCP
import subprocess
# import httpx
# import os
# import json
import socket
import dns.resolver
import re
from typing import Dict, Any
# from typing import List, Dict, Any, Optional


# Initialise FastMCP server
mcp = FastMCP("external-recon")

## Prompt to initialise the AI model to the task
@mcp.tool()
def setup_prompt(domainname: str) -> str:
    """
    setup external reconnaissance by domain name

    :param domainname: domain name to target
    :type domainname: str
    :return:
    :rtype: str
    """

    return f"""
Your role is a highly skilled penetration tester specialising in network reconnaissance. Your primary objective is to enumerate the {domainname} domain and report on discovered IP addresses, subdomains, and email security.

Observer carefully the output of the tools in inform next steps

Your objective is to perform reconnaissance against the organisation's domain name, identify IP addresses, discover subdomains, report on the ownership of the domains, and assess the email security measures. When you find new IP addresses or subdomains I want you to repeat enumeration steps.

First, reflect on the objective, then execute any tools you have access to on the target domain {domainname} and report your findings on all IP addresses and subdomains discovered.
"""

@mcp.tool()
def dns_lookup(domain: str) -> Dict[str, Any]:
    """
    Perform DNS lookups for A, MX, NS, TXT, and SOA records

    :param domain: The domain to look up
    :type domain: str
    :return: Dictionary containing different DNS records
    :rtype: Dict[str, Any]
    """
    results = {}
    
    try:
        # A records (IPv4 addresses)
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            results['a_records'] = [record.to_text() for record in a_records]
        except Exception as e:
            results['a_records'] = f"Error: {str(e)}"
            
        # MX records (Mail servers)
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results['mx_records'] = [record.to_text() for record in mx_records]
        except Exception as e:
            results['mx_records'] = f"Error: {str(e)}"
            
        # NS records (Name servers)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results['ns_records'] = [record.to_text() for record in ns_records]
        except Exception as e:
            results['ns_records'] = f"Error: {str(e)}"
            
        # TXT records (Text records, includes SPF usually)
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results['txt_records'] = [record.to_text() for record in txt_records]
        except Exception as e:
            results['txt_records'] = f"Error: {str(e)}"
            
        # SOA records (Start of Authority)
        try:
            soa_records = dns.resolver.resolve(domain, 'SOA')
            results['soa_records'] = [record.to_text() for record in soa_records]
        except Exception as e:
            results['soa_records'] = f"Error: {str(e)}"
            
    except Exception as e:
        results['error'] = f"General error: {str(e)}"
        
    return results

@mcp.tool()
def check_email_security(domain: str) -> Dict[str, Any]:
    """
    Check for email security measures like SPF, DMARC and DKIM

    :param domain: The domain to check
    :type domain: str
    :return: Dictionary containing email security findings
    :rtype: Dict[str, Any]
    """
    results = {"spf": None, "dmarc": None, "dkim_configured": False}
    
    # Check SPF (Sender Policy Framework)
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if "v=spf1" in record.to_text():
                results["spf"] = record.to_text()
                break
    except Exception as e:
        results["spf_error"] = str(e)
    
    # Check DMARC (Domain-based Message Authentication, Reporting & Conformance)
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for record in dmarc_records:
            if "v=DMARC1" in record.to_text():
                results["dmarc"] = record.to_text()
                break
    except Exception as e:
        results["dmarc_error"] = str(e)
    
    # Check DKIM (DomainKeys Identified Mail)
    # We can't check directly as DKIM selectors are custom
    # But we can try common selectors
    common_selectors = ["default", "mail", "email", "selector1", "selector2", "k1", "dkim"]
    for selector in common_selectors:
        try:
            dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            results["dkim_configured"] = True
            results["dkim_selector"] = selector
            results["dkim"] = dkim_records[0].to_text()
            break
        except:
            pass
    
    return results

@mcp.tool()
def scan_ports(target: str, ports: str = "21,22,23,25,53,80,443,8080,8443") -> Dict[str, Any]:
    """
    Scan for open ports on a target IP or domain

    :param target: IP or domain to scan
    :type target: str
    :param ports: Comma-separated list of ports to scan (defaults to common ports)
    :type ports: str
    :return: Dictionary containing open ports and their services
    :rtype: Dict[str, Any]
    """
    results = {"open_ports": []}
    
    # First resolve the target if it's a domain
    try:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            ip = socket.gethostbyname(target)
            results["resolved_ip"] = ip
        else:
            ip = target
    except Exception as e:
        results["error"] = f"Could not resolve hostname: {str(e)}"
        return results
        
    port_list = [int(p) for p in ports.split(",")]
    
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Try to identify the service
                service = "unknown"
                try:
                    # Common port to service mapping
                    services = {
                        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
                        53: "DNS", 80: "HTTP", 443: "HTTPS", 3389: "RDP",
                        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
                    }
                    if port in services:
                        service = services[port]
                except:
                    pass
                    
                results["open_ports"].append({"port": port, "service": service})
            sock.close()
        except:
            pass
            
    return results

@mcp.tool()
def whois_lookup(domain: str) -> Dict[str, str]:
    """
    Perform a WHOIS lookup on a domain

    :param domain: The domain to look up
    :type domain: str
    :return: Dictionary containing WHOIS information
    :rtype: Dict[str, str]
    """
    results = {}
    
    try:
        # Use the whois command line tool
        command = ["whois", domain]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        
        # Extract useful information from the output
        output = result.stdout
        
        # Extract registrar information
        registrar_match = re.search(r"Registrar:\s*(.*)", output)
        if registrar_match:
            results["registrar"] = registrar_match.group(1).strip()
            
        # Extract creation date
        creation_date_match = re.search(r"Creation Date:\s*(.*)", output)
        if creation_date_match:
            results["creation_date"] = creation_date_match.group(1).strip()
            
        # Extract expiration date
        expiration_date_match = re.search(r"Registry Expiry Date:\s*(.*)", output)
        if expiration_date_match:
            results["expiration_date"] = expiration_date_match.group(1).strip()
            
        # Include the full output
        results["raw_data"] = output
        
    except Exception as e:
        results["error"] = f"WHOIS lookup failed: {str(e)}"
        
    return results

if __name__ == "__main__":
    # Initialise and run the server
    mcp.run(transport='stdio')
