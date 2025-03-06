#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ==========================
# NGINX + MODSECURITY INSTALL SCRIPT
# ==========================
# 🚀 Installs and configures Nginx + ModSecurity v3 (compiled from source)
# 🏷️ Idempotent approach with multiple security profiles
# 📢 Author: orbitturner
# ==========================

import os
import sys
import subprocess
import signal
import argparse
import time

from loguru import logger
from dotenv import load_dotenv
from rich.console import Console
from rich.prompt import Prompt
from rich import print as rprint

# ------------------------------------------------------------------------------
# Loguru Configuration
# ------------------------------------------------------------------------------
logger.add("install_modsec.log", rotation="5 MB", compression="zip", backtrace=True, diagnose=True)

# ------------------------------------------------------------------------------
# Load environment variables
# ------------------------------------------------------------------------------
load_dotenv()

# ------------------------------------------------------------------------------
# Rich Configuration
# ------------------------------------------------------------------------------
console = Console()

# ------------------------------------------------------------------------------
# Definition of security profiles
# ------------------------------------------------------------------------------
PROFILES = {
    "basic": {
        "description": "Basic profile with OWASP CRS default rules and minimal filtering.",
        "rules": [
            "SecRuleEngine On",
            "Include /etc/nginx/modsec/coreruleset/crs-setup.conf",
            "Include /etc/nginx/modsec/coreruleset/rules/*.conf",
        ]
    },
    "strict": {
        "description": "Strict profile with stronger defensive rules (SQLi, XSS).",
        "rules": [
            "SecRuleEngine On",
            "Include /etc/nginx/modsec/coreruleset/crs-setup.conf",
            "Include /etc/nginx/modsec/coreruleset/rules/*.conf",
            "SecRule REQUEST_HEADERS:User-Agent \"(?i:sqlmap)\" \"id:1001,deny,log,msg:'SQLMap Scan Detected'\""
        ]
    },
    "paranoid": {
        "description": "Paranoid profile with aggressive rule activation, higher risk of false positives.",
        "rules": [
            "SecRuleEngine On",
            "Include /etc/nginx/modsec/coreruleset/crs-setup.conf",
            "Include /etc/nginx/modsec/coreruleset/rules/*.conf",
            "SecRule ARGS \"(?i:select|union|drop|insert)\" \"id:2001,deny,log,msg:'SQL Keywords Detected'\"",
            "SecRule ARGS \"<script>\" \"id:2002,deny,log,msg:'XSS Detected'\""
        ]
    }
}

# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------

def run_command(cmd: str) -> bool:
    logger.debug(f"Executing command: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
        if result.returncode == 0:
            logger.debug(f"Success: {result.stdout.strip()}")
            return True
        else:
            logger.error(f"Error ({result.returncode}): {result.stderr.strip()}")
            return False
    except Exception as e:
        logger.exception(f"Exception while running command: {cmd}")
        return False

def is_nginx_installed() -> bool:
    check = subprocess.run("which nginx", shell=True, capture_output=True)
    return check.returncode == 0

def is_modsecurity_installed() -> bool:
    check = subprocess.run("ls /usr/local/modsecurity/bin/modsecurity", shell=True, capture_output=True)
    return check.returncode == 0

def install_nginx() -> bool:
    if is_nginx_installed():
        rprint("[green]✅ Nginx is already installed.[/green]")
        return True

    rprint("[yellow]⚠️  Nginx is not installed on this system.[/yellow]")
    if Prompt.ask("Do you want to install it? (y/n)", default="y").lower() == "y":
        return run_command("sudo apt update && sudo apt install -y nginx")
    else:
        rprint("[red]❌ Nginx installation skipped.[/red]")
        sys.exit(1)

def install_modsecurity() -> bool:
    if is_modsecurity_installed():
        rprint("[green]✅ ModSecurity v3 is already installed.[/green]")
        return True

    rprint("🚀 [blue]Installing ModSecurity v3...[/blue]")
    commands = [
        "sudo apt update && sudo apt install -y git gcc g++ make autoconf automake libtool pkg-config libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev",
        "cd /usr/local/src && sudo git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity",
        "cd /usr/local/src/ModSecurity && sudo git submodule init && sudo git submodule update",
        "cd /usr/local/src/ModSecurity && sudo ./build.sh && sudo ./configure && sudo make && sudo make install",
    ]
    
    for cmd in commands:
        if not run_command(cmd):
            rprint("[red]❌ ModSecurity installation failed.[/red]")
            return False

    return True

def install_owasp_crs():
    crs_repo = "/etc/nginx/modsec/coreruleset"
    
    if os.path.exists(crs_repo):
        rprint("[green]✅ OWASP Core Rule Set is already installed.[/green]")
        return True
    
    rprint("🌍 [blue]Downloading OWASP Core Rule Set (CRS)...[/blue]")
    
    commands = [
        "sudo mkdir -p /etc/nginx/modsec",
        "sudo git clone --depth 1 https://github.com/coreruleset/coreruleset.git /etc/nginx/modsec/coreruleset",
        "sudo mv /etc/nginx/modsec/coreruleset/crs-setup.conf.example /etc/nginx/modsec/coreruleset/crs-setup.conf"
    ]

    for cmd in commands:
        if not run_command(cmd):
            rprint("[red]❌ Failed to install OWASP CRS.[/red]")
            return False

    rprint("[green]✅ OWASP CRS installed successfully![/green]")
    return True

def configure_modsecurity(profile_name: str):
    modsec_conf = "/etc/nginx/modsecurity.conf"

    if profile_name not in PROFILES:
        rprint(f"[red]❌ Unknown profile {profile_name}. Aborting.[/red]")
        sys.exit(1)

    with open(modsec_conf, "w") as f:
        f.write("\n".join(PROFILES[profile_name]["rules"]) + "\n")

    rprint(f"[green]✅ ModSecurity configured with profile [bold]{profile_name}[/bold].[/green]")

    nginx_conf = "/etc/nginx/nginx.conf"
    with open(nginx_conf, "r") as f:
        content = f.read()

    if "modsecurity.conf" not in content:
        with open(nginx_conf, "a") as f:
            f.write("\nmodsecurity on;\nmodsecurity_rules_file /etc/nginx/modsecurity.conf;\n")

    run_command("sudo systemctl restart nginx")

# ------------------------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Install and configure Nginx + ModSecurity v3.")
    parser.add_argument("--profile", type=str, default="basic", help="ModSecurity profile (basic, strict, paranoid).")
    args = parser.parse_args()

    rprint("[bold magenta]Welcome to the ModSecurity installation script![/bold magenta] 🎉")

    if not install_nginx():
        sys.exit(1)
    if not install_modsecurity():
        sys.exit(1)
    if not install_owasp_crs():
        sys.exit(1)
    
    configure_modsecurity(args.profile)
    rprint("[bold green]✨ All done![/bold green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        rprint("\n[bold red]❗ Script interrupted.[/bold red]")
        sys.exit(1)
