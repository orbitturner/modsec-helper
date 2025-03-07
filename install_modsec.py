#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ==========================
# NGINX + MODSECURITY INSTALL SCRIPT
# ==========================
# 🚀 Installs and configures Nginx + ModSecurity v3 (compiled from source)
# 🏷️ Idempotent approach with multiple security profiles
# 💾 Backs up existing Nginx binaries before recompilation
# 📢 Author: orbitturner
# ==========================

import os
import sys
import subprocess
import signal
import argparse
import time
from datetime import datetime

from loguru import logger
from dotenv import load_dotenv
from rich.console import Console
from rich.prompt import Prompt
from rich import print as rprint

# ------------------------------------------------------------------------------
# Loguru Configuration
# ------------------------------------------------------------------------------
logger.add("install_modsec.log", rotation="5 MB",
           compression="zip", backtrace=True, diagnose=True)

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
        result = subprocess.run(
            cmd, shell=True, check=False, capture_output=True, text=True)
        if result.returncode == 0:
            logger.debug(f"Success: {result.stdout.strip()}")
            return True
        else:
            logger.error(
                f"Error ({result.returncode}): {result.stderr.strip()}")
            return False
    except Exception as e:
        logger.exception(f"Exception while running command: {cmd}")
        return False


def is_nginx_installed() -> bool:
    check = subprocess.run("which nginx", shell=True, capture_output=True)
    return check.returncode == 0


def is_nginx_with_modsec() -> bool:
    check = subprocess.run("nginx -V 2>&1 | grep 'modsecurity'",
                           shell=True, capture_output=True, text=True)
    return check.returncode == 0


def backup_nginx():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"/usr/local/nginx_backup_{timestamp}"
    rprint(
        f"📦 [yellow]Backing up existing Nginx binaries to {backup_dir}[/yellow]")
    run_command(f"sudo mkdir -p {backup_dir}")
    run_command(f"sudo cp -r /usr/sbin/nginx {backup_dir}/nginx_backup")
    run_command(f"sudo cp -r /etc/nginx {backup_dir}/nginx_conf_backup")
    rprint("[green]✅ Backup completed successfully![/green]")


def install_nginx():
    if is_nginx_installed():
        rprint("[yellow]⚠️  Nginx is already installed.[/yellow]")

        if is_nginx_with_modsec():
            rprint("[green]✅ Nginx already supports ModSecurity.[/green]")
            return True

        rprint("[red]❌ Existing Nginx does NOT support ModSecurity.[/red]")

        if Prompt.ask("Do you want to backup and recompile Nginx with ModSecurity? (y/n)", default="y").lower() != "y":
            rprint(
                "[red]❌ Skipping Nginx recompilation. ModSecurity will NOT work![/red]")
            sys.exit(1)

        backup_nginx()

    rprint("🚀 [blue]Compiling Nginx with ModSecurity support...[/blue]")
    commands = [
        "sudo apt update && sudo apt install -y git gcc g++ make autoconf automake libtool pkg-config libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev",
        "cd /usr/local/src && sudo git clone https://github.com/nginx/nginx.git",
        "cd /usr/local/src/nginx && sudo git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git",
        "cd /usr/local/src/nginx && sudo ./auto/configure --with-compat --add-module=/usr/local/src/nginx/ModSecurity-nginx",
        "cd /usr/local/src/nginx && sudo make && sudo make install",
    ]

    for cmd in commands:
        if not run_command(cmd):
            rprint("[red]❌ Failed to compile Nginx with ModSecurity.[/red]")
            return False

    rprint("[green]✅ Nginx compiled with ModSecurity successfully![/green]")
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

    rprint(
        f"[green]✅ ModSecurity configured with profile [bold]{profile_name}[/bold].[/green]")

    run_command("sudo systemctl restart nginx")

# ------------------------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Install and configure Nginx + ModSecurity v3.")
    parser.add_argument("--profile", type=str, default="basic",
                        help="ModSecurity profile (basic, strict, paranoid).")
    args = parser.parse_args()

    rprint(
        "[bold magenta]Welcome to the ModSecurity installation script![/bold magenta] 🎉")

    if not install_nginx():
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
