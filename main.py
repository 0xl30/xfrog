#!/usr/bin/env python3
import sys
import os
import re
import argparse
import subprocess
import urllib.parse
from typing import Callable, List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from halo import Halo
from datetime import datetime
from colorama import Fore, Style, init as colorama_init

# Init colorama
colorama_init(autoreset=True)

# Add modules path
modules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
sys.path.insert(0, modules_path)

# Import module tools
from crt import crtsh_subdomain_module
from censys import censys_subdomain_module
from virustotal import virustotal_subdomain_module
from subdomaincenter import subdomaincenter_subdomain_module
from certspotter import certspotter_subdomain_module

VERSION = "2.0"
API_FILE = "api.txt"
LOG_FILE = "log.txt"

# ---------- Logging + Color ---------- #
class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    CYAN = '\033[36m'
    RESET = '\033[0m'

def timestamp():
    return datetime.now().strftime("[%H:%M:%S]")

def log_message(msg: str):
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp()} {msg}\n")

def color_print(msg, color=Colors.RESET):
    print(f"{color}{timestamp()} {msg}{Colors.RESET}")
    log_message(msg)

def print_banner():
    banner = f"""
{Colors.RED}██╗  ██╗███████╗██████╗  ██████╗  ██████╗ {Colors.RESET}
{Colors.GREEN}╚██╗██╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝ {Colors.RESET}
{Colors.CYAN} ╚███╔╝ █████╗  ██████╔╝██║   ██║██║  ███╗{Colors.RESET}
{Colors.RED} ██╔██╗ ██╔══╝  ██╔══██╗██║   ██║██║   ██║{Colors.RESET}
{Colors.GREEN}██╔╝ ██╗██║     ██║  ██║╚██████╔╝╚██████╔╝{Colors.RESET}
{Colors.CYAN}╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ {Colors.RESET}
                            {Colors.CYAN}Made by Ryan{Colors.RESET}
"""
    print(banner)
    log_message("Started Subdomain Enumeration")

SUBDOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

# ---------- Tool Registry ---------- #
class ToolRegistry:
    def __init__(self):
        self.commands = {}
        self.modules = {}

    def register_command(self, name: str, cmd: List[str]):
        self.commands[name] = cmd

    def register_module(self, name: str, func: Callable[[str, Dict[str, str]], List[str]]):
        self.modules[name] = func

tool_registry = ToolRegistry()

# CLI tools
tool_registry.register_command("Subfinder", ["subfinder", "-d", "$domain"])
tool_registry.register_command("Assetfinder", ["assetfinder", "--subs-only", "$domain"])
tool_registry.register_command("Findomain", ["findomain", "-t", "$domain"])
tool_registry.register_command("Chaos", ["chaos", "-d", "$domain", "-key", "project_api"])
tool_registry.register_command("Haktrails", ["haktrails", "subdomains"])
tool_registry.register_command("Gau", ["gau", "--threads", "10", "--subs", "$domain"]) 
tool_registry.register_command("Github-Sub", ["github-subdomains", "-d", "$domain", "-t", "github_api"])
tool_registry.register_command("Gitlab-Sub", ["gitlab-subdomains", "-d", "$domain", "-t", "gitlab_api"])
tool_registry.register_command("Cero", ["cero", "$domain"])
tool_registry.register_command("Shosubgo", ["shosubgo", "-d", "$domain", "-s", "shodan_api"])

# Module tools
tool_registry.register_module("CertSpotter", lambda d, k: certspotter_subdomain_module(d, k.get("CERTSPOTTER_API_KEY")))
tool_registry.register_module("Crt", lambda d, k: crtsh_subdomain_module(d))
#tool_registry.register_module("Censys", lambda d, k: censys_subdomain_module(d, k.get("CENSYS_API_ID"), k.get("CENSYS_API_SECRET"))) ## IF YOU HAVE PAID API THEN UNCOMMENT THIS
tool_registry.register_module("VirusTotal", lambda d, k: virustotal_subdomain_module(d, k.get("VIRUSTOTAL_API_KEY")))
tool_registry.register_module("SubdomainCenter", lambda d, k: subdomaincenter_subdomain_module(d))

# ---------- Utility Functions ---------- #
def load_api_keys(path: str) -> Dict[str, str]:
    keys = {}
    try:
        with open(path, "r") as f:
            for line in f:
                if "=" in line:
                    k, v = map(str.strip, line.strip().split("=", 1))
                    keys[k] = v
    except FileNotFoundError:
        color_print(f"[!] API file '{path}' not found.", Colors.RED)
        sys.exit(1)
    return keys

def run_tool(tool: str, domain: str, api_keys: Dict[str, str]) -> Set[str]:
    subdomains = set()
    spinner = Halo(text=f"Running {tool}...", spinner='dots', color='cyan')
    spinner.start()

    try:
        if tool in tool_registry.commands:
            cmd = list(tool_registry.commands[tool])
            for i, part in enumerate(cmd):
                if part == "$domain":
                    cmd[i] = domain
                elif part.endswith("_api"):
                    key_map = {
                        "github_api": "GITHUB_API_KEY",
                        "gitlab_api": "GITLAB_API_KEY",
                        "shodan_api": "SHODAN_API_KEY",
                        "project_api": "CHAOS_API_KEY"
                    }
                    val = api_keys.get(key_map.get(part))
                    if not val:
                        spinner.fail(f"{Fore.RED}{tool} error: Api-Key")
                        log_message(f"{tool} missing API key")
                        return set()
                    cmd[i] = val

            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            except FileNotFoundError:
                spinner.fail(f"{Fore.RED}{tool} error: Not Found")
                log_message(f"{tool} not installed or not in PATH")
                return set()

            for line in result.stdout.splitlines():
                line = line.strip()

                if tool == "Gau":
                    # Extract hostname from URL
                    try:
                        parsed = urllib.parse.urlparse(line)
                        hostname = parsed.hostname
                        if hostname and SUBDOMAIN_REGEX.match(hostname):
                            subdomains.add(hostname.replace("*.", ""))
                    except Exception:
                        continue
                else:
                    line = line.replace("*.", "")
                    if SUBDOMAIN_REGEX.match(line):
                        subdomains.add(line)

        elif tool in tool_registry.modules:
            try:
                results = tool_registry.modules[tool](domain, api_keys)
                for r in results:
                    clean = r.strip().replace("*.", "")
                    if SUBDOMAIN_REGEX.match(clean):
                        subdomains.add(clean)
            except (AttributeError, TypeError, KeyError):
                spinner.fail(f"{Fore.RED}{tool} error: Api-Key")
                log_message(f"{tool} API key missing or misused")
                return set()
            except Exception as e:
                err = str(e).strip()
                if "503" in err or "Unavailable" in err:
                    spinner.fail(f"{Fore.RED}{tool} error: Service Unavailable")
                else:
                    spinner.fail(f"{Fore.RED}{tool} error: Failed")
                log_message(f"{tool}: {err}")
                return set()

        spinner.succeed(f"{Fore.GREEN}{tool} found {len(subdomains)}")
        log_message(f"{tool} success: {len(subdomains)} found")

    except Exception as e:
        spinner.fail(f"{Fore.RED}{tool} error: Unexpected")
        log_message(f"{tool} crashed: {str(e).strip()}")

    return subdomains

# ---------- Main Program ---------- #
def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")

    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-u", "--use", help="Comma-separated tools to use")
    parser.add_argument("-e", "--exclude", help="Comma-separated tools to exclude")
    parser.add_argument("-o", "--output", help="Output file (default: <domain>.txt)")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads (default: 1)")
    parser.add_argument("-s", "--silent", action="store_true", help="Suppress banner")
    parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("--list", action="store_true", help="List available tools and exit")

    args = parser.parse_args()

    if args.version:
        print(f"Version: {VERSION}")
        sys.exit(0)

    if args.list:
        print("Available tools:")
        for tool in sorted(set(tool_registry.commands) | set(tool_registry.modules)):
            print(f" - {tool}")
        sys.exit(0)

    if not args.domain:
        parser.error("the following argument is required: -d/--domain")

    if not args.silent:
        print_banner()

    with open(LOG_FILE, "w") as f:
        f.write(f"{timestamp()} Subdomain Enumeration Started\n")

    domain = args.domain

    # Ensure output file is only set ONCE
    if args.output:
        output_file = args.output
    else:
        output_file = f"{domain}.txt"

    api_keys = load_api_keys(API_FILE)

    selected = set(tool_registry.commands) | set(tool_registry.modules)
    if args.use:
        selected = set(args.use.split(","))
    if args.exclude:
        selected -= set(args.exclude.split(","))

    found_subdomains = set()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(run_tool, tool, domain, api_keys): tool
            for tool in sorted(selected)
        }
        for future in as_completed(futures):
            tool = futures[future]
            try:
                results = future.result()
                found_subdomains.update(results)
            except Exception as e:
                log_message(f"{tool} failed in thread: {str(e).strip()}")

    try:
        with open(output_file, "w") as f:
            f.write("\n".join(sorted(found_subdomains)))
        color_print(f"[✓] {len(found_subdomains)} subdomains saved to {output_file}", Colors.CYAN)
        log_message(f"[✓] Saved output to {output_file}")
    except Exception as e:
        color_print(f"[!] Failed to write output: {e}", Colors.RED)
        log_message(f"[!] Output error: {e}")

if __name__ == "__main__":
    main()
