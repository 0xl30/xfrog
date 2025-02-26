#!/usr/bin/env python3
import sys
import os
import re
import argparse
import tempfile
import subprocess

# Add the modules directory to the Python path
modules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
sys.path.insert(0, modules_path)

# Import subdomain modules
from crt import crtsh_subdomain_module
from censys import censys_subdomain_module
from virustotal import virustotal_subdomain_module
from subdomaincenter import subdomaincenter_subdomain_module
from certspotter import certspotter_subdomain_module

VERSION = "1.0"
API_FILE = "api.txt"

class Colors:
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    NC = '\033[0m'
    RESET = '\033[0m'

def print_banner():
    print(f"{Colors.RED}██╗  ██╗███████╗██████╗  ██████╗  ██████╗ {Colors.RESET}")
    print(f"{Colors.GREEN}╚██╗██╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝ {Colors.RESET}")
    print(f"{Colors.PURPLE} ╚███╔╝ █████╗  ██████╔╝██║   ██║██║  ███╗{Colors.RESET}")
    print(f"{Colors.CYAN} ██╔██╗ ██╔══╝  ██╔══██╗██║   ██║██║   ██║{Colors.RESET}")
    print(f"{Colors.RED}██╔╝ ██╗██║     ██║  ██║╚██████╔╝╚██████╔╝{Colors.RESET}")
    print(f"{Colors.GREEN}╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ {Colors.RESET}")
    print(f"                             {Colors.CYAN}Made By Ryan{Colors.RESET}")

def color_print(message, color=Colors.NC):
    print(f"{color}{message}{Colors.NC}")

# Tools and Sources
tools = {
    "Subfinder": ["subfinder", "-d", "$domain"],
    "Assetfinder": ["assetfinder", "--subs-only", "$domain"],
    "Findomain": ["findomain", "-t", "$domain"],
    "Chaos": ["chaos", "-d", "$domain", "-key", "project_api"],
    "Haktrails": ["haktrails", "subdomains"],
    "Gau": ["gau", "-t", "10", "--subs", "$domain"],
    "Github-Sub": ["github-subdomains", "-d", "$domain", "-t", "github_api"],
    "Gitlab-Sub": ["gitlab-subdomains", "-d", "$domain", "-t", "gitlab_api"],
    "Cero": ["cero", "$domain"],
    "Shosubgo": ["shosubgo", "-d", "$domain", "-s", "shodan_api"],
    "Crt": "crt",                # Module-based
    "VirusTotal": "virustotal",   # Module-based
    "SubdomainCenter": "subdomaincenter",  # Module-based
    "CertSpotter": "certspotter"  # Module-based
}

# Regular expression to match valid subdomains of any depth
SUBDOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

def load_api_keys(api_file):
    api_keys = {}
    try:
        with open(api_file, "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    api_keys[key] = value
    except FileNotFoundError:
        color_print(f"[!] API file '{api_file}' not found. Ensure it exists and contains the necessary keys.", Colors.RED)
        sys.exit(1)
    return api_keys

def run_tool(tool_name, domain, api_keys, silent=False):
    temp_file = tempfile.NamedTemporaryFile(delete=False, mode="w+t")
    command = tools.get(tool_name)
    subdomains = set()  # Set to store unique subdomains for each tool

    if isinstance(command, list):
        if tool_name == "Haktrails":
            shell_command = f"echo {domain} | {' '.join(command)}"
            try:
                if not silent:
                    print(f"Running Haktrails with piped input: {shell_command}")
                result = subprocess.run(shell_command, shell=True, stdout=temp_file, stderr=subprocess.PIPE, check=False)
                if result.returncode != 0:
                    print(f"[!] {tool_name} failed to run. Error: {result.stderr.decode()}")
                temp_file.seek(0)
                subdomains.update(line.strip() for line in temp_file if line.strip())
            except subprocess.CalledProcessError as e:
                print(f"[!] {tool_name} failed to run. Exception: {e}")
        else:
            command = command.copy()
            masked_command = command.copy()  # Create a copy of the command for masking
            for i, part in enumerate(command):
                if part == "$domain":
                    command[i] = domain
                    masked_command[i] = domain
                elif part == "github_api":
                    api_key = api_keys.get("GITHUB_API_KEY", "")
                    if not api_key:
                        color_print(f"[!] {tool_name} requires a GitHub API key. Skipping...", Colors.RED)
                        return temp_file.name
                    command[i] = api_key
                    masked_command[i] = "Valid-Api-Key"  # Mask the API key
                elif part == "gitlab_api":
                    api_key = api_keys.get("GITLAB_API_KEY", "")
                    if not api_key:
                        color_print(f"[!] {tool_name} requires a GitLab API key. Skipping...", Colors.RED)
                        return temp_file.name
                    command[i] = api_key
                    masked_command[i] = "Valid-Api-Key"  # Mask the API key
                elif part == "shodan_api":
                    api_key = api_keys.get("SHODAN_API_KEY", "")
                    if not api_key:
                        color_print(f"[!] {tool_name} requires a Shodan API key. Skipping...", Colors.RED)
                        return temp_file.name
                    command[i] = api_key
                    masked_command[i] = "Valid-Api-Key"  # Mask the API key
                elif part == "project_api":
                    api_key = api_keys.get("CHAOS_API_KEY", "")
                    if not api_key:
                        color_print(f"[!] {tool_name} requires a Chaos API key. Skipping...", Colors.RED)
                        return temp_file.name
                    command[i] = api_key
                    masked_command[i] = "Valid-Api-Key"  # Mask the API key
            if silent and "-silent" not in command:
                command.append("-silent")
                masked_command.append("-silent")
            try:
                if not silent:
                    print(f"Running command-line tool: {' '.join(masked_command)}")  # Print masked command
                result = subprocess.run(command, stdout=temp_file, stderr=subprocess.PIPE, check=False)
                if result.returncode != 0:
                    print(f"[!] {tool_name} failed to run. Error: {result.stderr.decode()}")
                temp_file.seek(0)
                subdomains.update(line.strip() for line in temp_file if line.strip())
            except subprocess.CalledProcessError as e:
                print(f"[!] {tool_name} failed to run. Exception: {e}")

    elif isinstance(command, str):
        if not silent:
            print(f"Running module-based tool: {tool_name}")
        if tool_name == "CertSpotter":
            api_key = api_keys.get("CERTSPOTTER_API_KEY", "")
            if not api_key:
                color_print(f"[!] {tool_name} requires a CertSpotter API key. Skipping...", Colors.RED)
                return temp_file.name
            subdomains.update(certspotter_subdomain_module(domain, api_key))
        elif tool_name == "Crt":
            subdomains.update(crtsh_subdomain_module(domain))
        elif tool_name == "Censys":
            api_id = api_keys.get("CENSYS_API_ID", "")
            api_secret = api_keys.get("CENSYS_API_SECRET", "")
            if not api_id or not api_secret:
                color_print(f"[!] {tool_name} requires Censys API ID and Secret. Skipping...", Colors.RED)
                return temp_file.name
            subdomains.update(censys_subdomain_module(domain, api_id, api_secret))
        elif tool_name == "VirusTotal":
            api_key = api_keys.get("VIRUSTOTAL_API_KEY", "")
            if not api_key:
                color_print(f"[!] {tool_name} requires a VirusTotal API key. Skipping...", Colors.RED)
                return temp_file.name
            subdomains.update(virustotal_subdomain_module(domain, api_key))
        elif tool_name == "SubdomainCenter":
            subdomains.update(subdomaincenter_subdomain_module(domain))
        else:
            print(f"[!] Unknown module-based tool: {tool_name}")
            return temp_file.name

    with open(temp_file.name, "w") as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
    if not silent:
        print(f"[*] {tool_name}: {len(subdomains)} unique subdomains found.")
    return temp_file.name

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("-d", "--domain", required=True, help="Domain to enumerate")
    parser.add_argument("-u", "--use", help="Specify tools to use (comma-separated)")
    parser.add_argument("-e", "--exclude", help="Specify tools to exclude (comma-separated)")
    parser.add_argument("-o", "--output", help="Output file for final results")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode")
    parser.add_argument("-v", "--version", action="store_true", help="Display version")

    args = parser.parse_args()

    if args.version:
        color_print(f"Version: {VERSION}", Colors.BOLD)
        sys.exit(0)

    # Set the output file name
    output_file = args.output if args.output else f"{args.domain}.txt"

    api_keys = load_api_keys(API_FILE)
    selected_tools = set(tools.keys())

    if args.use:
        selected_tools = set(args.use.split(","))
    if args.exclude:
        selected_tools.difference_update(set(args.exclude.split(",")))

    unique_subdomains = set()

    if not args.silent:
        color_print(f"Starting enumeration for {args.domain}", Colors.GREEN)

    for tool in selected_tools:
        if not args.silent:
            color_print(f"Running {tool}...", Colors.CYAN)
        temp_file_name = run_tool(tool, args.domain, api_keys, args.silent)
        with open(temp_file_name) as temp_file:
            for line in temp_file:
                subdomain = line.strip()
                if SUBDOMAIN_REGEX.match(subdomain):
                    unique_subdomains.add(subdomain)
        os.remove(temp_file_name)

    # Write results to the output file
    try:
        with open(output_file, "w") as f:
            f.write("\n".join(sorted(unique_subdomains)))  # Sort for consistent ordering
        if not args.silent:
            color_print(f"Final results saved to {output_file} with {len(unique_subdomains)} unique subdomains.", Colors.GREEN)
    except IOError as e:
        color_print(f"[!] Failed to write to {output_file}: {e}", Colors.RED)

if __name__ == "__main__":
    main()