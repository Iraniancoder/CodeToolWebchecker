import requests
from bs4 import BeautifulSoup
import re
import random
import time
from urllib.parse import urlparse
import socket
import socks
from colorama import init, Fore
import pyfiglet
from concurrent.futures import ThreadPoolExecutor
import json

init(autoreset=True)  

class CodeToolWebchecker:
    def __init__(self):
        self.tech_stack = {
            'CMS': [],
            'Web Server': [],
            'Programming Language': [],
            'JavaScript Frameworks': [],
            'Database': [],
            'Security': [],
            'CDN': [],
            'WAF': []
        }
        self.session = requests.Session()
        self._init_user_agents()
        self._init_patterns()
        self.timeout = 20
        self.max_retries = 3
        self.show_banner()
        
    def show_banner(self):
        
        banner = pyfiglet.figlet_format(" WEBCHECKER", font="Big")
        print(Fore.CYAN + banner)
        print(Fore.YELLOW + " " * 20 + "CodeTool Webchecker v1.0")
        print(Fore.YELLOW + " " * 25 + "Coder By CodeTool.ir \n")

    def _init_user_agents(self):
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
            'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]

    def _init_patterns(self):
        
        self.db_patterns = {
            'MySQL': [r'mysql_', r'mysqli_', r'MySQLdb'],
            'PostgreSQL': [r'pg_', r'postgres', r'PostgreSQL'],
            'SQLite': [r'sqlite3', r'SQLite3'],
            'MongoDB': [r'mongodb', r'mongo'],
            'Oracle': [r'oracle', r'oci8'],
            'Microsoft SQL': [r'sqlsrv', r'mssql']
        }
        
        self.cms_patterns = {
            r'/wp-content/': 'WordPress',
            r'/_next/static/': 'Next.js',
            r'/media/jui/': 'Joomla',
            r'/sites/all/': 'Drupal',
            r'/static/assets/': 'Shopify',
            r'/wix-static/': 'Wix'
        }
        
        self.waf_patterns = {
            'Cloudflare': ['__cfduid', 'cloudflare', 'cf-ray'],
            'Akamai': ['akamai'],
            'Imperva': ['incap_ses', 'visid_incap']
        }

    def _setup_proxy(self):
        
        socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
        socket.socket = socks.socksocket

    def _chunked_request(self, url):
        
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Transfer-Encoding': 'chunked',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                stream=True
            )
            return response
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[-] Chunked request failed: {str(e)}")
            return None

    def _obfuscate_request(self, url):
        
        techniques = [
            self._send_basic_request,
            self._chunked_request,
            lambda u: self._send_basic_request(u, headers={'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'})
        ]
        
        for attempt in range(self.max_retries):
            technique = random.choice(techniques)
            response = technique(url)
            if response and response.status_code == 200:
                return response
        
        return None

    def _send_basic_request(self, url, headers=None):
        
        if not headers:
            headers = {'User-Agent': random.choice(self.user_agents)}
        
        try:
            time.sleep(random.uniform(1, 3))
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[-] Request error: {str(e)}")
            return None

    def _detect_waf(self, response):
        
        headers = response.headers
        cookies = headers.get('Set-Cookie', '')
        
        for waf, patterns in self.waf_patterns.items():
            if any(p.lower() in cookies.lower() for p in patterns):
                self.tech_stack['WAF'].append(waf)
                return True
        
        
        if 'cf-ray' in headers or 'cloudflare' in headers.get('server', '').lower():
            self.tech_stack['WAF'].append('Cloudflare')
            return True
        
        return False

    def _detect_database(self, response):
        
        
        for header, value in response.headers.items():
            if 'db' in header.lower():
                self.tech_stack['Database'].append(value)
        
        
        for db_type, patterns in self.db_patterns.items():
            if any(re.search(pattern, response.text, re.IGNORECASE) for pattern in patterns):
                if db_type not in self.tech_stack['Database']:
                    self.tech_stack['Database'].append(db_type)

    def _detect_cdn(self, response):
        
        server = response.headers.get('Server', '').lower()
        if 'cloudflare' in server:
            self.tech_stack['CDN'].append('Cloudflare')
        elif 'akamai' in server:
            self.tech_stack['CDN'].append('Akamai')
        elif 'fastly' in server:
            self.tech_stack['CDN'].append('Fastly')

    def fingerprint(self, url):
        
        print(Fore.GREEN + f"\n[+] Scanning: {url}")
        
        
        response = self._obfuscate_request(url)
        if not response:
            print(Fore.RED + "[-] Failed to get valid response after multiple attempts")
            return None
        
        
        self._detect_waf(response)
        self._detect_cdn(response)
        
        
        headers = response.headers
        if 'Server' in headers:
            self.tech_stack['Web Server'].append(headers['Server'])
        if 'X-Powered-By' in headers:
            self.tech_stack['Programming Language'].append(headers['X-Powered-By'])
        
        
        cookies = headers.get('Set-Cookie', '')
        cookie_tech = {
            'PHPSESSID': 'PHP',
            'JSESSIONID': 'Java',
            'ASP.NET_SessionId': 'ASP.NET',
            'laravel_session': 'PHP (Laravel)',
            'wordpress_logged_in': 'WordPress'
        }
        for cookie, tech in cookie_tech.items():
            if cookie in cookies:
                self.tech_stack['Programming Language'].append(tech)
        
        
        soup = BeautifulSoup(response.text, 'lxml')
        
        
        for meta in soup.find_all('meta'):
            if meta.get('name') == 'generator':
                self.tech_stack['CMS'].append(meta.get('content'))
        
        
        with ThreadPoolExecutor() as executor:
            executor.map(self._analyze_script, soup.find_all('script', src=True))
        
        
        for pattern, cms in self.cms_patterns.items():
            if re.search(pattern, response.text):
                if cms not in self.tech_stack['CMS']:
                    self.tech_stack['CMS'].append(cms)
        
        
        self._detect_database(response)
        
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking Protection',
            'Content-Security-Policy': 'CSP Enabled',
            'X-Content-Type-Options': 'MIME Sniffing Prevention',
            'Strict-Transport-Security': 'HSTS Enabled'
        }
        for header, desc in security_headers.items():
            if header not in headers:
                self.tech_stack['Security'].append(f'Missing {header}')
            else:
                self.tech_stack['Security'].append(desc)
        
        
        self._print_results()
        
        return self.tech_stack

    def _analyze_script(self, script):
        
        js_frameworks = {
            'jquery': 'jQuery',
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'next': 'Next.js',
            'svelte': 'Svelte',
            'ember': 'Ember.js'
        }
        
        src = script.get('src', '').lower()
        for pattern, name in js_frameworks.items():
            if pattern in src and name not in self.tech_stack['JavaScript Frameworks']:
                self.tech_stack['JavaScript Frameworks'].append(name)

    def _print_results(self):
        
        print(Fore.CYAN + "\n[+] Technology Stack Identified:")
        for category, techs in self.tech_stack.items():
            if techs:
                unique_techs = list(set(techs))
                colored_techs = Fore.GREEN + ', '.join(unique_techs)
                print(Fore.YELLOW + f"  • {category}: {colored_techs}")

    def save_results(self, filename):
        
        with open(filename, 'w') as f:
            json.dump(self.tech_stack, f, indent=4)
        print(Fore.GREEN + f"\n[+] Results saved to {filename}")

if __name__ == "__main__":
    try:
        scanner = CodeToolWebchecker()
        target_url = input(Fore.BLUE + "[?] Enter URL to scan: ").strip()
        
        if not urlparse(target_url).scheme:
            target_url = f'https://{target_url}'
        
        results = scanner.fingerprint(target_url)
        if results:
            scanner.save_results("tech_stack.json")
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
    except Exception as e:
        print(Fore.RED + f"\n[!] Unexpected error: {str(e)}")
