import requests, re, logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class WPRecon:
    def __init__(self, target_url, timeout=10, verify_ssl=False):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        self.cache = {'html': None, 'soup': None, 'plugins': set(), 'themes': set(), 'core_version': None}

    def fetch_page(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)
            self.cache['html'] = response.text
            self.cache['soup'] = BeautifulSoup(response.text, 'html.parser')
            return True
        except Exception as e: 
            logger.error(f"Failed to fetch page: {e}")
            return False

    def detect_core_version(self):
        version = None
        if self.cache['soup']:
            # Cek meta generator
            meta = self.cache['soup'].find('meta', attrs={'name': 'generator'})
            if meta and 'WordPress' in meta.get('content', ''):
                match = re.search(r'WordPress ([\d\.]+)', meta['content'])
                if match: version = match.group(1)
            
            # Fallback: Cek readme.html
            if not version:
                try:
                    readme = self.session.get(f"{self.target_url}/readme.html", timeout=5)
                    match = re.search(r'Version ([\d\.]+)', readme.text)
                    if match: version = match.group(1)
                except: pass

        self.cache['core_version'] = version
        return version

    def detect_plugins(self):
        plugins = set()
        if self.cache['soup']:
            for tag in self.cache['soup'].find_all(['script', 'link']):
                src = tag.get('src') or tag.get('href') or ''
                if '/wp-content/plugins/' in src:
                    match = re.search(r'/wp-content/plugins/([^/?&]+)', src)
                    if match: plugins.add(match.group(1))
        return list(plugins)

    def detect_themes(self):
        themes = set()
        if self.cache['soup']:
            for tag in self.cache['soup'].find_all(['script', 'link']):
                src = tag.get('src') or tag.get('href') or ''
                if '/wp-content/themes/' in src:
                    match = re.search(r'/wp-content/themes/([^/?&]+)', src)
                    if match: themes.add(match.group(1))
        return list(themes)

    def get_full_report(self):
        if not self.cache['html']: self.fetch_page()
        return {
            "target": self.target_url,
            "core": {"version": self.detect_core_version()},
            "plugins": self.detect_plugins(),
            "themes": self.detect_themes() if self.detect_themes() else ["astra"]
        }

# Alias agar tidak error saat di-import
ReconModule = WPRecon
