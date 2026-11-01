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
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.cache = {'html': None, 'soup': None, 'plugins': set(), 'themes': set(), 'core_version': None}

    def fetch_page(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)
            self.cache['html'] = response.text
            self.cache['soup'] = BeautifulSoup(response.text, 'html.parser')
            return True
        except Exception: return False

    def detect_core_version(self):
        version = None
        if self.cache['soup']:
            meta = self.cache['soup'].find('meta', attrs={'name': 'generator'})
            if meta and 'WordPress' in meta.get('content', ''):
                match = re.search(r'WordPress ([\d\.]+)', meta['content'])
                if match: version = match.group(1)
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

    def get_full_report(self):
        if not self.cache['html']: self.fetch_page()
        return {
            "target": self.target_url,
            "core": {"version": self.detect_core_version()},
            "plugins": self.detect_plugins(),
            "themes": ["astra"] # Contoh
}
