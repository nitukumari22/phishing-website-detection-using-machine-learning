import urllib.parse
import re
import socket

# List of common URL shortening services
SHORTENING_SERVICES = {
    'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl.com',
    'tr.im', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu',
    'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm',
    'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com',
    'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 'lnkd.in',
    'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv', 'tiny.cc', 'ow.ly',
    'bit.ly', 'ity.im', 'q.gs', 'is.gd', 'po.st', 'bc.vc', 'twitthis.com', 'u.to',
    'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co', 'prettylinkpro.com',
    'scrnch.me', 'filoops.info', 'linkis.com', 'su.pr', 'urlin.it', 'lnkd.in', 'tiny.cc'
}

# List of suspicious keywords often found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'secure', 'update', 'account', 'verify', 'webscr', 'banking',
    'confirm', 'live', 'ebayisapi', 'paypal', 'admin', 'auth', 'recover', 'online',
    'service', 'free', 'gift', 'bonus', 'claim', 'winner', 'support', 'authorize', 'oauth'
]

# Official domains for brand impersonation detection
OFFICIAL_DOMAINS = {
    'google': {'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.de', 'google.fr', 'youtube.com', 'gmail.com', 'blogger.com'},
    'facebook': {'facebook.com', 'fb.com', 'messenger.com'},
    'instagram': {'instagram.com'},
    'paypal': {'paypal.com', 'paypal.me'},
    'apple': {'apple.com', 'icloud.com'},
    'microsoft': {'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'},
    'amazon': {'amazon.com'},
    'netflix': {'netflix.com'},
    'chase': {'chase.com'},
    'bankofamerica': {'bankofamerica.com'},
    'yahoo': {'yahoo.com'}
}

def check_dns_resolution(domain):
    """
    Attempts to resolve the domain to an IP address.
    Returns (1, resolved_ip) if successful, (0, "Unresolved") otherwise.
    """
    if not domain:
        return 0, "Unresolved"
    try:
        # Set a short timeout for socket resolution
        socket.setdefaulttimeout(1.2)
        ip = socket.gethostbyname(domain)
        return 1, ip
    except Exception:
        return 0, "Unresolved"

def check_brand_impersonation(domain):
    """
    Checks if a domain contains a major brand name but is not one of the official brand domains.
    Returns 1 if it is an impersonator, 0 otherwise.
    """
    domain = domain.lower()
    for brand, official_set in OFFICIAL_DOMAINS.items():
        if brand in domain:
            is_official = False
            for off_dom in official_set:
                if domain == off_dom or domain.endswith('.' + off_dom):
                    is_official = True
                    break
            if not is_official:
                return 1
    return 0

def get_features(url):
    """
    Extract features from a URL for machine learning classification.
    Returns a dictionary of features.
    """
    features = {}
    
    # Clean and parse URL
    if not url.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url
        
    try:
        parsed_url = urllib.parse.urlparse(url_to_parse)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
    except Exception:
        domain = ""
        path = ""
        query = ""

    # Feature 1: URL Length (Phishing URLs are often longer)
    features['url_length'] = len(url)
    
    # Feature 2: Domain Length
    features['domain_length'] = len(domain)
    
    # Feature 3: Dot Count in URL (excluding http://)
    features['dot_count'] = url.count('.')
    
    # Feature 4: Hyphen Count in Domain (Phishing domains often use hyphens, e.g. pay-pal.com)
    features['domain_hyphens'] = domain.count('-')
    
    # Feature 5: Special characters in URL
    features['hyphen_count'] = url.count('-')
    features['at_count'] = url.count('@')
    features['question_count'] = url.count('?')
    features['equal_count'] = url.count('=')
    features['underscore_count'] = url.count('_')
    
    # Feature 6: Presence of IP Address in Domain name
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    # Check if domain looks like an IP
    is_ip = 1 if re.match(ip_pattern, domain) or any(char.isdigit() for char in domain.replace('.', '')) and len(domain.replace('.', '')) > 0 and all(c.isdigit() or c == '.' for c in domain) else 0
    features['has_ip'] = is_ip
    
    # Feature 7: Shortening Service check
    is_shortened = 1 if domain.lower() in SHORTENING_SERVICES else 0
    features['is_shortened'] = is_shortened
    
    # Feature 8: Presence of HTTPS (1 = legitimate, 0 = phishing/suspicious HTTP)
    features['is_https'] = 1 if url.startswith('https://') else 0
    
    # Feature 9: Subdomain count (number of dots in domain - 1)
    # e.g., login.paypal.com has 2 dots, so subdomain count is 1 (excluding com)
    dot_domain = domain.count('.')
    features['subdomain_count'] = max(0, dot_domain - 1)
    
    # Feature 10: Presence of another domain in the path or query
    # Phishing URLs often put legitimate domains in paths: e.g., facebook.com/login/paypal.com
    has_domain_in_path = 0
    for keyword in ['.com', '.org', '.net', '.info', '.biz', '.co']:
        if keyword in path or keyword in query:
            has_domain_in_path = 1
            break
    features['domain_in_path'] = has_domain_in_path
    
    # Feature 11: Suspicious keywords count in URL
    keyword_count = 0
    url_lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            keyword_count += 1
    features['suspicious_keyword_count'] = keyword_count
    
    # Feature 12: Directory Depth (number of slashes in path)
    features['directory_depth'] = path.count('/')
    
    # Feature 13: Brand Impersonation in domain
    features['brand_impersonation'] = check_brand_impersonation(domain)
    
    # Feature 14: DNS Resolution check (1 = resolves/online, 0 = unresolved/offline)
    dns_res, res_ip = check_dns_resolution(domain)
    features['dns_resolved'] = dns_res
    features['resolved_ip'] = res_ip
    
    return features

def get_feature_names():
    """
    Returns the ordered list of feature names used for model input.
    """
    return [
        'url_length',
        'domain_length',
        'dot_count',
        'domain_hyphens',
        'hyphen_count',
        'at_count',
        'question_count',
        'equal_count',
        'underscore_count',
        'has_ip',
        'is_shortened',
        'is_https',
        'subdomain_count',
        'domain_in_path',
        'suspicious_keyword_count',
        'directory_depth',
        'brand_impersonation',
        'dns_resolved'
    ]

