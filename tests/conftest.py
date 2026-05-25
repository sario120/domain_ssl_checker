import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ssl_domain_checker"))

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-purposes-only"
os.environ["ENCRYPTION_KEY"] = "test-encryption-key-for-testing-purposes-only"
os.environ["WHOIS_TIMEOUT"] = "2"
os.environ["WHOIS_CACHE_TTL"] = "0"
os.environ["ADMIN_PASSWORD"] = "test-admin-password"
