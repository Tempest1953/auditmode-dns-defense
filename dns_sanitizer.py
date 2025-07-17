# dns_sanitizer.py
# Braylock Global - DNS Threat Defense Sample
# MIT License

import re

def sanitize_txt_record(txt):
    """Remove unsafe characters from a DNS TXT record."""
    return re.sub(r'[^a-zA-Z0-9\s\-_.@=]', '', txt)

def has_magic_bytes(txt):
    """Check for known magic byte hex signatures in a DNS TXT record."""
    known_signatures = ["4D5A", "25504446", "504B0304"]  # EXE, PDF, ZIP
    hex_txt = txt.encode().hex().upper()
    return any(sig in hex_txt for sig in known_signatures)

# Example usage
dns_txt = "This is clean text, but maybe...MZ\x90\x00 or %PDF-1.5 hidden inside."
clean_txt = sanitize_txt_record(dns_txt)

if has_magic_bytes(clean_txt):
    print("⚠️ Potential embedded binary detected!")
else:
    print("✅ TXT record is clean.")
