# agent/tools/utils.py
from ipaddress import ip_address, AddressValueError

def is_ip(value: str) -> bool:
    """Check if string is a valid IPv4/IPv6 address"""
    try:
        ip_address(value)
        return True
    except AddressValueError:
        return False  # Return False instead of raising error