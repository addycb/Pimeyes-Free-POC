import socks
import socket
import requests
from stem import Signal
from stem.control import Controller

def set_tor_proxy():
    """Sets the proxy to Tor."""
    socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)  # Tor's default SOCKS proxy port
    socket.socket = socks.socksocket

def renew_tor_ip():
    """Renews the Tor IP address."""
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        print("New Tor IP address has been set.")
        
def get_tor_session():
    """Returns a requests session configured to use Tor."""
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://localhost:9050',
        'https': 'socks5h://localhost:9050'
    }
    return session

if __name__ == "__main__":
    set_tor_proxy()  # Set the Tor proxy
    renew_tor_ip()  # Renew the IP (optional, for avoiding rate limiting)
