import requests
from stem import Signal
from stem.control import Controller

def connect_to_tor():
    try:
        controller = Controller.from_port(port=9051)
        controller.authenticate()  # Use the password if set, e.g., controller.authenticate(password="your_password")
        controller.signal(Signal.NEWNYM)  # Signal Tor for a new identity
        return controller
    except Exception as e:
        print(f"Error connecting to Tor: {e}")
        return None

def get_tor_session():
    controller = connect_to_tor()
    if controller:
        session = requests.Session()
        session.proxies = {
            'http': 'socks5h://localhost:9050',
            'https': 'socks5h://localhost:9050',
        }
        return session
    else:
        return None
