from flask import Flask, request, jsonify, render_template
import requests
import base64
import re
import json
import time
import os
import random
import socket
import urllib3
import whois
import shelve
from tor_proxy import get_tor_session  # Import the Tor proxy handler
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


# Set the allowed image file extensions
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'bmp', 'tiff'}

# Set the maximum file size (1.5 MB)
MAX_FILE_SIZE = 1.5 * 1024 * 1024  # 1.5 MB

# Check if the file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

BLOCKLIST_CACHE_FILE = "blocklist_cache.txt"
CACHE_EXPIRY_TIME = 3600  # Cache expiry time in seconds (1 hour)

# Global variable to hold the blocklist
blocked_domains = set()

def load_blocklist(url):
    current_time = time.time()
    print(f"Checking if cache is valid...")  # Debug log
    # Check if cached blocklist exists and is not expired
    if os.path.exists(BLOCKLIST_CACHE_FILE):
        cache_age = current_time - os.path.getmtime(BLOCKLIST_CACHE_FILE)
        print(f"Cache age: {cache_age} seconds")  # Debug log
        if cache_age < CACHE_EXPIRY_TIME:
            print("Using cached blocklist.")  # Debug log
            with open(BLOCKLIST_CACHE_FILE, 'r') as file:
                return set(file.read().splitlines())
    
    print("Fetching blocklist from URL...")  # Debug log
    # Fetch the blocklist from the URL if the cache is expired or doesn't exist
    try:
        response = requests.get(url)
        if response.status_code == 200:
            # Decode byte strings to normal strings and collect them into a set
            blocklist = set(line.decode('utf-8').strip() for line in response.iter_lines())
            print(f"Fetched {len(blocklist)} domains.")  # Debug log
            # Save the blocklist to the cache file
            with open(BLOCKLIST_CACHE_FILE, 'w') as cache_file:
                cache_file.write("\n".join(blocklist))
            print(f"Blocklist cached to {BLOCKLIST_CACHE_FILE}.")  # Debug log
            return blocklist
        else:
            print(f"Failed to fetch blocklist. Status code: {response.status_code}")
            return set()
    except requests.RequestException as e:
        print(f"Error fetching blocklist: {e}")
        return set()

# Load the blocklist at startup (and cache it for future use)
blocklist_url = "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/refs/heads/master/block.txt"
blocked_domains = load_blocklist(blocklist_url)

# Set the maximum upload size to 100MB
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

def select_random_user_agent(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            if not lines:
                raise ValueError("The file is empty")
            return random.choice(lines).strip()
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except ValueError as ve:
        print(ve)

def upload_image(base64_image, use_tor=False):
    try:
        data = {"image": base64_image}
        url = "https://pimeyes.com/api/upload/file"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # If Tor proxy is enabled, use it
        if use_tor:
            session = get_tor_session()
            response = session.post(url, headers=headers, json=data, verify=False)
        else:
            response = requests.post(url, headers=headers, json=data, verify=False)
        
        if response.status_code == 200:
            print("Image uploaded successfully.")
            if not response.json().get("faces"):
                print("No faces found in uploaded image.")
                return None, None
            return response.cookies, response.json().get("faces")[0]["id"]
        else:
            print(f"Failed to upload image. Status code: {response.status_code}")
            print(response.text)
            return None, None
    except Exception as e:
        print(f"Error uploading image: {e}")
        return None, None

def get_ip_address_through_tor():
    try:
        session = get_tor_session()
        response = session.get("https://httpbin.org/ip", verify=False)
        if response.status_code == 200:
            return response.json().get("origin")
        else:
            return "Could not retrieve IP address"
    except Exception as e:
        return f"Error retrieving IP: {e}"

def exec_search(cookies, search_id, user_agent, use_tor=False):
    headers = {
        'sec-ch-ua': '"Not;A=Brand";v="99", "Chromium";v="106"',
        'accept': 'application/json, text/plain, */*',
        'content-type': 'application/json',
        'sec-ch-ua-mobile': '?0',
        'user-agent': user_agent,
        'origin': 'https://pimeyes.com',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://pimeyes.com/en',
        'accept-encoding': 'gzip, deflate',
        'accept-language': 'en-US,en;q=0.9'
    }
    url = "https://pimeyes.com/api/search/new"
    data = {
        "faces": [search_id],
        "time": "any",
        "type": "PREMIUM_SEARCH",
        "g-recaptcha-response": None
    }
    # If Tor proxy is enabled, use it
    if use_tor:
        session = get_tor_session()
        response = session.post(url, headers=headers, json=data, cookies=cookies)
    else:
        response = requests.post(url, headers=headers, json=data, cookies=cookies)

    if response.status_code == 200:
        json_response = response.json()
        return json_response.get("searchHash"), json_response.get("searchCollectorHash")
    else:
        print(f"Failed to get searchHash. Status code: {response.status_code}")
        print(response.text)
        return None, None


def extract_url_from_html(html_content):
    pattern = r'api-url="([^"]+)"'
    url = re.search(pattern, html_content)
    if url:
        return re.search(r'https://[^\"]+', url.group()).group()
    return None

def get_ip_address_through_tor():
    try:
        session = get_tor_session()
        response = session.get("https://httpbin.org/ip", verify=False)
        if response.status_code == 200:
            return response.json().get("origin")
        else:
            return "Could not retrieve IP address"
    except Exception as e:
        return f"Error retrieving IP: {e}"


def find_results(search_hash, search_collector_hash, search_id, cookies, use_tor=False):
    url = f"https://pimeyes.com/en/results/{search_collector_hash}_{search_hash}?query={search_id}"
    
    # If Tor proxy is enabled, use it
    if use_tor:
        session = get_tor_session()
        response = session.get(url, cookies=cookies)
    else:
        response = requests.get(url, cookies=cookies)
    
    if response.status_code == 200:
        print("Found correct server.")
        return extract_url_from_html(response.text)
    else:
        print(f"Failed to find results. Status code: {response.status_code}")
        print(response.text)
        return None


def get_results(url, search_hash, user_agent):
    data = {
        "hash": search_hash,
        "limit": 250,
        "offset": 0,
        "retryCount": 0
    }
    headers = {
        'sec-ch-ua': '"Not;A=Brand";v="99", "Chromium";v="106"',
        'accept': 'application/json, text/plain, */*',
        'content-type': 'application/json',
        'sec-ch-ua-mobile': '?0',
        'user-agent': user_agent,
        'origin': 'https://pimeyes.com',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://pimeyes.com/en',
        'accept-encoding': 'gzip, deflate',
        'accept-language': 'en-US,en;q=0.9'
    }
    response = requests.post(url, headers=headers, json=data, verify=False)
    if response.status_code == 200:
        print("Results obtained successfully.")
        return response.json()
    else:
        print(f"Failed to obtain results. Status code: {response.status_code}")
        print(response.text)
        return None

def hex_to_ascii(hex_string):
    hex_string = hex_string.lstrip('0x')
    bytes_data = bytes.fromhex(hex_string)
    return bytes_data.decode('ascii', errors='ignore')

def normalize_domain(domain):
    """
    Normalize the domain name to ensure it matches the blocklist format.
    This includes removing common subdomains like 'www.', 'pic.', 'static.' and converting to lowercase.
    """
    domain = domain.lower()
    
    # Remove common subdomains if they exist
    subdomains_to_remove = ['www.', 'pic.', 'static.', 'm.', 'cdn.', 'api.','public.']  # Add more subdomains as needed
    for subdomain in subdomains_to_remove:
        if domain.startswith(subdomain):
            domain = domain[len(subdomain):]
            break  # Only remove the first matching subdomain
    
    return domain

def classify_site(url):
    domain = re.search(r'https?://([^/]+)', url).group(1)
    normalized_domain = normalize_domain(domain)

    print(f"Checking domain: {normalized_domain}")  # Debug log
    
    # Check if the site is an adult site
    if is_adult_site(url):
        return "Adult Site"
    
    # Check if the domain is in the blocklist
    if domain in blocked_domains:
        print(f"Domain {normalized_domain} is in blocklist.")  # Debug log
        return "Adult Site"
    
    # Replace ICANN-based classification with WHOIS-based classification
    elif classify_site_with_whois(domain) == "Social E-Commerce Site":
        return "Social E-Commerce Site"
    
    return "Unclassified Site"



def is_adult_site(url):
    # Extract the domain from the URL
    domain = re.search(r'https?://([^/]+)', url)
    
    if domain:
        domain = domain.group(1)
        
        # Check if the domain is in the blocklist
        if domain in blocked_domains:
            return True
    
    return False

def is_social_e_commerce_site(url):
    # List of known social e-commerce websites
    social_e_commerce_sites = [
        'pinterest.com', 'instagram.com', 'facebook.com', 'etsy.com', 
        'poshmark.com', 'depop.com', 'mercari.com', 'letgo.com', 
        'offerup.com', 'carousell.com', 'vinted.com', 'thredup.com', 
        'tradesy.com', 'grailed.com', 'reverb.com', 'jet.com', 
        'socialshopwave.com', 'shoploop.app', 'verishop.com', 'wanelo.com', 
        'fancy.com', 'polyvore.com', 'liketoknow.it', 'shopstyle.com', 
        'keep.com', 'lyst.com', 'mightybuy.co', 'yelpextensions.com', 
        'shpock.com', 'rumgr.com', 'curtsyapp.com', '5miles.com', 
        'swappa.com', 'wallapop.com', 'barnesandnoble.com', 'notonthehighstreet.com', 
        'bigcartel.com', 'cratejoy.com', 'lazada.com', 'shopee.com',
        'geekbuying.com', 'kikuu.com', 'carrefour.com', 'jumia.com', 
        'tophatter.com', 'overstock.com', 'newegg.com', 'wayfair.com', 
        'zalando.com', 'asos.com', 'fashionnova.com', 'boohoo.com', 
        'shein.com', 'romwe.com', 'yesstyle.com', 'tictail.com', 
        'dote.com', 'curtsy.com', 'shoptiques.com', 'beruby.com',
        'indiebazaar.com', 'trendyol.com', 'flipkart.com', 'jabong.com',
        'shopclues.com', 'ajio.com', 'myntra.com', 'snapdeal.com',
        'kith.com', 'farfetch.com', 'mytheresa.com', 'mrporter.com',
        'brownsfashion.com', 'matchesfashion.com', 'ssense.com', 'yoox.com',
        'modaoperandi.com', 'vitrue.com', 'fancy.com', 'farfetch.com',
        'poshmark.com', 'pinimg.com'
    ]
    
    # Check if any of the social e-commerce site domains are in the page URL
def resolve_domain_whois(domain, cache_file='whois_cache.db', cache_expiry=86400):  # Cache expiry time in seconds (e.g., 1 day)
    try:
        with shelve.open(cache_file) as cache:
            if domain in cache:
                cached_data, timestamp = cache[domain]
                if time.time() - timestamp < cache_expiry:
                #     print(f"Cache hit for domain: {domain}")
                    return cached_data
                # else:
                #     print(f"Cache expired for domain: {domain}. Performing WHOIS lookup.")
            # else:
            #     print(f"Cache miss for domain: {domain}. Performing WHOIS lookup.")
            
            domain_info = whois.whois(domain)
            cache[domain] = (domain_info, time.time())
            return domain_info
    except Exception as e:
        print(f"Error resolving domain: {e}")
        return None

def classify_site_with_whois(domain):
    # Mapping of known subdomains to their main domains
    domain_mappings = {
        "i.etsystatic.com": "etsy.com",
        "mir-s3-cdn-cf.behance.net": "behance.net",
        "i.pinimg.com": "pinterest.com"
    }
    
    # Check if the domain matches any known subdomains
    for subdomain, main_domain in domain_mappings.items():
        if subdomain in domain:
            return main_domain
    
    # List of known main domains
    main_domains = ["etsy.com", "behance.net", "pinterest.com"]
    
    # Check if the domain is a subdomain of any known main domains
    for main_domain in main_domains:
        if domain.endswith(main_domain):
            return main_domain

    # Resolve WHOIS information for the domain (if it's not a subdomain)
    domain_info = resolve_domain_whois(domain)
    
    if not domain_info:
        return "Unclassified Site"
    
    # Check if the domain matches known social e-commerce sites
    if is_social_e_commerce_site(domain):
        return "Social E-Commerce Site"
    
    return "Unclassified Site"

def process_thumbnails(json_data):
    results = json_data.get('results', [])
    if not results:
        return "Search successful, but no matches found."

    processed_results = []
    for result in results:
        thumbnail_url = result.get('thumbnailUrl', '')
        match = re.search(r'/proxy/([0-9a-fA-F]+)', thumbnail_url)
        if match:
            hex_part = match.group(1)
            ascii_text = hex_to_ascii(hex_part)
            try:
                ascii_data = json.loads(ascii_text)
                page_url = ascii_data.get('url')
                site = result.get('site', '')
                
                # Resolve the domain from the page URL if needed
                if not site and page_url:
                    site = re.search(r'https?://([^/]+)', page_url).group(1) if page_url else 'Unknown site'
                
                # Resolve domain classification
                domain = re.search(r'https?://([^/]+)', page_url).group(1) if page_url else ''
                resolved_domain = classify_site_with_whois(domain)  # Resolve the domain using WHOIS
                
                # Check if the site is adult or social e-commerce
                is_adult = is_adult_site(page_url)
                is_social_e_commerce = is_social_e_commerce_site(page_url)
                
                if page_url:
                    processed_results.append({
                        "page_url": page_url,
                        "account_info": result.get('accountInfo', 'Not available'),
                        "thumbnail_url": thumbnail_url,
                        "site": site,
                        "resolved_domain": resolved_domain,  # Add resolved domain here
                        "is_adult": is_adult,
                        "is_social_e_commerce": is_social_e_commerce
                    })
            except json.JSONDecodeError:
                print("Failed to decode JSON from ASCII text.")
    
    return processed_results

@app.route("/", methods=["GET", "POST"])
def index():
    use_tor = request.form.get("use_tor") == "on"  # Check if user wants to use Tor
    tor_ip = None
    if use_tor:
        tor_ip = get_ip_address_through_tor()  # Get the IP address used by Tor

    if request.method == "POST":
        file = request.files.get("file")
        pasted_image = request.form.get("pasted_image")

        if not file and not pasted_image:
            return render_template("index.html", error="No selected file or pasted image", tor_ip=tor_ip)

        if file:
            base64_image = base64.b64encode(file.read()).decode("utf-8")
            base64_image = f"data:image/jpeg;base64,{base64_image}"

        elif pasted_image:
            base64_image = re.sub("^data:image/.+;base64,", "", pasted_image)
            base64_image = f"data:image/jpeg;base64,{base64_image}"

        cookies, search_id = upload_image(base64_image, use_tor)
        if not cookies or not search_id:
            return render_template("index.html", error="Failed to upload image", tor_ip=tor_ip)

        cookies.set("payment_gateway_v3", "fastspring", domain="pimeyes.com")
        cookies.set("uploadPermissions", str(time.time() * 1000)[:13], domain="pimeyes.com")
        
        user_agent = select_random_user_agent("user-agents.txt")

        search_hash, search_collector_hash = exec_search(cookies, search_id, user_agent, use_tor)
        if not (search_hash and search_collector_hash):
            return jsonify({"error": "Could not proceed with further API calls."}), 404
        
        server_url = find_results(search_hash, search_collector_hash, search_id, cookies, use_tor)
        if not server_url:
            return jsonify({"error": "Failed to find server URL."}), 404

        res = get_results(server_url, search_hash, user_agent)
        if res:
            results = process_thumbnails(res)
            if not results:
                return render_template('404.html', error="No matches found."), 404
            return render_template('results.html', results=results, tor_ip=tor_ip)
        else:
            return render_template('index.html', error="Failed to get results", tor_ip=tor_ip)

    return render_template('index.html', tor_ip=tor_ip)


def find_available_port(start_port=5000, max_port=65535):
    for port in range(start_port, max_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return port
            except socket.error:
                continue
    return None

if __name__ == '__main__':
    # Load the blocklist when the app starts
    blocked_domains = load_blocklist(blocklist_url)

    port = find_available_port()
    if port:
        print(f"Starting server on port {port}")
        app.run(debug=True, port=port)
    else:
        print("No available ports found.")
