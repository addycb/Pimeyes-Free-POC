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

# Suppress only the single InsecureRequestWarning from urllib3 needed for this request.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

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

def upload_image(base64_image):
    try:
        data = {"image": base64_image}
        url = "https://pimeyes.com/api/upload/file"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        cookies = requests.cookies.RequestsCookieJar()
        response = requests.post(url, headers=headers, cookies=cookies, json=data, verify=False)
        
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

def exec_search(cookies, search_id, user_agent):
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

def find_results(search_hash, search_collector_hash, search_id, cookies):
    url = f"https://pimeyes.com/en/results/{search_collector_hash}_{search_hash}?query={search_id}"
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

def classify_site(url):
    if is_adult_site(url):
        return "Adult Site"
    elif is_social_e_commerce_site(url):
        return "Social E-Commerce Site"
    else:
        return "Unclassified Site"

def is_adult_site(url):
    # Expanded list of known adult or borderline adult websites
    adult_sites = [
        'pornhub.com', 'xvideos.com', 'redtube.com', 'xhamster.com',
        'curvage.org', 'onlyfans.com', 'fansly.com', 'cammodel.com', 'tube8.com', 
        'bangbros.com', 'spankwire.com', 'youporn.com', 'metart.com', 
        'javlibrary.com', 'brazzers.com', 'playboy.com', 'hustler.com', 
        'chaturbate.com', 'cam4.com', 'myfreecams.com', 'livejasmin.com', 
        'bongacams.com', 'camsoda.com', 'imlive.com', 'stripchat.com', 
        'adultfriendfinder.com', 'fapdu.com', 'xxxbunker.com', 'cliphunter.com', 
        'motherless.com', 'tnaflix.com', 'drtuber.com', 'pornmd.com', 
        'xtube.com', 'xhamsterlive.com', 'camster.com', 'camwhores.tv', 
        'private.com', 'naughtyamerica.com', '8muses.com',
        'rule34.xxx', 'gelbooru.com', 'danbooru.donmai.us', 'e621.net',
        'hentai-foundry.com', 'fakku.net', 'hentaihaven.org', 'hanime.tv',
        'rule34hentai.net', 'pururin.to', 'hentai2read.com', 'doujins.com',
        'fantasyfeeder.com', 'feedist.net', 'bbwchan.net', 'onlyfinder.com'
    ]
    
    # Check if any of the adult site domains are in the page URL
    for site in adult_sites:
        if site in url:
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
        'poshmark.com', 'etsystatic.com', 'pinimg.com'
    ]
    
    # Check if any of the social e-commerce site domains are in the page URL
    for site in social_e_commerce_sites:
        if site in url:
            return True
    return False

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
                if not site and page_url:
                    site = re.search(r'https?://([^/]+)', page_url).group(1) if page_url else 'Unknown site'
                
                is_adult = is_adult_site(page_url)  # Check if the page is an adult site
                is_social_e_commerce = is_social_e_commerce_site(page_url)  # Check if the page is a social e-commerce site
                
                if page_url:
                    processed_results.append({
                        "page_url": page_url,
                        "account_info": result.get('accountInfo', 'Not available'),
                        "thumbnail_url": thumbnail_url,
                        "site": site,
                        "is_adult": is_adult,  # Add adult site info
                        "is_social_e_commerce": is_social_e_commerce  # Add social e-commerce info
                    })
            except json.JSONDecodeError:
                print("Failed to decode JSON from ASCII text.")
    
    return processed_results

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("file")
        pasted_image = request.form.get("pasted_image")

        if not file and not pasted_image:
            return render_template("index.html", error="No selected file or pasted image")

        # Handle the uploaded image file
        if file:
            base64_image = base64.b64encode(file.read()).decode("utf-8")
            base64_image = f"data:image/jpeg;base64,{base64_image}"  # Add the prefix to ensure correct format

        # Handle the pasted image from the clipboard
        elif pasted_image:
            base64_image = re.sub("^data:image/.+;base64,", "", pasted_image)
            base64_image = f"data:image/jpeg;base64,{base64_image}"  # Ensure the prefix is included

        # Upload the image to Pimeyes API
        cookies, search_id = upload_image(base64_image)
        if not cookies or not search_id:
            return render_template("index.html", error="Failed to upload image")

        # Process the cookies and proceed with the search
        cookies.set("payment_gateway_v3", "fastspring", domain="pimeyes.com")
        cookies.set("uploadPermissions", str(time.time() * 1000)[:13], domain="pimeyes.com")
        
        user_agent = select_random_user_agent("user-agents.txt")

        # Execute the search
        search_hash, search_collector_hash = exec_search(cookies, search_id, user_agent)
        if not (search_hash and search_collector_hash):
            return jsonify({"error": "Could not proceed with further API calls."})
        
        server_url = find_results(search_hash, search_collector_hash, search_id, cookies)
        if not server_url:
            return jsonify({"error": "Failed to find server URL."})

        # Get the results
        res = get_results(server_url, search_hash, user_agent)
        if res:
            results = process_thumbnails(res)
            return render_template('results.html', results=results)
        else:
            return render_template('index.html', error="Failed to get results")

    return render_template('index.html')


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
    port = find_available_port()
    if port:
        print(f"Starting server on port {port}")
        app.run(debug=True, port=port)
    else:
        print("No available ports found.")
