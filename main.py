import requests
import base64
import re
import json
import time
import os

def upload_image(image_path):
    # Encode the image to base64
    with open(image_path, "rb") as image_file:
        base64_image = base64.b64encode(image_file.read()).decode('utf-8')
    image_file.close()
    base64_image="data:image/jpeg;base64,"+base64_image
    # Prepare the payload
    data = {
        "image": base64_image
    }
    # POST request to upload the image
    url = "https://pimeyes.com/api/upload/file"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    cookies=requests.cookies.RequestsCookieJar()
    response = requests.post(url, headers=headers, cookies=cookies, json=data)
    if response.status_code == 200:
        print("Image uploaded successfully.")
        #print(response.text)
        #print(response.json().get("faces")[0]["id"])
        return response.cookies,response.json().get("faces")[0]["id"]
    else:
        print(f"Failed to upload image. Status code: {response.status_code}")
        print(response.text)
        print(response.status_code)
        print(response.json())
        return None, None

def exec_search(cookies,search_id):
    #Cookies are already Setup, hope uploadperms cookie is
    #Headers are good
    headers = {
    'sec-ch-ua':'"Not;A=Brand";v="99", "Chromium";v="106"',
    'accept':'application/json, text/plain, */*',
    'content-type':'application/json',
    'sec-ch-ua-mobile': '?0',
    'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36',
    'sec-ch-ua-platform':'"Linux"',
    'origin':'https://pimeyes.com',
    'sec-fetch-site':'same-origin',
    'sec-fetch-mode':'cors',
    'sec-fetch-dest':'empty',
    'referer':'https://pimeyes.com/en',
    'accept-encoding':'gzip, deflate',
    'accept-language':'en-US,en;q=0.9'
    }
    url = "https://pimeyes.com/api/search/new"
    data = {
    "faces": [search_id],
    "time": "any",
    "type": "PREMIUM_SEARCH",
    "g-recaptcha-response": None
    }
    response = requests.post(url,headers=headers,json=data,cookies=cookies)
    if response.status_code == 200:
        # Extract the JSON response body
        print(response.text)
        json_response = response.json()
        search_hash = json_response.get("searchHash")
        search_collector_hash = json_response.get("searchCollectorHash")
        return search_hash, search_collector_hash
    else:
        print(f"Failed to get searchHash. Status code: {response.status_code}")
        print(response.text)
        return None, None

def extract_url_from_html(html_content):
    # Define the regular expression pattern to find api-url="my_url"
    pattern = r'api-url="([^"]+)"'
    url=re.search(pattern,html_content)
    url = url.group()  # This will give 'api-url="https://jsc12.pimeyes.com/get_results"'
    # Extract the URL from the full match string
    url = re.search(r'https://[^\"]+', url).group()  # This regex extracts the URL
    return url

def find_results(search_hash, search_collector_hash, search_id, cookies):
    url="https://pimeyes.com/en/results/"+search_collector_hash+"_"+search_hash+"?query="+search_id
    response = requests.get(url,cookies=cookies)
    if response.status_code == 200:
        print("Found correct server.")
        return extract_url_from_html(response.text)

def get_results(url,search_hash):
    # Prepare the payload
    data = {
        "hash": search_hash,
        "limit": 250,
        "offset": 0,
        "retryCount": 0
    }
    # POST request to get results 
    headers = {
    'sec-ch-ua':'"Not;A=Brand";v="99", "Chromium";v="106"',
    'accept':'application/json, text/plain, */*',
    'content-type':'application/json',
    'sec-ch-ua-mobile': '?0',
    'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36',
    'sec-ch-ua-platform':'"Linux"',
    'origin':'https://pimeyes.com',
    'sec-fetch-site':'same-origin',
    'sec-fetch-mode':'cors',
    'sec-fetch-dest':'empty',
    'referer':'https://pimeyes.com/en',
    'accept-encoding':'gzip, deflate',
    'accept-language':'en-US,en;q=0.9'
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        print("Results obtained successfully.")
        #{"archiveResults":0,"isMoreResults":false,"numberOfResults":0,"results":[],"time":2015,"type":"FREE_SEARCH"}
        #Add a message if results are empty
        return response.json()
    else:
        print(f"Failed to obtain results. Status code: {response.status_code}")
        print(response.text)

def hex_to_ascii(hex_string):
    # Remove '0x' prefix if present
    hex_string = hex_string.lstrip('0x')
    # Convert hex string to bytes
    bytes_data = bytes.fromhex(hex_string)
    # Convert bytes to ASCII string
    ascii_string = bytes_data.decode('ascii', errors='ignore')
    
    return ascii_string


def process_thumbnails(json_data):
    results = json_data.get('results', [])
    if len(results) == 0:
        print("Search successful, but no matches found.")
    for result in results:
        thumbnail_url = result.get('thumbnailUrl', '')
        # Extract the hex part after /proxy/
        match = re.search(r'/proxy/([0-9a-fA-F]+)', thumbnail_url)
        if match:
            hex_part = match.group(1)
            ascii_text = hex_to_ascii(hex_part)
            ascii_text=json.loads(ascii_text)
            ascii_text=ascii_text.get('url')
            print(ascii_text)

def getimg():
    print("Starting new search")
    
    while True:
        # Call the upload img func to get cookies and searchid 
        print("Input path to image:")
        image_path = input().strip()
        
        # Check if the file exists and is a file
        if os.path.isfile(image_path):
            return image_path
        else:
            print("Invalid file path. Please try again.")

def search(image_path):
    cookies,search_id=upload_image(image_path)
    # Set needed cookies
    cookies.set("payment_gateway_v3","fastspring",domain="pimeyes.com")
    cookies.set("uploadPermissions",str(time.time()*1000)[:13],domain="pimeyes.com")
    #Execute search to get search hash info
    search_hash, search_collector_hash = exec_search(cookies,search_id)
    if search_hash and search_collector_hash and cookies:
        # Now you can use search_hash and session_cookies for further API calls
        print("Ready for further API calls.")
    else:
        print("Could not proceed with further API calls.")
    serverurl=find_results(search_hash,search_collector_hash,search_id,cookies)
    res=get_results(serverurl,search_hash)
    process_thumbnails(res)

image_path=getimg()
search(image_path)