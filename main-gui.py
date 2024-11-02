import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import requests
import base64
import re
import json
import time
import os
import random
import threading

class PimeyesGUI:
    def __init__(self, master):
        self.master = master
        master.title("Pimeyes Image Search")
        master.geometry("600x500")

        self.label = tk.Label(master, text="Select an image to search:")
        self.label.pack()

        self.select_button = tk.Button(master, text="Select Image", command=self.select_image)
        self.select_button.pack()

        self.search_button = tk.Button(master, text="Search", command=self.start_search, state=tk.DISABLED)
        self.search_button.pack()

        self.result_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70, height=20)
        self.result_area.pack(padx=10, pady=10)

        self.save_button = tk.Button(master, text="Save Results", command=self.save_results, state=tk.DISABLED)
        self.save_button.pack(pady=10)

        self.image_path = None
        self.user_agent = self.select_random_user_agent("user-agents.txt")
        self.results = []

    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg *.jpeg *.png")])
        if self.image_path:
            self.search_button['state'] = tk.NORMAL
            self.result_area.insert(tk.END, f"Selected image: {self.image_path}\n")

    def start_search(self):
        self.result_area.delete('1.0', tk.END)
        self.result_area.insert(tk.END, "Starting search...\n")
        self.results = []  # Clear previous results
        self.save_button['state'] = tk.DISABLED
        threading.Thread(target=self.search, daemon=True).start()

    def search(self):
        if not os.path.exists(self.image_path):
            self.result_area.insert(tk.END, "Selected file does not exist.\n")
            return

        result = self.upload_image(self.image_path)
        if result is None or result[0] is None:
            self.result_area.insert(tk.END, "Failed to upload image. Please try again.\n")
            return

        cookies, search_id = result

        cookies.set("payment_gateway_v3", "fastspring", domain="pimeyes.com")
        cookies.set("uploadPermissions", str(int(time.time()*1000)), domain="pimeyes.com")

        search_result = self.exec_search(cookies, search_id)
        if search_result is None:
            self.result_area.insert(tk.END, "Failed to execute search.\n")
            return

        search_hash, search_collector_hash = search_result

        server_url = self.find_results(search_hash, search_collector_hash, search_id, cookies)
        if server_url is None:
            self.result_area.insert(tk.END, "Failed to find results server.\n")
            return

        res = self.get_results(server_url, search_hash)
        if res is None:
            self.result_area.insert(tk.END, "Failed to get results.\n")
            return

        self.process_thumbnails(res)
        
        if self.results:
            self.master.after(0, lambda: self.save_button.config(state=tk.NORMAL))
        else:
            self.result_area.insert(tk.END, "No results found to save.\n")

    def save_results(self):
        if not self.results:
            messagebox.showinfo("No Results", "There are no results to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    for result in self.results:
                        file.write(result + '\n')
                messagebox.showinfo("Save Successful", f"Results saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"An error occurred while saving: {str(e)}")

    def select_random_user_agent(self, file_path):
        try:
            with open(file_path, 'r') as file:
                user_agents = file.readlines()
            if not user_agents:
                raise ValueError("The user-agents.txt file is empty")
            return random.choice(user_agents).strip()
        except FileNotFoundError:
            self.result_area.insert(tk.END, f"Error: The file '{file_path}' does not exist.\n")
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        except ValueError as ve:
            self.result_area.insert(tk.END, f"Error: {str(ve)}\n")
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    def upload_image(self, image_path):
        try:
            with open(image_path, "rb") as image_file:
                base64_image = base64.b64encode(image_file.read()).decode('utf-8')
            base64_image = "data:image/jpeg;base64," + base64_image
            data = {"image": base64_image}
            url = "https://pimeyes.com/api/upload/file"
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            cookies = requests.cookies.RequestsCookieJar()
            response = requests.post(url, headers=headers, cookies=cookies, json=data)
            if response.status_code == 200:
                self.result_area.insert(tk.END, "Image uploaded successfully.\n")
                if response.json().get("faces"):
                    return response.cookies, response.json().get("faces")[0]["id"]
                else:
                    self.result_area.insert(tk.END, "No faces found in uploaded image.\n")
                    return None, None
            else:
                self.result_area.insert(tk.END, f"Failed to upload image. Status code: {response.status_code}\n")
                return None, None
        except Exception as e:
            self.result_area.insert(tk.END, f"Error uploading image: {str(e)}\n")
            return None, None

    def exec_search(self, cookies, search_id):
        try:
            headers = {
                'sec-ch-ua':'"Not;A=Brand";v="99", "Chromium";v="106"',
                'accept':'application/json, text/plain, */*',
                'content-type':'application/json',
                'sec-ch-ua-mobile': '?0',
                'user-agent': self.user_agent,
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
            response = requests.post(url, headers=headers, json=data, cookies=cookies)
            if response.status_code == 200:
                json_response = response.json()
                return json_response.get("searchHash"), json_response.get("searchCollectorHash")
            else:
                self.result_area.insert(tk.END, f"Failed to get searchHash. Status code: {response.status_code}\n")
                return None
        except Exception as e:
            self.result_area.insert(tk.END, f"Error executing search: {str(e)}\n")
            return None

    def extract_url_from_html(self, html_content):
        pattern = r'api-url="([^"]+)"'
        url = re.search(pattern, html_content)
        if url:
            url = url.group()
            return re.search(r'https://[^\"]+', url).group()
        return None

    def find_results(self, search_hash, search_collector_hash, search_id, cookies):
        try:
            url = f"https://pimeyes.com/en/results/{search_collector_hash}_{search_hash}?query={search_id}"
            response = requests.get(url, cookies=cookies)
            if response.status_code == 200:
                self.result_area.insert(tk.END, "Found correct server.\n")
                return self.extract_url_from_html(response.text)
            else:
                self.result_area.insert(tk.END, f"Failed to find results. Status code: {response.status_code}\n")
                return None
        except Exception as e:
            self.result_area.insert(tk.END, f"Error finding results: {str(e)}\n")
            return None

    def get_results(self, url, search_hash):
        try:
            data = {
                "hash": search_hash,
                "limit": 250,
                "offset": 0,
                "retryCount": 0
            }
            headers = {
                'sec-ch-ua':'"Not;A=Brand";v="99", "Chromium";v="106"',
                'accept':'application/json, text/plain, */*',
                'content-type':'application/json',
                'sec-ch-ua-mobile': '?0',
                'user-agent': self.user_agent,
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
                self.result_area.insert(tk.END, "Results obtained successfully.\n")
                return response.json()
            else:
                self.result_area.insert(tk.END, f"Failed to obtain results. Status code: {response.status_code}\n")
                return None
        except Exception as e:
            self.result_area.insert(tk.END, f"Error getting results: {str(e)}\n")
            return None

    def hex_to_ascii(self, hex_string):
        hex_string = hex_string.lstrip('0x')
        bytes_data = bytes.fromhex(hex_string)
        return bytes_data.decode('ascii', errors='ignore')

    def process_thumbnails(self, json_data):
        results = json_data.get('results', [])
        if len(results) == 0:
            self.result_area.insert(tk.END, "Search successful, but no matches found.\n")
        for result in results:
            thumbnail_url = result.get('thumbnailUrl', '')
            match = re.search(r'/proxy/([0-9a-fA-F]+)', thumbnail_url)
            if match:
                hex_part = match.group(1)
                ascii_text = self.hex_to_ascii(hex_part)
                try:
                    ascii_text = json.loads(ascii_text)
                    ascii_text = ascii_text.get('url')
                    self.result_area.insert(tk.END, f"{ascii_text}\n")
                    self.results.append(ascii_text)
                except json.JSONDecodeError:
                    self.result_area.insert(tk.END, f"Error decoding JSON for thumbnail: {thumbnail_url}\n")

root = tk.Tk()
gui = PimeyesGUI(root)
root.mainloop()
