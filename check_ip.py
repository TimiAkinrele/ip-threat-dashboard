import requests
#import os
#import time
import ipaddress
#import csv
#from dotenv import load_dotenv
import streamlit as st


#load environment variables
#load_dotenv()

API_KEY = st.secrets["api"]["abuseipdb_key"]

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_ip(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        if response.status_code == 200:
            return response.json()['data']
        else:
            st.error(f"API Error {response.status_code}: {response.text}")
    except requests.exceptions.RequestException as e:
        st.error(f"Network Error: {e}")
    return None

    if response.status_code == 200:
        data = response.json()['data']
        print(f"\n IP: {ip_address}")
        print(f" - Abuse Score: {data['abuseConfidenceScore']} /100")
        print(f" - Country: {data['countryCode']} | ISP: {data['isp']}")
        print(f" - Reports: {data['totalReports']}")
        print(f" - Last Seen: {data['lastReportedAt']}")
        return data
    else:
        print(f"\n Error {response.status_code}: {response.text}")
        return None

def load_logged_ips(filename="ip_report.csv"):
    if not os.path.exists(filename):
        return set()
    with open(filename, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return {row['IP'] for row in reader}

def save_to_csv(data, filename="ip_report.csv"):
    already_logged = load_logged_ips(filename)
    if data['ipAddress'] in already_logged:
        print(f"Already logged: {data['ipAddress']}")
        return

    file_exists = os.path.isfile(filename)
    with open(filename, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["IP", "Abuse Score", "Country", "ISP", "Reports", "Last Seen"])
        writer.writerow([
            data['ipAddress'],
            data['abuseConfidenceScore'],
            data['countryCode'],
            data['isp'],
            data['totalReports'],
            data['lastReportedAt']
        ])

def batch_checker(batch_ips="ips.txt"):
    if not os.path.isfile(batch_ips):
        raise FileNotFoundError(f"{batch_ips} not found.")

    with open(batch_ips, mode ='r') as f:
        for i, line in enumerate(f):
            ip = line.strip()
            if not ip:
                continue
            print(f"Checking {i + 1}: {ip}")
            result = check_ip(ip)
            if result:
                save_to_csv(result)
            time.sleep(1)



if __name__ == "__main__":
    print("Welcome to IP Threat Checker")
    print("- Type `Search` to look up one IP")
    print("- Type `Batch` to scan multiple IPs from `ips.txt`")
    print("- Type `x` to end\n")
    while True:
        choice = input("Type 'Search' to check one IP, 'Batch' to scan a file, or `x` to stop: ").strip().lower()    
        
        if choice == "search":
            ip = input("Enter IP to check: ").strip()
            if is_valid_ip(ip):
                result = check_ip(ip)
                if result:
                    save_to_csv(result)
            else:
                print("Invalid IP address format")
            
        elif choice == "batch": 
            batch_checker()
            

        elif choice == "x":
            print("Exiting. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please type 'Search', 'Batch' or 'x'.\n")

        