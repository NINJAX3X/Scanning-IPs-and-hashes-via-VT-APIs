import requests
import time
import sys
import csv
from datetime import datetime

# ==============================
# CONFIGURATION
# ==============================
API_KEY = "API_KEY"  # Replace with your API key
with open("ips.txt") as f:
    IP_LIST = [line.strip() for line in f if line.strip()]  # Replace with your IPs or load from file
RATE_LIMIT_DELAY = 20  # Seconds to wait between requests (free tier limit)
OUTPUT_CSV = f"vt_ip_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# ==============================
# FUNCTIONS
# ==============================

def reanalyze_ip(ip):
    """
    Sends a reanalysis request for the given IP to VirusTotal.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/analyse"
    headers = {"x-apikey": API_KEY}
    try:
        resp = requests.post(url, headers=headers)
        if resp.status_code == 200:
            analysis_id = resp.json().get("data", {}).get("id")
            return analysis_id
        else:
            print(f"[ERROR] Failed to reanalyze {ip}: {resp.status_code} {resp.text}")
            return None
    except requests.RequestException as e:
        print(f"[ERROR] Network error for {ip}: {e}")
        return None


def get_analysis_results(ip):
    """
    Retrieves the latest analysis results for the given IP.
    Returns the 'malicious' count (int) or None on error.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return malicious
        else:
            print(f"[ERROR] Failed to get results for {ip}: {resp.status_code} {resp.text}")
            return None
    except requests.RequestException as e:
        print(f"[ERROR] Network error for {ip}: {e}")
        return None


def write_results_to_csv(results, filename=OUTPUT_CSV):
    """
    Writes analysis results to a CSV file with columns: ip, malicious.
    'results' should be an iterable of dicts like: {'ip': '1.2.3.4', 'malicious': 0}
    """
    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["ip", "malicious"])
            writer.writeheader()
            for row in results:
                # Ensure keys exist and coerce None malicious to empty or 0 as desired
                writer.writerow({
                    "ip": row.get("ip", ""),
                    "malicious": "" if row.get("malicious") is None else row.get("malicious")
                })
        print(f"\n[SAVED] Results written to: {filename}")
    except (OSError, IOError) as e:
        print(f"[ERROR] Failed to write CSV '{filename}': {e}")


def main():
    print("=== VirusTotal Bulk IP Re-Analysis ===")
    results = []  # Collect results to write to CSV at the end

    for ip in IP_LIST:
        print(f"\n[INFO] Reanalyzing IP: {ip}")
        analysis_id = reanalyze_ip(ip)
        if not analysis_id:
            # Record as unknown if reanalysis failed
            results.append({"ip": ip, "malicious": None})
            continue

        print(f"[INFO] Waiting {RATE_LIMIT_DELAY}s for analysis to complete...")
        time.sleep(RATE_LIMIT_DELAY)  # Wait before fetching results

        flagged_count = get_analysis_results(ip)
        if flagged_count is not None:
            print(f"[RESULT] {ip} flagged by {flagged_count} security vendors.")
        else:
            print(f"[WARN] Could not retrieve results for {ip}.")

        # Store result (None if unavailable)
        results.append({"ip": ip, "malicious": flagged_count})

        time.sleep(1)  # Small delay to avoid hitting rate limits

    # Write out CSV at the end
    write_results_to_csv(results, OUTPUT_CSV)

if __name__ == "__main__":
    if API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        print("[ERROR] Please set your VirusTotal API key in the script.")
        sys.exit(1)
    main()