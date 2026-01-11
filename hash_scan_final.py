import requests
import time
import csv
import sys
import os

# ==============================
# CONFIGURATION
# ==============================
API_KEY = "API_KEY"  # Replace with your VirusTotal API key
INPUT_FILE = "hashes.txt"    # Text file with one hash per line
OUTPUT_FILE = "vt_results.csv"
RATE_LIMIT_SECONDS = 16      # Public API: 4 requests/minute => 15 sec gap

# ==============================
# FUNCTIONS
# ==============================

def reanalyze_hash(file_hash):
    """Trigger a re-analysis for the given hash."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/analyse"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.post(url, headers=headers)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            print(f"[!] Hash not found in VT: {file_hash}")
        else:
            print(f"[!] Re-analyze failed for {file_hash}: {response.status_code} {response.text}")
    except requests.RequestException as e:
        print(f"[!] Network error during re-analyze for {file_hash}: {e}")
    return False


def get_hash_reputation(file_hash):
    """Get the number of vendors flagging the hash as malicious."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            return malicious_count
        elif response.status_code == 404:
            print(f"[!] Hash not found in VT: {file_hash}")
        else:
            print(f"[!] Failed to get reputation for {file_hash}: {response.status_code} {response.text}")
    except requests.RequestException as e:
        print(f"[!] Network error during reputation fetch for {file_hash}: {e}")
    return None


def process_hashes():
    """Main processing function."""
    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] Input file '{INPUT_FILE}' not found.")
        sys.exit(1)

    with open(INPUT_FILE, "r") as f:
        hashes = [line.strip() for line in f if line.strip()]

    if not hashes:
        print("[ERROR] No hashes found in input file.")
        sys.exit(1)

    results = []

    for idx, file_hash in enumerate(hashes, start=1):
        print(f"\n[{idx}/{len(hashes)}] Processing hash: {file_hash}")

        # Step 1: Re-analyze
        if reanalyze_hash(file_hash):
            print("    Re-analysis triggered successfully.")
        else:
            print("    Skipping reputation fetch due to re-analysis failure.")
            # Append with Result = "Unknown"
            results.append((file_hash, None, "Unknown"))
            time.sleep(RATE_LIMIT_SECONDS)
            continue

        # Step 2: Wait before fetching results (VT needs time to update)
        print("    Waiting 20 seconds for VT to update results...")
        time.sleep(20)

        # Step 3: Get reputation
        malicious_count = get_hash_reputation(file_hash)
        if malicious_count is not None:
            print(f"    Malicious detections: {malicious_count}")
        else:
            print("    Failed to retrieve malicious count.")

        # Determine Result column
        if malicious_count is None:
            result_label = "Unknown"
        elif malicious_count == 0:
            result_label = "Clean"
        else:
            result_label = "Malicious"

        results.append((file_hash, malicious_count, result_label))

        # Step 4: Respect API rate limit
        time.sleep(RATE_LIMIT_SECONDS)

    # Step 5: Save results to CSV
    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Hash", "Malicious_Vendors", "Result"])
        writer.writerows(results)

    print(f"\n[+] Results saved to '{OUTPUT_FILE}'")


# ==============================
# MAIN EXECUTION
# ==============================
if __name__ == "__main__":
    process_hashes()