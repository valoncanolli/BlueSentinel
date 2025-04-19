import requests
import json
import os
import time
import sys
from datetime import datetime, timedelta
from colorama import init, Fore, Style

init(autoreset=True)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
CACHE_DIR = os.path.join(BASE_DIR, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

CACHE_FILE = os.path.join(CACHE_DIR, "virustotal_hash_cache.json")

# Ngarko API keys
def load_api_keys():
    with open(os.path.join(CONFIG_DIR, "api_keys.json"), "r") as f:
        keys = json.load(f)
    return keys["virustotal"]["api_keys"]

# Ngarko hash-et nga file raporti
def load_hashes(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# Ngarko ose inicializo cache
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

# Lookup në VirusTotal
def lookup_hash(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.status_code}
    except Exception as e:
        return {"error": str(e)}

# Printimi i bannerit fillestar
def print_banner(api_count):
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.BLUE + "🔵 BlueSentinel – VirusTotal Hash Lookup")
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.YELLOW + f"🧠 [INFO] Using {api_count} VirusTotal API keys\n")

# Progress bar custom
def update_progress(current, total, start_time):
    percent = int((current / total) * 100)
    elapsed = int(time.time() - start_time)
    bar = f"{Fore.BLUE}{'█' * (percent // 4)}{Style.RESET_ALL}{'.' * (25 - percent // 4)}"
    sys.stdout.write(
        f"\r🔄 Progress: |{bar}| {percent}% ({current}/{total}) ⏱️ {time.strftime('%H:%M:%S', time.gmtime(elapsed))}"
    )
    sys.stdout.flush()

# Ruaj rezultatet
def save_results(vt_results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_path = os.path.join(REPORTS_DIR, f"virustotal_results_{timestamp}.json")
    summary_path = os.path.join(REPORTS_DIR, f"virustotal_summary_{timestamp}.txt")

    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(vt_results, f, indent=4)

    with open(summary_path, "w", encoding="utf-8") as f:
        for item in vt_results:
            file = item['file']
            h = item['hash']
            result = item['result']
            if "data" in result:
                stats = result['data']['attributes']['last_analysis_stats']
                f.write(f"File: {file}\nHash: {h}\n")
                f.write(f"Malicious: {stats.get('malicious')}, Suspicious: {stats.get('suspicious')}, Harmless: {stats.get('harmless')}\n")
                f.write(f"Link: https://www.virustotal.com/gui/file/{h}\n\n")
            else:
                f.write(f"[!] Error for hash: {h} | Code: {result.get('error')}\n\n")

    print(f"\n\n[✓] JSON saved: {result_path}")
    print(f"[✓] TXT summary saved: {summary_path}")
    return result_path

# =====================
# MAIN FUNCTION
# =====================
def main():
    api_keys = load_api_keys()
    print_banner(len(api_keys))

    print("📂 Available hash reports in 'reports/' folder:\n")
    hash_files = [f for f in os.listdir(REPORTS_DIR) if f.startswith("advanced_hash_scan") and f.endswith(".json")]
    for i, file in enumerate(hash_files):
        print(f"[{i+1}] {file}")

    if not hash_files:
        print("[-] No hash report files found.")
        return

    choice = int(input("\nSelect file to analyze (number): ")) - 1
    selected = os.path.join(REPORTS_DIR, hash_files[choice])
    hashes = load_hashes(selected)
    cache = load_cache()
    now = datetime.now()

    print(f"\n🔍 Starting lookup for {len(hashes)} hashes...\n")
    start_time = time.time()

    vt_results = []
    total = len(hashes)
    scanned = 0
    skipped = 0
    api_index = 0

    for i, entry in enumerate(hashes, start=1):
        file_hash = entry["hash"]
        file_path = entry["file"]

        # Kontrollo në cache
        if file_hash in cache:
            try:
                last_checked = datetime.strptime(cache[file_hash]["last_checked"], "%Y-%m-%d %H:%M:%S")
                if now - last_checked < timedelta(days=7):
                    skipped += 1
                    vt_results.append({
                        "file": file_path,
                        "hash": file_hash,
                        "result": cache[file_hash]["result"]
                    })
                    update_progress(i, total, start_time)
                    continue
            except:
                pass

        # Ekzekuto lookup me rotacion të key-ve
        for _ in range(len(api_keys)):
            result = lookup_hash(file_hash, api_keys[api_index % len(api_keys)])
            if "data" in result or "error" not in result or result.get("error") != 429:
                break
            else:
                print(Fore.YELLOW + "⚠️  Rate limit – switching key...")
                api_index += 1
                time.sleep(1)

        # Ruaje në listë
        vt_results.append({
            "file": file_path,
            "hash": file_hash,
            "result": result
        })

        # Përditëso cache
        cache[file_hash] = {
            "last_checked": now.strftime("%Y-%m-%d %H:%M:%S"),
            "result": result
        }

        scanned += 1
        update_progress(i, total, start_time)
        time.sleep(0.4)

    end = time.time()
    elapsed = time.strftime("%H:%M:%S", time.gmtime(end - start_time))

    save_cache(cache)
    saved_path = save_results(vt_results)

    # Stats
    malicious = sum(1 for r in vt_results if "data" in r["result"] and r["result"]["data"]["attributes"]["last_analysis_stats"].get("malicious", 0) > 0)
    suspicious = sum(1 for r in vt_results if "data" in r["result"] and r["result"]["data"]["attributes"]["last_analysis_stats"].get("suspicious", 0) > 0)

    print(Fore.CYAN + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"🧾 {Style.BRIGHT}Scan Summary:")
    print(f"• Total Files       : {total}")
    print(f"• Skipped (cache)   : {skipped}")
    print(f"• Newly Scanned     : {scanned}")
    print(f"• Malicious Files   : {malicious}")
    print(f"• Suspicious Files  : {suspicious}")
    print(f"• Time Elapsed      : {elapsed}")
    print(f"• Report saved to   : {saved_path}")
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
