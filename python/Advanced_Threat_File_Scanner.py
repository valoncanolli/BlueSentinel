import os
import hashlib
import json
from datetime import datetime, timedelta
from tqdm import tqdm
from colorama import init, Fore, Style

init(autoreset=True)

# Lista e path-eve kritike për skanim
critical_paths = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\Temp",
    r"C:\Users\%USERNAME%\AppData\Local\Temp",
    r"C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\Users\%USERNAME%\AppData\Roaming",
    r"C:\Users\%USERNAME%\AppData\Local",
    r"C:\Users\%USERNAME%\Downloads",
    r"C:\Users\%USERNAME%\Desktop",
    r"C:\ProgramData",
    r"C:\Program Files",
    r"C:\Program Files (x86)"
]

# Zëvendëso %USERNAME% me user aktual
critical_paths = [os.path.expandvars(p) for p in critical_paths]

# Vendosim rrugët për raportim dhe cache
base_dir = os.path.dirname(__file__)
report_folder = os.path.join(base_dir, "../reports")
cache_folder = os.path.join(base_dir, "../cache")
os.makedirs(report_folder, exist_ok=True)
os.makedirs(cache_folder, exist_ok=True)

# Emërtimi i raporteve
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
txt_output_file = os.path.join(report_folder, f"hash_scan_report_{timestamp}.txt")
json_output_file = os.path.join(report_folder, f"advanced_hash_scan_{timestamp}.json")
cache_file = os.path.join(cache_folder, "virustotal_hash_cache.json")

# Ngarkimi i cache ekzistues
if os.path.exists(cache_file):
    with open(cache_file, "r", encoding="utf-8") as f:
        cache = json.load(f)
else:
    cache = {}

# Fillimi i printimit
print(f"{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print(f"{Fore.CYAN}🔵 BlueSentinel – Advanced Threat Scanner")
print(f"{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
print(f"{Fore.MAGENTA}📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{Fore.LIGHTWHITE_EX}💬 [INFO] Initializing scan on system-critical locations...\n")

# Mbledhim të gjithë path-at për skanim
all_files = []
for path in critical_paths:
    if os.path.exists(path):
        for root, dirs, files in os.walk(path):
            for file in files:
                all_files.append(os.path.join(root, file))

# Inicimi i skanimit
json_results = []
now = datetime.now()
skipped_cached = 0
scanned_now = 0
errors = 0

start_time = datetime.now()

print(f"{Fore.LIGHTWHITE_EX}🔧 Skanimi në progres...", end=" ")

with open(txt_output_file, "w", encoding="utf-8") as report:
    for file_path in tqdm(all_files, desc="Scanning files", unit="file", colour="blue"):
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()

            # Kontrollo në cache nëse është skanuar brenda 7 ditëve
            if file_hash in cache:
                last_scanned = datetime.strptime(cache[file_hash]["timestamp"], "%Y-%m-%d %H:%M:%S")
                if now - last_scanned < timedelta(days=7):
                    skipped_cached += 1
                    continue

            report.write(f"{file_path} | {file_hash}\n")
            json_results.append({"file": file_path, "hash": file_hash})
            scanned_now += 1

            cache[file_hash] = {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "path": file_path
            }

            with open(cache_file, "w", encoding="utf-8") as cf:
                json.dump(cache, cf, indent=2)

        except Exception:
            errors += 1
            continue

with open(json_output_file, "w", encoding="utf-8") as jf:
    json.dump(json_results, jf, indent=2)

end_time = datetime.now()
elapsed = str(end_time - start_time).split(".")[0]

# Raporti Final
print(f"\n{Fore.CYAN}📋 Scan Summary:")
print(f"{Fore.LIGHTCYAN_EX}  • Total files found     : {len(all_files)}")
print(f"  • Skipped (cached)      : {skipped_cached}")
print(f"  • Newly scanned         : {scanned_now}")
print(f"  • Could not read        : {errors}")
print(f"  • Time elapsed          : {elapsed}")
print(f"{Fore.YELLOW}  • Report saved to       : {json_output_file}\n")
print(f"{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
