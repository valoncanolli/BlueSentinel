import os
import json
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

def read_txt_section(filename, html_id, title):
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        return f"<p><em>{title} report not found.</em></p>"
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return f"<div class='toggle-section' id='{html_id}'><h3>{title}</h3><pre>{content}</pre></div>"

def generate_html_report():
    vt_files = sorted([f for f in os.listdir(REPORTS_DIR) if f.startswith("virustotal_results") and f.endswith(".json")])
    latest_vt = vt_files[-1] if vt_files else None
    vt_data = []
    if latest_vt:
        with open(os.path.join(REPORTS_DIR, latest_vt), "r", encoding="utf-8") as f:
            vt_data = json.load(f)

    malicious = sum(1 for d in vt_data if d["result"].get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0)
    suspicious = sum(1 for d in vt_data if d["result"].get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0) > 0)
    skipped = sum(1 for d in vt_data if d["result"].get("from_cache"))
    total = len(vt_data)
    scanned = total - skipped

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(REPORTS_DIR, f"BlueSentinel_Report_{timestamp}.html")

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>BlueSentinel Threat Report</title>
<style>
body {{
    font-family: Consolas, monospace;
    background: #1e1e1e;
    color: #f0f0f0;
    padding: 20px;
}}
h1, h2 {{
    color: #44aaff;
    border-bottom: 1px solid #555;
}}
.summary {{
    background: #2e2e2e;
    padding: 10px 15px;
    border-left: 4px solid #44aaff;
    margin-bottom: 20px;
}}
.malicious {{ color: #ff4c4c; }}
.suspicious {{ color: #ffaa00; }}
.clean {{ color: #8fc866; }}
.toggle-btn {{
    background: #007acc;
    color: white;
    border: none;
    padding: 8px 12px;
    margin-top: 10px;
    cursor: pointer;
}}
.toggle-section {{
    display: none;
    margin-top: 10px;
}}
pre {{ white-space: pre-wrap; word-wrap: break-word; }}
</style>
</head>
<body>
<h1>🛡️ BlueSentinel – Final Threat Report</h1>

<div class='summary'>
<h2>📊 Scan Summary</h2>
<ul>
<li><strong>Total Files Scanned:</strong> {total}</li>
<li><strong>New Scanned:</strong> {scanned}</li>
<li><strong>Skipped (cache):</strong> {skipped}</li>
<li><strong class='malicious'>Malicious:</strong> {malicious}</li>
<li><strong class='suspicious'>Suspicious:</strong> {suspicious}</li>
</ul>
</div>

<button class='toggle-btn' onclick="toggle('vt')">🔽 VirusTotal Details</button>
<div id='vt' class='toggle-section'>
"""

    for item in vt_data:
        file = item["file"]
        hash_val = item["hash"]
        result = item["result"]
        if "data" in result:
            stats = result["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            harm = stats.get("harmless", 0)
            und = stats.get("undetected", 0)
            status = "🛑 MALICIOUS" if mal > 0 else "⚠️ SUSPICIOUS" if susp > 0 else "✅ CLEAN"
            color_class = "malicious" if mal > 0 else "suspicious" if susp > 0 else "clean"
            html += f"""<pre class='{color_class}'>
File: {file}
Hash: {hash_val}
Status: {status}
Stats:
 - Malicious: {mal}
 - Suspicious: {susp}
 - Harmless: {harm}
 - Undetected: {und}
Link: https://www.virustotal.com/gui/file/{hash_val}
</pre><hr>"""
        else:
            html += f"""<pre class='suspicious'>File: {file}
Hash: {hash_val}
⚠️ Error retrieving data from VirusTotal.</pre><hr>"""

    html += "</div>"

    # Toggle sections for each report part
    html += "<button class='toggle-btn' onclick=\"toggle('sysinfo')\">🖥️ System Info</button>"
    html += read_txt_section("sysinfo_report.txt", "sysinfo", "System Information")

    html += "<button class='toggle-btn' onclick=\"toggle('network')\">🌐 Network Analysis</button>"
    html += read_txt_section("network_report.txt", "network", "Network Analysis")

    html += "<button class='toggle-btn' onclick=\"toggle('autorun')\">⚙️ Autorun & Persistence</button>"
    html += read_txt_section("autorun_report.txt", "autorun", "Autorun & Persistence")

    html += "<button class='toggle-btn' onclick=\"toggle('tshark')\">📡 TShark Traffic Analysis</button>"
    html += read_txt_section("network_report.txt", "tshark", "TShark Traffic Analysis")

    html += """
<script>
function toggle(id) {
  const section = document.getElementById(id);
  if (section) {
    section.style.display = section.style.display === "none" ? "block" : "none";
  }
}
window.onload = function() {
  const els = document.getElementsByClassName('toggle-section');
  for (let el of els) el.style.display = 'none';
}
</script>
</body></html>"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[✓] HTML report generated: {out_file}")

if __name__ == "__main__":
    generate_html_report()
