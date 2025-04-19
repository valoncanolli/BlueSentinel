import os
import json
from openai import OpenAI
from datetime import datetime

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
CONFIG_DIR = os.path.join(BASE_DIR, "config")

# Load API keys
def load_api_keys():
    with open(os.path.join(CONFIG_DIR, "api_keys.json"), "r") as f:
        return json.load(f)

# Load selected report
def load_report(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

# Send to GPT using new OpenAI SDK
def analyze_with_gpt(report_data, api_key):
    client = OpenAI(api_key=api_key)

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst. Analyze this scan report for signs of compromise or malicious activity."},
                {"role": "user", "content": report_data}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error during GPT analysis: {str(e)}"

# Save the analysis
def save_analysis(output):
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(REPORTS_DIR, f"gpt_analysis_{timestamp}.txt")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(output)
    print(f"[+] GPT analysis saved to {file_path}")

# --- MAIN ---
if __name__ == "__main__":
    keys = load_api_keys()
    gpt_key = keys['openai']['api_key']

    print(f"Available reports in '{REPORTS_DIR}' directory:\n")
    files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".txt")]
    for i, file in enumerate(files):
        print(f"[{i+1}] {file}")

    choice = int(input("\nSelect report to analyze (number): ")) - 1
    selected_file = os.path.join(REPORTS_DIR, files[choice])
    report_content = load_report(selected_file)

    print("\n[*] Sending report to GPT for analysis...")
    result = analyze_with_gpt(report_content, gpt_key)

    print("\n--- GPT Analysis Result ---\n")
    print(result)
    save_analysis(result)
