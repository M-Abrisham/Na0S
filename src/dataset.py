print(" RUNNING...")

import pandas as pd
import os

# JAILBREAK Data
JAILBREAK_URL = "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_12_25.csv"
JAILBREAK_PATH = "data/raw/jailbreaks.csv"

# Good Data (Awesome ChatGPT Prompts dataset)
SAFE_URL = "https://raw.githubusercontent.com/f/awesome-chatgpt-prompts/main/prompts.csv"
SAFE_PATH = "data/raw/safe_prompts.csv"

def download_data(url, path):

    try:
        df = pd.read_csv(url)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        df.to_csv(path, index=False)
        return len(df)
    except (OSError, ValueError) as e:
        print(f"❌ Error: {e}")
        return 0


if __name__ == "__main__":
    bad_urls = download_data(JAILBREAK_URL, JAILBREAK_PATH)
    good_urls = download_data(SAFE_URL, SAFE_PATH)
    print("\n✅ Success! Saved")
    print(f"JAILBREAK_URL: {bad_urls}")
    print(f"SAFE-URLs: {good_urls}")