import pandas as pd
import os


JAILBREAK_PATH = "data/raw/jailbreaks.csv"
SAFE_PATH = "data/raw/safe_prompts.csv"
HF_SAFE_PATH = "data/raw/hf_safe_prompts.csv"
OUTPUT_PATH = "data/processed/combined_data.csv"


def merge_datasets():
    try:
        # Load Jailbreak data
        jailbreak_df = pd.read_csv(JAILBREAK_PATH)
        jailbreak_df['label'] = 1  # Malicious
        jailbreak_df = jailbreak_df.rename(columns={'prompt': 'text'})
        jailbreak_df = jailbreak_df[['text', 'label']]

        # Load Safe data (GitHub)
        df_good = pd.read_csv(SAFE_PATH)
        df_good['label'] = 0  # Safe
        df_good = df_good.rename(columns={'prompt': 'text'})
        df_good = df_good[['text', 'label']]

        # Load Safe data (Hugging Face)
        hf_safe_count = 0
        if os.path.exists(HF_SAFE_PATH):
            df_hf = pd.read_csv(HF_SAFE_PATH)
            df_hf = df_hf.rename(columns={'prompt': 'text'})
            df_hf['label'] = 0
            df_hf = df_hf[['text', 'label']]
            hf_safe_count = len(df_hf)
            df_good = pd.concat([df_good, df_hf], axis=0)

        # Combine
        combined = pd.concat([jailbreak_df, df_good], axis=0).sample(frac=1, random_state=42)

        # Save
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        combined.to_csv(OUTPUT_PATH, index=False)

        print(f"Merged data saved to {OUTPUT_PATH}")
        print(f"Total: {len(combined)}")
        print(f"   - Malicious: {len(jailbreak_df)}")
        print(f"   - Safe: {len(df_good)} (GitHub: {len(df_good) - hf_safe_count}, HuggingFace: {hf_safe_count})")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    merge_datasets()