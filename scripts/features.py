import re
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from na0s.safe_pickle import safe_dump

# Paths
INPUT_PATH = "data/processed/combined_data.csv"
VECTORIZER_PATH = "data/processed/tfidf_vectorizer.pkl"
FEATURES_PATH = "data/processed/features.pkl"

def load_training_data():
    print("Loading...")
    dataset = pd.read_csv(INPUT_PATH)  #import the dataset
    
    dataset['text'] = dataset['text'].fillna('').astype(str)

# Create Vectorizer with top 5K words 
    vec = TfidfVectorizer(
        lowercase=True,
        max_features=5000
        )
    
    X = vec.fit_transform(dataset['text'])
    y = dataset['label'] # 0 = Safe, 1 = Malicious

# Save VECTORIZER_Path data
    print(f"Saving vectorizer to {VECTORIZER_PATH}...")
    safe_dump(vec, VECTORIZER_PATH)

 # Save FEATURES_PATH data
    print(f"Saving features to {FEATURES_PATH}...")
    safe_dump((X, y), FEATURES_PATH)


    print(f"✅Successfully created! Shape: {X.shape}")

# Test 
if __name__ == "__main__":
    load_training_data()