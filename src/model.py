    #Train the Model
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from safe_pickle import safe_load, safe_dump

FEATURES_PATH = "data/processed/features.pkl"
MODEL_PATH = "data/processed/model.pkl"

def train_model():
    print(" Training...")

    # load Binary data (integrity-checked)
    X, y = safe_load(FEATURES_PATH)


    # Split data: Test + Training 
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Train model
    clf = LogisticRegression(max_iter=10000, random_state=0)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f" Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))
    

    # Save model
    safe_dump(clf, MODEL_PATH)

    print("✅ Classifier is Successfully trained and saved")

if __name__ == "__main__":
    train_model()