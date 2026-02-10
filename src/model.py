import pickle
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report

FEATURES_PATH = "data/processed/features.pkl"
MODEL_PATH = "data/processed/model.pkl"


def train_model():
    print("Training...\n")

    # Load features
    with open(FEATURES_PATH, "rb") as f:
        X, y = pickle.load(f)

    # Split data with stratification to maintain class balance
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Try multiple models
    models = {
        "LogisticRegression": LogisticRegression(
            max_iter=10000, class_weight="balanced", random_state=42
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=42
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=100, random_state=42
        ),
    }

    best_model = None
    best_acc = 0
    best_name = ""

    print("--- Model Comparison (5-fold CV) ---\n")

    for name, model in models.items():
        # Cross-validation on training data
        cv_scores = cross_val_score(model, X_train, y_train, cv=5)
        print(f"{name}:")
        print(f"  CV accuracy: {cv_scores.mean():.2%} (+/- {cv_scores.std():.2%})")

        # Train and evaluate on test set
        model.fit(X_train, y_train)
        acc = accuracy_score(y_test, model.predict(X_test))
        print(f"  Test accuracy: {acc:.2%}\n")

        if acc > best_acc:
            best_acc = acc
            best_model = model
            best_name = name

    # Final evaluation of best model
    print(f"--- Best Model: {best_name} ({best_acc:.2%}) ---\n")
    y_pred = best_model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))

    # Save best model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(best_model, f)

    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    train_model()
