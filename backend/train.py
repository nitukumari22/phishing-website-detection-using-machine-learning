import os
import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report
import joblib

# Add current directory to path so we can import extractors
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from extractors import get_features, get_feature_names

# Sample legitimate and phishing domains/URLs to generate a starting dataset if none is present
LEGITIMATE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com", "amazon.com",
    "twitter.com", "live.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "office.com", "microsoft.com", "tumblr.com", "pinterest.com", "apple.com", "github.com",
    "stackoverflow.com", "quora.com", "medium.com", "adobe.com", "dropbox.com", "slack.com",
    "zoom.us", "spotify.com", "imdb.com", "cnn.com", "nytimes.com", "bbc.com", "theguardian.com",
    "forbes.com", "bloomberg.com", "reuters.com", "huffpost.com", "washingtonpost.com",
    "wsj.com", "nationalgeographic.com", "nature.com", "nasa.gov", "nih.gov", "who.int",
    "un.org", "harvard.edu", "stanford.edu", "mit.edu", "berkeley.edu", "yale.edu",
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "usbank.com"
]

PHISHING_PATTERNS = [
    "login-facebook-verify.com", "secure-paypal-login.net", "chase-bank-verify-account.org",
    "apple-id-recovery-support.com", "netflix-billing-update.info", "microsoft-office365-login.xyz",
    "google-account-security-alert.security", "yahoo-mail-login-verification.co",
    "instagram-followers-free.xyz", "linkedin-verify-profile.net", "amazon-giftcard-winner.xyz",
    "dropbox-shared-file-download.com", "update-bankofamerica.org", "wellsfargo-client-signin.com",
    "citibank-identity-verification.net", "steam-community-trade-offers.ru", "blockchain-wallet-login.io",
    "coinbase-auth-verify.com", "binance-security-check.cc", "metamask-wallet-restore.io"
]

def generate_base_dataset(output_path):
    """
    Generates a realistic baseline dataset of URLs and labels (0 = Legitimate, 1 = Phishing),
    extracts their features, and writes them to a CSV file.
    """
    print("Generating baseline URL dataset...")
    data = []
    
    # 1. Generate Legitimate URLs (Label = 0)
    for domain in LEGITIMATE_DOMAINS:
        # standard domain
        data.append((f"https://{domain}", 0))
        data.append((f"https://www.{domain}", 0))
        # with common paths
        data.append((f"https://{domain}/search?q=query", 0))
        data.append((f"https://{domain}/about", 0))
        data.append((f"https://{domain}/contact-us", 0))
        data.append((f"https://{domain}/index.html", 0))
        data.append((f"https://{domain}/news/today", 0))
        data.append((f"https://{domain}/help/center", 0))
        
    # 2. Generate Phishing URLs (Label = 1)
    for domain in PHISHING_PATTERNS:
        # simple phishing domain
        data.append((f"http://{domain}", 1))
        data.append((f"http://www.{domain}", 1))
        # subdomains/paths pretending to be secure
        data.append((f"http://{domain}/login", 1))
        data.append((f"http://{domain}/signin/index.php", 1))
        data.append((f"http://{domain}/secure/account/update.html", 1))
        data.append((f"http://{domain}/verification.php?id=12938", 1))
        data.append((f"http://{domain}/banking/online/login.html", 1))
        data.append((f"http://{domain}/webscr?cmd=_login-run", 1))
        
    # 3. Add more synthetic variants to ensure a solid balanced dataset (~1000 items)
    # Legitimate variations
    for i in range(150):
        dom = LEGITIMATE_DOMAINS[i % len(LEGITIMATE_DOMAINS)]
        data.append((f"https://{dom}/user/profile/{i}", 0))
        data.append((f"https://{dom}/assets/images/logo.png?v={i}", 0))
        data.append((f"https://{dom}/blog/post-{i}-details", 0))
        
        # Add legitimate OAuth / Authorize links
        if dom == "google.com":
            data.append((f"https://accounts.google.com/o/oauth2/v2/auth?client_id=client_{i}&response_type=code&scope=email", 0))
        elif dom == "facebook.com":
            data.append((f"https://www.facebook.com/v12.0/dialog/oauth?client_id=app_{i}&redirect_uri=https://safeapp.com", 0))
        
    # Phishing variations
    for i in range(150):
        # random-looking numeric phishing
        data.append((f"http://91.243.51.{i}/secure/login", 1))
        # shorteners and masked domains
        data.append((f"http://bit.ly/secure-login-update-{i}", 1))
        # domain-in-path trick
        dom = LEGITIMATE_DOMAINS[i % len(LEGITIMATE_DOMAINS)]
        bad_dom = PHISHING_PATTERNS[i % len(PHISHING_PATTERNS)]
        data.append((f"http://{bad_dom}/{dom}/login.html", 1))
        data.append((f"http://{bad_dom}/signin?service={dom}", 1))
        data.append((f"http://{dom}-security-alert-update-{i}.net/login", 1))

        # Add phishing brand impersonation / authorize links
        if i % 2 == 0:
            data.append((f"https://accounts-google-oauth.net/o/oauth2/v2/auth?client_id=client_{i}", 1))
        else:
            data.append((f"http://facebook-authorize-app.com/v12.0/dialog/oauth?client_id=app_{i}", 1))

    # Convert to DataFrame
    df_urls = pd.DataFrame(data, columns=['url', 'label'])
    
    # Extract features for all generated URLs
    print("Extracting features from generated URLs...")
    feature_list = []
    for idx, row in df_urls.iterrows():
        feats = get_features(row['url'])
        feats['url'] = row['url']
        feats['label'] = row['label']
        feature_list.append(feats)
        
    df_dataset = pd.DataFrame(feature_list)
    
    # Save CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df_dataset.to_csv(output_path, index=False)
    print(f"Baseline dataset saved to {output_path} with {len(df_dataset)} samples.")
    return df_dataset

def train_model(dataset_path, model_output_path, n_estimators=100, max_depth=15):
    """
    Trains a Random Forest classifier on the dataset at dataset_path.
    Saves the trained model to model_output_path.
    Returns a dictionary of metrics.
    """
    print(f"Loading dataset from {dataset_path}...")
    
    # Generate dataset if it does not exist
    if not os.path.exists(dataset_path):
        df = generate_base_dataset(dataset_path)
    else:
        df = pd.read_csv(dataset_path)
        
    # If the user uploaded a raw CSV containing only 'url' and 'label' columns,
    # we need to extract the features dynamically.
    if 'url' in df.columns and 'label' in df.columns and len(df.columns) <= 3:
        print("Raw URL dataset detected. Extracting features...")
        feature_list = []
        for idx, row in df.iterrows():
            feats = get_features(row['url'])
            feats['url'] = row['url']
            feats['label'] = row['label']
            feature_list.append(feats)
        df = pd.DataFrame(feature_list)
        # Save back the feature-rich CSV
        df.to_csv(dataset_path, index=False)
        print("Features extracted and saved.")

    feature_names = get_feature_names()
    
    # Ensure all required features are present in the dataset
    missing_features = [f for f in feature_names if f not in df.columns]
    if missing_features:
        raise ValueError(f"Dataset is missing required feature columns: {missing_features}")
        
    X = df[feature_names]
    y = df['label']
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"Training Random Forest Classifier (Train size: {len(X_train)}, Test size: {len(X_test)}, n_estimators={n_estimators}, max_depth={max_depth})...")
    clf = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth, random_state=42)
    clf.fit(X_train, y_train)
    
    # Predict and evaluate
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    
    print("Evaluation Results:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save the model
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    joblib.dump(clf, model_output_path)
    print(f"Model saved to {model_output_path}")
    
    # Save feature importances to print or display on UI
    importances = clf.feature_importances_
    feature_importance_dict = dict(zip(feature_names, [float(x) for x in importances]))
    
    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "n_estimators": int(n_estimators),
        "max_depth": int(max_depth),
        "feature_importances": feature_importance_dict
    }
    
    # Save metrics metadata as JSON next to the model
    metrics_path = model_output_path.replace(".joblib", "_metrics.json")
    import json
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=4)
        
    return metrics

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_file = os.path.join(base_dir, "dataset", "base_dataset.csv")
    model_file = os.path.join(base_dir, "model.joblib")
    
    train_model(dataset_file, model_file)
