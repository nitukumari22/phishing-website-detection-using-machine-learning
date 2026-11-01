import os
import sys
import shutil
import json
import urllib.parse
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import joblib

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from extractors import get_features, get_feature_names
from train import train_model

app = FastAPI(title="Phishing Website Detection API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "base_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "model_metrics.json")

# Load model globally on startup (or train if not exists)
model = None
metrics = {}

def load_or_train_model():
    global model, metrics
    try:
        if not os.path.exists(MODEL_PATH):
            print("Model not found. Running training script...")
            metrics = train_model(DATASET_PATH, MODEL_PATH)
        else:
            print("Loading pre-trained model...")
            with open(METRICS_PATH, 'r') as f:
                metrics = json.load(f)
        model = joblib.load(MODEL_PATH)
        print("Model loaded successfully.")
    except Exception as e:
        print(f"Error loading/training model: {e}")
        model = None
        metrics = {}

@app.on_event("startup")
def startup_event():
    load_or_train_model()

WHITELISTED_DOMAINS = {
    'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.de', 'google.fr', 
    'youtube.com', 'gmail.com', 'blogger.com',
    'facebook.com', 'fb.com', 'messenger.com',
    'instagram.com',
    'paypal.com', 'paypal.me',
    'apple.com', 'icloud.com',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'windows.net',
    'amazon.com', 'amazon.in', 'amazon.co.uk',
    'netflix.com',
    'chase.com',
    'bankofamerica.com',
    'yahoo.com',
    'github.com',
    'stackoverflow.com'
}

def is_whitelisted(domain):
    domain = domain.lower()
    for white_dom in WHITELISTED_DOMAINS:
        if domain == white_dom or domain.endswith('.' + white_dom):
            return True
    return False

class URLRequest(BaseModel):
    url: str

@app.post("/predict")
def predict_url(payload: URLRequest):
    global model
    if model is None:
        # Try to train on-the-fly
        load_or_train_model()
        if model is None:
            raise HTTPException(status_code=503, detail="Machine Learning model is not available. Please retrain.")

    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    try:
        # Extract features
        features_dict = get_features(url)
        feature_names = get_feature_names()
        
        # Parse domain to check whitelist
        url_to_parse = url if url.startswith(('http://', 'https://')) else 'http://' + url
        try:
            parsed_url = urllib.parse.urlparse(url_to_parse)
            domain = parsed_url.netloc
        except Exception:
            domain = ""
            
        is_url_https = url.startswith('https://')
        
        # Override prediction for secure whitelisted official domains
        if is_url_https and is_whitelisted(domain):
            return {
                "url": url,
                "prediction": 0,
                "risk_score": 0.0,
                "features": features_dict,
                "explanations": [{
                    "feature": "Verified Official Domain",
                    "value": "Whitelisted",
                    "status": "safe",
                    "desc": f"This URL belongs to the verified official domain ({domain}) and uses secure SSL encryption."
                }],
                "resolved_ip": features_dict['resolved_ip']
            }
            
        # Prepare vector for model
        feature_vector = [features_dict[name] for name in feature_names]
        X = np.array([feature_vector])
        
        # Make predictions
        prediction = int(model.predict(X)[0])
        probabilities = model.predict_proba(X)[0]
        
        # Probability of phishing (label = 1)
        phishing_probability = float(probabilities[1])
        
        # Generate visual explanation details for the frontend
        explanations = []
        
        if features_dict['url_length'] > 75:
            explanations.append({
                "feature": "URL Length",
                "value": f"{features_dict['url_length']} chars",
                "status": "warning",
                "desc": "URL is very long, which is a common trick to hide actual domain."
            })
        else:
            explanations.append({
                "feature": "URL Length",
                "value": f"{features_dict['url_length']} chars",
                "status": "safe",
                "desc": "URL length is within standard limits."
            })

        if features_dict['is_https'] == 0:
            explanations.append({
                "feature": "SSL Security",
                "value": "HTTP (Unencrypted)",
                "status": "danger",
                "desc": "Website does not use HTTPS. Connection is insecure and susceptible to interception."
            })
        else:
            explanations.append({
                "feature": "SSL Security",
                "value": "HTTPS (Secured)",
                "status": "safe",
                "desc": "Website uses SSL encryption."
            })

        if features_dict['has_ip'] == 1:
            explanations.append({
                "feature": "IP Address in Domain",
                "value": "Detected",
                "status": "danger",
                "desc": "Using an IP address instead of a domain name is a strong indicator of phishing."
            })

        if features_dict['is_shortened'] == 1:
            explanations.append({
                "feature": "URL Shortener",
                "value": "Detected",
                "status": "warning",
                "desc": "Uses a URL shortener service, which can hide the real destination domain."
            })

        if features_dict['domain_hyphens'] > 1:
            explanations.append({
                "feature": "Hyphens in Domain",
                "value": f"{features_dict['domain_hyphens']} hyphens",
                "status": "warning",
                "desc": "Phishing sites often mimic brands by using hyphens (e.g., brand-support.com)."
            })

        if features_dict['suspicious_keyword_count'] > 0:
            explanations.append({
                "feature": "Suspicious Keywords",
                "value": f"{features_dict['suspicious_keyword_count']} keywords",
                "status": "danger",
                "desc": "URL contains sensitive security keywords like login, verify, secure, account."
            })

        if features_dict['domain_in_path'] == 1:
            explanations.append({
                "feature": "Nested Domain in Path",
                "value": "Detected",
                "status": "danger",
                "desc": "Legitimate TLD (.com/.org) found in URL path. Used to trick users into seeing a brand domain."
            })

        if features_dict['subdomain_count'] > 2:
            explanations.append({
                "feature": "Subdomain Count",
                "value": f"{features_dict['subdomain_count']} subdomains",
                "status": "warning",
                "desc": "Large number of subdomains is frequently used to obfuscate the root domain."
            })

        if features_dict['brand_impersonation'] == 1:
            explanations.append({
                "feature": "Brand Impersonation",
                "value": "Spoofing Detected",
                "status": "danger",
                "desc": "URL domain contains a major brand name (like Facebook/Google) but is hosted on an unofficial domain."
            })

        if features_dict['dns_resolved'] == 0:
            explanations.append({
                "feature": "DNS Active Scan",
                "value": "Offline / Unregistered",
                "status": "danger",
                "desc": "The domain failed DNS resolution. It is either offline, inactive, or was recently registered and has not propagated."
            })
        else:
            explanations.append({
                "feature": "DNS Active Scan",
                "value": "Online",
                "status": "safe",
                "desc": f"Domain resolved successfully. Server IP Address: {features_dict['resolved_ip']}"
            })

        return {
            "url": url,
            "prediction": prediction, # 1 for phishing, 0 for legitimate
            "risk_score": round(phishing_probability * 100, 2),
            "features": features_dict,
            "explanations": explanations,
            "resolved_ip": features_dict['resolved_ip']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.get("/metrics")
def get_model_metrics():
    global metrics
    if not metrics:
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH, 'r') as f:
                metrics = json.load(f)
        else:
            return {"status": "untrained", "message": "Model is not trained yet."}
    return metrics

@app.post("/retrain")
async def retrain_model_endpoint(
    file: UploadFile = File(...),
    n_estimators: int = 100,
    max_depth: int = 15
):
    global model, metrics
    
    # Validate file type
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV datasets are supported.")
        
    try:
        # Save uploaded file
        os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
        with open(DATASET_PATH, 'wb') as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        print(f"CSV saved. Re-training model with n_estimators={n_estimators}, max_depth={max_depth}...")
        # Train model
        metrics = train_model(DATASET_PATH, MODEL_PATH, n_estimators=n_estimators, max_depth=max_depth)
        # Reload model
        model = joblib.load(MODEL_PATH)
        
        return {
            "status": "success",
            "message": "Model successfully retrained with the new dataset.",
            "metrics": metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(e)}")
