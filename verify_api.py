import urllib.request
import json
import time

API_URL = "http://127.0.0.1:8000"

def test_api():
    print("Starting API verification...")
    time.sleep(2)  # Wait for server stability
    
    # 1. Test GET /metrics
    try:
        print("\n--- Testing GET /metrics ---")
        req = urllib.request.Request(f"{API_URL}/metrics", method="GET")
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode())
            print(f"Status: SUCCESS")
            print(f"Accuracy: {res.get('accuracy'):.4f}")
            print(f"Precision: {res.get('precision'):.4f}")
            print(f"Recall: {res.get('recall'):.4f}")
            print(f"Train size: {res.get('train_samples')} samples")
            print("Feature Importances:")
            for k, v in list(res.get('feature_importances', {}).items())[:5]:
                print(f"  - {k}: {v:.4f}")
    except Exception as e:
        print(f"Error testing /metrics: {e}")

    # 2. Test POST /predict with Legitimate URL
    try:
        print("\n--- Testing POST /predict (Legitimate URL) ---")
        payload = json.dumps({"url": "https://www.google.com/about"}).encode('utf-8')
        req = urllib.request.Request(
            f"{API_URL}/predict", 
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode())
            print(f"Status: SUCCESS")
            print(f"URL: {res.get('url')}")
            print(f"Risk Score: {res.get('risk_score')}%")
            print(f"Prediction: {res.get('prediction')} (0 = Legitimate, 1 = Phishing)")
            print(f"Explanations count: {len(res.get('explanations', []))}")
    except Exception as e:
        print(f"Error testing /predict (Legitimate): {e}")

    # 3. Test POST /predict with Phishing URL
    try:
        print("\n--- Testing POST /predict (Phishing URL) ---")
        payload = json.dumps({"url": "http://secure-paypal-login.net/banking/online/login.html"}).encode('utf-8')
        req = urllib.request.Request(
            f"{API_URL}/predict", 
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode())
            print(f"Status: SUCCESS")
            print(f"URL: {res.get('url')}")
            print(f"Risk Score: {res.get('risk_score')}%")
            print(f"Prediction: {res.get('prediction')} (0 = Legitimate, 1 = Phishing)")
            print("Detected Flags:")
            for exp in res.get('explanations', []):
                if exp.get('status') in ['warning', 'danger']:
                    print(f"  - [{exp.get('status').upper()}] {exp.get('feature')}: {exp.get('value')} ({exp.get('desc')})")
    except Exception as e:
        print(f"Error testing /predict (Phishing): {e}")

    # 4. Test Brand Impersonation Phishing URL
    try:
        print("\n--- Testing POST /predict (Google OAuth Impersonation) ---")
        payload = json.dumps({"url": "https://accounts-google-oauth.net/o/oauth2/auth?client_id=123"}).encode('utf-8')
        req = urllib.request.Request(
            f"{API_URL}/predict", 
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode())
            print(f"Status: SUCCESS")
            print(f"URL: {res.get('url')}")
            print(f"Risk Score: {res.get('risk_score')}%")
            print(f"Prediction: {res.get('prediction')} (0 = Legitimate, 1 = Phishing)")
            print("Detected Flags:")
            for exp in res.get('explanations', []):
                if exp.get('status') in ['warning', 'danger']:
                    print(f"  - [{exp.get('status').upper()}] {exp.get('feature')}: {exp.get('value')} ({exp.get('desc')})")
    except Exception as e:
        print(f"Error testing /predict (Impersonation): {e}")

    # 5. Test Legitimate Official OAuth URL
    try:
        print("\n--- Testing POST /predict (Official Google OAuth - Safe) ---")
        payload = json.dumps({"url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=123"}).encode('utf-8')
        req = urllib.request.Request(
            f"{API_URL}/predict", 
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode())
            print(f"Status: SUCCESS")
            print(f"URL: {res.get('url')}")
            print(f"Risk Score: {res.get('risk_score')}%")
            print(f"Prediction: {res.get('prediction')} (0 = Legitimate, 1 = Phishing)")
    except Exception as e:
        print(f"Error testing /predict (Official OAuth): {e}")

if __name__ == "__main__":
    test_api()
