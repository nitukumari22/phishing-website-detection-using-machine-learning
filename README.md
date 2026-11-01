# 🛡️ PhishShield AI - Real-Time Phishing Website Detection

PhishShield AI is a full-stack Machine Learning application designed to analyze and detect phishing websites in real time. It uses URL feature extraction (lexical, SSL credentials, domain structure) paired with a trained ML model to identify fraudulent links instantly.

---

## ✨ Features

- **Real-Time Link Scanning:** Quick diagnosis of suspect links and domains.
- **Machine Learning Powered:** High-accuracy classification using XGBoost / Random Forest algorithms.
- **Full-Stack Architecture:** 
  - **Backend:** Flask REST API for model predictions.
  - **Frontend:** Modern, dark-themed responsive user interface.
- **Feature Extraction Pipeline:** Automated URL parsing for lexical structure and security metrics.

---

## 🛠️ Tech Stack

- **Frontend:** HTML5, CSS3, JavaScript (ES6+)
- **Backend:** Python, Flask, Flask-CORS
- **Machine Learning:** XGBoost, Scikit-learn, Pandas, Joblib
- **Automation / Scripts:** Windows Batch Script (`run_project.bat`)

---

## 📁 Repository Structure

```text
phishing-detector/
├── backend/
│   ├── app.py                  # Flask API server
│   ├── extractors.py           # Feature extraction logic
│   ├── model.joblib            # Trained ML model
│   ├── model_metrics.json      # Performance benchmarks
│   ├── requirements.txt        # Backend dependencies
│   └── train.py                # Model training script
├── frontend/
│   ├── index.html              # Main UI dashboard
│   ├── styles.css              # Custom styling
│   └── app.js                  # Frontend logic & API calls
├── requirements.txt            # Project dependencies
└── run_project.bat             # One-click launcher script
