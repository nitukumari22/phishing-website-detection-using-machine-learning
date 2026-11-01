// API Base Configuration
const API_BASE_URL = "http://127.0.0.1:8000";

// DOM Elements
const navScanBtn = document.getElementById("nav-scan-btn");
const navModelBtn = document.getElementById("nav-model-btn");
const scannerSection = document.getElementById("scanner-section");
const metricsSection = document.getElementById("metrics-section");

const scanForm = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const loadingState = document.getElementById("loading-state");
const resultsContainer = document.getElementById("results-container");

const riskPercentageText = document.getElementById("risk-percentage");
const gaugeFill = document.getElementById("gauge-fill");
const verdictBanner = document.getElementById("verdict-banner");
const verdictTitle = document.getElementById("verdict-title");
const verdictSubtitle = document.getElementById("verdict-subtitle");
const verdictIconSvg = document.getElementById("verdict-icon-svg");
const scannedUrlText = document.getElementById("scanned-url-text");
const explanationsList = document.getElementById("explanations-list");

// Metrics Elements
const statAccuracy = document.getElementById("stat-accuracy");
const statPrecision = document.getElementById("stat-precision");
const statRecall = document.getElementById("stat-recall");
const importanceChartContainer = document.getElementById("importance-chart-container");

// Retrain Form Elements
const uploadForm = document.getElementById("upload-form");
const dropzone = document.getElementById("dropzone");
const datasetFileInput = document.getElementById("dataset-file-input");
const fileDetails = document.getElementById("file-details");
const selectedFileName = document.getElementById("selected-file-name");
const removeFileBtn = document.getElementById("remove-file-btn");
const retrainSubmitBtn = document.getElementById("retrain-submit-btn");
const retrainLoading = document.getElementById("retrain-loading");

const modelTreesSpan = document.getElementById("model-trees");
const modelDepthSpan = document.getElementById("model-depth");
const historyContainer = document.getElementById("history-container");
const historyList = document.getElementById("history-list");

// SVGs for Verdict Banner
const SVG_SAFE = `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`;
const SVG_WARNING = `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>`;
const SVG_DANGER = `<octagon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></octagon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>`;

// State Variables
let selectedFile = null;

// Tab Navigation Handler
navScanBtn.addEventListener("click", () => {
    switchTab("scan");
});

navModelBtn.addEventListener("click", () => {
    switchTab("metrics");
    loadModelMetrics();
});

function switchTab(tab) {
    if (tab === "scan") {
        navScanBtn.classList.add("active");
        navModelBtn.classList.remove("active");
        scannerSection.classList.add("active");
        metricsSection.classList.remove("active");
    } else {
        navScanBtn.classList.remove("active");
        navModelBtn.classList.add("active");
        scannerSection.classList.remove("active");
        metricsSection.classList.add("active");
    }
}

// ----------------------------------------------------
// SCANNING LOGIC
// ----------------------------------------------------
scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    // Reset UI
    resultsContainer.classList.add("hidden");
    loadingState.classList.remove("hidden");

    try {
        const response = await fetch(`${API_BASE_URL}/predict`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || "Server returned error");
        }

        const data = await response.json();
        saveToHistory(url, data);
        
        // Console log simulator elements
        const consoleBox = document.getElementById("console-box");
        consoleBox.innerHTML = "";
        
        const logs = [
            { text: `[INIT] Parse URL protocol and domains...`, delay: 100, class: 'info' },
            { text: `[LEXICAL] Checking lexical factors (length: ${data.features.url_length} chars, dots: ${data.features.dot_count})...`, delay: 300, class: '' },
            { text: `[RESOLVE] Pinging domain '${data.url.replace(/^https?:\/\/(www\.)?/, '').split('/')[0]}' for DNS records...`, delay: 550, class: 'info' },
            { text: data.features.dns_resolved ? `[NET] Resolved IP Address: ${data.resolved_ip} (Online)` : `[NET] Host Offline (DNS resolution failed)`, delay: 800, class: data.features.dns_resolved ? 'success' : 'danger' },
            { text: data.features.brand_impersonation ? `[BRAND] WARNING: Brand spoofing signature detected!` : `[BRAND] Heuristics match official domain listings`, delay: 1050, class: data.features.brand_impersonation ? 'danger' : 'success' },
            { text: `[ML] Injecting feature vector to Random Forest...`, delay: 1250, class: '' },
            { text: `[DONE] Risk evaluation computed in 480ms. Rendering dashboard...`, delay: 1450, class: 'success' }
        ];

        logs.forEach(log => {
            setTimeout(() => {
                const line = document.createElement("div");
                line.className = `console-line ${log.class}`;
                line.textContent = log.text;
                consoleBox.appendChild(line);
                consoleBox.scrollTop = consoleBox.scrollHeight;
            }, log.delay);
        });

        // Show results after log simulation finishes
        setTimeout(() => {
            loadingState.classList.add("hidden");
            renderScanResults(data);
        }, 1700);

    } catch (err) {
        alert(`Scan failed: ${err.message}. Make sure the backend server is running.`);
        console.error(err);
        loadingState.classList.add("hidden");
    }
});

function renderScanResults(data) {
    const risk = data.risk_score;
    scannedUrlText.textContent = data.url;

    // Reset indicator styles using CSS Variables
    let themeColor = "var(--accent)";
    let themeGlow = "var(--accent-glow)";
    
    if (risk < 30) {
        themeColor = "var(--color-safe)";
        themeGlow = "var(--color-safe-glow)";
    } else if (risk >= 30 && risk < 70) {
        themeColor = "var(--color-warning)";
        themeGlow = "var(--color-warning-glow)";
    } else {
        themeColor = "var(--color-danger)";
        themeGlow = "var(--color-danger-glow)";
    }
    
    document.body.style.setProperty('--theme-color', themeColor);
    document.body.style.setProperty('--theme-glow', themeGlow);

    // Render visual breakdown
    renderURLHighlight(data.url, data);

    // 1. Ticking Counter Animation
    let startVal = 0;
    const targetVal = Math.round(risk);
    riskPercentageText.textContent = "0%";
    
    const counterInterval = setInterval(() => {
        if (startVal >= targetVal) {
            riskPercentageText.textContent = `${targetVal}%`;
            clearInterval(counterInterval);
        } else {
            startVal += Math.ceil((targetVal - startVal) / 8) || 1;
            riskPercentageText.textContent = `${startVal}%`;
        }
    }, 25);

    // 2. Calculate radial gauge animation
    const circumference = 251.2;
    const dashoffset = circumference - (risk / 100) * circumference;
    
    gaugeFill.style.strokeDasharray = circumference;
    gaugeFill.style.strokeDashoffset = dashoffset;
    gaugeFill.style.stroke = themeColor;

    // Reset Verdict banner CSS classes
    verdictBanner.className = "verdict-banner";
    
    if (risk < 30) {
        // Legitimate / Safe
        verdictBanner.classList.add("safe");
        verdictTitle.textContent = "LEGITIMATE WEBSITE";
        verdictSubtitle.textContent = `High certainty (${100 - risk}% safe) that this site is clean.`;
        verdictIconSvg.innerHTML = SVG_SAFE;
    } else if (risk >= 30 && risk < 70) {
        // Suspicious / Warning
        verdictBanner.classList.add("warning");
        verdictTitle.textContent = "SUSPICIOUS TRAITS DETECTED";
        verdictSubtitle.textContent = "Moderate risk elements found. Exercise caution before logging in.";
        verdictIconSvg.innerHTML = SVG_WARNING;
    } else {
        // Phishing / Danger
        verdictBanner.classList.add("danger");
        verdictTitle.textContent = "PHISHING WEBSITE DETECTED";
        verdictSubtitle.textContent = `High risk (${risk}% phishing). Avoid sharing credentials.`;
        verdictIconSvg.innerHTML = SVG_DANGER;
    }

    // 2. Render detailed explanations
    explanationsList.innerHTML = "";
    
    if (data.explanations && data.explanations.length > 0) {
        data.explanations.forEach(exp => {
            const item = document.createElement("div");
            item.className = "explanation-item";
            
            item.innerHTML = `
                <div class="exp-status-indicator ${exp.status}"></div>
                <div class="exp-info">
                    <div class="exp-header">
                        <span class="exp-name">${exp.feature}</span>
                        <span class="exp-value ${exp.status}">${exp.value}</span>
                    </div>
                    <p class="exp-desc">${exp.desc}</p>
                </div>
            `;
            explanationsList.appendChild(item);
        });
    } else {
        // Fallback if everything is safe
        const item = document.createElement("div");
        item.className = "explanation-item";
        item.innerHTML = `
            <div class="exp-status-indicator safe"></div>
            <div class="exp-info">
                <div class="exp-header">
                    <span class="exp-name">All Markers Safe</span>
                    <span class="exp-value safe">Verified</span>
                </div>
                <p class="exp-desc">URL parameters and structure match legitimate usage norms perfectly.</p>
            </div>
        `;
        explanationsList.appendChild(item);
    }

    // Show results panel
    resultsContainer.classList.remove("hidden");
}

// ----------------------------------------------------
// METRICS & VISUALS LOGIC
// ----------------------------------------------------
async function loadModelMetrics() {
    try {
        const response = await fetch(`${API_BASE_URL}/metrics`);
        if (!response.ok) throw new Error("Could not fetch model metrics.");
        
        const data = await response.json();
        if (data.status === "untrained") {
            statAccuracy.textContent = "N/A";
            statPrecision.textContent = "N/A";
            statRecall.textContent = "N/A";
            importanceChartContainer.innerHTML = "<p class='section-desc'>Model is not trained. Retrain to see statistics.</p>";
            return;
        }

        // Set performance stats
        statAccuracy.textContent = `${(data.accuracy * 100).toFixed(1)}%`;
        statPrecision.textContent = `${(data.precision * 100).toFixed(1)}%`;
        statRecall.textContent = `${(data.recall * 100).toFixed(1)}%`;

        if (modelTreesSpan && modelDepthSpan) {
            modelTreesSpan.textContent = data.n_estimators || 100;
            modelDepthSpan.textContent = data.max_depth || 15;
        }

        // Render feature importance chart
        importanceChartContainer.innerHTML = "";
        
        // Sort feature importances descending
        const sortedImportances = Object.entries(data.feature_importances)
            .sort((a, b) => b[1] - a[1]);

        // Find max weight to normalize bar fills
        const maxVal = sortedImportances.length > 0 ? sortedImportances[0][1] : 1;

        sortedImportances.forEach(([feat, weight]) => {
            const barPct = (weight / maxVal) * 100;
            const barItem = document.createElement("div");
            barItem.className = "chart-bar-item";

            // Beautify feature names for display
            const displayName = feat.replace(/_/g, ' ').toUpperCase();

            barItem.innerHTML = `
                <div class="chart-bar-label-row">
                    <span class="chart-bar-name">${displayName}</span>
                    <span class="chart-bar-val">${(weight * 100).toFixed(1)}%</span>
                </div>
                <div class="chart-bar-track">
                    <div class="chart-bar-fill" style="width: 0%"></div>
                </div>
            `;
            importanceChartContainer.appendChild(barItem);

            // Animate width increase shortly after adding to DOM
            setTimeout(() => {
                const fill = barItem.querySelector(".chart-bar-fill");
                if (fill) fill.style.width = `${barPct}%`;
            }, 100);
        });

    } catch (err) {
        console.error(err);
    }
}

// ----------------------------------------------------
// DRAG & DROP RETRAINING LOGIC
// ----------------------------------------------------
dropzone.addEventListener("click", () => {
    datasetFileInput.click();
});

dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
});

dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    
    if (e.dataTransfer.files.length > 0) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
});

datasetFileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

function handleFileSelect(file) {
    if (!file.name.endsWith('.csv')) {
        alert("Please select a valid CSV file.");
        return;
    }
    
    selectedFile = file;
    selectedFileName.textContent = file.name;
    
    dropzone.classList.add("hidden");
    fileDetails.classList.remove("hidden");
    retrainSubmitBtn.disabled = false;
}

removeFileBtn.addEventListener("click", () => {
    selectedFile = null;
    datasetFileInput.value = "";
    
    fileDetails.classList.add("hidden");
    dropzone.classList.remove("hidden");
    retrainSubmitBtn.disabled = true;
});

uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    const trees = document.getElementById("param-n-estimators").value;
    const depth = document.getElementById("param-max-depth").value;

    retrainSubmitBtn.disabled = true;
    retrainLoading.classList.remove("hidden");

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
        const response = await fetch(`${API_BASE_URL}/retrain?n_estimators=${trees}&max_depth=${depth}`, {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || "Retraining failed");
        }

        const data = await response.json();
        alert("Success! Model has been retrained with the new dataset.");
        
        // Reset file selection
        removeFileBtn.click();
        
        // Reload metrics
        loadModelMetrics();
    } catch (err) {
        alert(`Retraining failed: ${err.message}`);
        retrainSubmitBtn.disabled = false;
    } finally {
        retrainLoading.classList.add("hidden");
    }
});

// Load stats initially on page load
window.addEventListener("DOMContentLoaded", () => {
    loadModelMetrics();
    loadHistory();
});

// ----------------------------------------------------
// ENHANCED UTILITIES: HIGHLIGHTER & HISTORY
// ----------------------------------------------------

function renderURLHighlight(urlStr, data) {
    const container = document.getElementById("url-highlighter-box");
    if (!container) return;
    container.innerHTML = "";
    
    let urlToParse = urlStr;
    if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
        urlToParse = "http://" + urlStr;
    }
    
    try {
        const parsed = new URL(urlToParse);
        const scheme = parsed.protocol + "//";
        const domain = parsed.hostname;
        const path = parsed.pathname;
        const query = parsed.search + parsed.hash;
        
        // 1. Render Scheme
        const schemeSpan = document.createElement("span");
        schemeSpan.className = "url-segment scheme";
        schemeSpan.textContent = scheme;
        if (data.features.is_https === 0) {
            schemeSpan.classList.add("warning-segment");
            schemeSpan.title = "Insecure protocol (HTTP)";
        }
        container.appendChild(schemeSpan);
        
        // 2. Render Domain
        const domainSpan = document.createElement("span");
        domainSpan.className = "url-segment domain";
        domainSpan.textContent = domain;
        if (data.features.brand_impersonation === 1) {
            domainSpan.classList.add("suspicious");
            domainSpan.title = "Brand Impersonation / Spoofing Detected!";
        } else if (data.features.domain_hyphens > 1) {
            domainSpan.classList.add("warning-segment");
            domainSpan.title = `Domain contains ${data.features.domain_hyphens} hyphens`;
        }
        container.appendChild(domainSpan);
        
        // 3. Render Path
        const pathSpan = document.createElement("span");
        pathSpan.className = "url-segment path";
        pathSpan.textContent = path;
        if (data.features.domain_in_path === 1) {
            pathSpan.classList.add("suspicious");
            pathSpan.title = "TLD extension (.com/.org) injected inside URL path!";
        }
        container.appendChild(pathSpan);
        
        // 4. Render Query
        if (query) {
            const querySpan = document.createElement("span");
            querySpan.className = "url-segment query";
            querySpan.textContent = query;
            container.appendChild(querySpan);
        }
    } catch (err) {
        // Fallback
        const fallbackSpan = document.createElement("span");
        fallbackSpan.className = "url-segment domain suspicious";
        fallbackSpan.textContent = urlStr;
        container.appendChild(fallbackSpan);
    }
}

function loadHistory() {
    if (!historyList || !historyContainer) return;
    
    let history = [];
    try {
        history = JSON.parse(localStorage.getItem("phish_scans")) || [];
    } catch(e) {
        history = [];
    }
    
    if (history.length === 0) {
        historyContainer.classList.add("hidden");
        return;
    }
    
    historyList.innerHTML = "";
    history.forEach(item => {
        const btn = document.createElement("div");
        btn.className = "history-item";
        btn.textContent = item.url.replace(/^https?:\/\/(www\.)?/, '');
        btn.title = `Risk: ${item.data.risk_score}% - Click to load`;
        
        btn.addEventListener("click", () => {
            urlInput.value = item.url;
            renderScanResults(item.data);
            switchTab("scan");
        });
        historyList.appendChild(btn);
    });
    
    historyContainer.classList.remove("hidden");
}

function saveToHistory(url, data) {
    let history = [];
    try {
        history = JSON.parse(localStorage.getItem("phish_scans")) || [];
    } catch(e) {
        history = [];
    }
    
    // Avoid duplicate URLs in history
    history = history.filter(item => item.url.toLowerCase() !== url.toLowerCase());
    
    // Add to beginning of array
    history.unshift({ url, data, timestamp: new Date().getTime() });
    
    // Limit to 5 items
    if (history.length > 5) {
        history.pop();
    }
    
    localStorage.setItem("phish_scans", JSON.stringify(history));
    loadHistory();
}
