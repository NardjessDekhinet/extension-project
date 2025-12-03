// URL Security Scanner - Popup Script
class URLSecurityScanner {
    constructor() {
        this.isScanning = false;
        this.currentScanData = null;
        this.securityEngines = this.initializeEngines();
        this.initializeEventListeners();
        this.loadHistory();
        this.setupCurrentTabScan();
    }

    initializeEngines() {
        return [
            { name: "Google Safe Browsing", weight: 15, type: "primary" },
            { name: "Microsoft Defender", weight: 12, type: "antivirus" },
            { name: "Kaspersky", weight: 11, type: "antivirus" },
            { name: "Norton", weight: 10, type: "antivirus" },
            { name: "Bitdefender", weight: 9, type: "antivirus" },
            { name: "McAfee", weight: 8, type: "antivirus" },
            { name: "Trend Micro", weight: 7, type: "antivirus" },
            { name: "ESET", weight: 6, type: "antivirus" },
            { name: "Avast", weight: 5, type: "antivirus" },
            { name: "AVG", weight: 4, type: "antivirus" },
            { name: "Symantec", weight: 4, type: "antivirus" },
            { name: "F-Secure", weight: 3, type: "antivirus" },
            { name: "Sophos", weight: 3, type: "antivirus" },
            { name: "Malwarebytes", weight: 3, type: "antimalware" },
            { name: "Panda", weight: 3, type: "antivirus" }
        ];
    }

    initializeEventListeners() {
        // Scan buttons
        document.getElementById('scanCurrentTab').addEventListener('click', () => this.scanCurrentTab());
        document.getElementById('scanButton').addEventListener('click', () => this.scanURL());
        
        // URL input
        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.scanURL();
        });

        // Export buttons
        document.getElementById('exportPDF').addEventListener('click', () => this.exportPDF());
        document.getElementById('exportJSON').addEventListener('click', () => this.exportJSON());
        document.getElementById('exportCSV').addEventListener('click', () => this.exportCSV());

        // Share buttons
        document.getElementById('copyLink').addEventListener('click', () => this.copyShareLink());
        document.getElementById('copyText').addEventListener('click', () => this.copyTextSummary());
        document.getElementById('shareEmail').addEventListener('click', () => this.shareViaEmail());

        // History management
        document.getElementById('clearHistory').addEventListener('click', () => this.clearHistory());

        // Alert acknowledgment
        document.getElementById('acknowledgeBtn').addEventListener('click', () => this.acknowledgeAlert());
    }

    async setupCurrentTabScan() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('moz-extension://')) {
                const domain = new URL(tab.url).hostname;
                document.getElementById('scanCurrentTab').innerHTML = `
                    <span class="icon">🔍</span>
                    Scan ${domain}
                `;
            }
        } catch (error) {
            console.error('Failed to get current tab:', error);
        }
    }

    async scanCurrentTab() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url) {
                document.getElementById('urlInput').value = tab.url;
                await this.scanURL();
            }
        } catch (error) {
            this.showToast('Unable to scan current tab', 'error');
        }
    }

    async scanURL() {
        const urlInput = document.getElementById('urlInput').value.trim();
        
        if (!urlInput) {
            this.showToast('Please enter a URL to scan', 'warning');
            return;
        }

        if (!this.isValidURL(urlInput)) {
            this.showToast('Please enter a valid URL', 'error');
            return;
        }

        if (this.isScanning) {
            return;
        }

        this.isScanning = true;
        this.showLoadingState(true);
        this.hideAlerts();
        this.hideResults();

        try {
            const scanData = await this.performSecurityScan(urlInput);
            this.currentScanData = scanData;
            this.displayResults(scanData);
            this.saveToHistory(scanData);
            this.showAlertIfNeeded(scanData);
        } catch (error) {
            console.error('Scan failed:', error);
            this.showToast('Scan failed. Please try again.', 'error');
        } finally {
            this.isScanning = false;
            this.showLoadingState(false);
        }
    }

    isValidURL(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    }

    async performSecurityScan(url) {
        const scanStartTime = new Date();
        
        // Simulate scanning delay
        await this.delay(2000);

        // Analyze URL with multiple methods
        const localAnalysis = this.analyzeUrlLocally(url);
        const apiAnalysis = await this.checkWithAPIs(url);
        const engineResults = this.generateEngineResults(url, localAnalysis.riskScore);

        // Calculate final risk score
        const riskScore = Math.max(localAnalysis.riskScore, apiAnalysis.riskScore);
        const status = this.determineStatus(riskScore);
        const detectedEngines = engineResults.filter(engine => engine.result === 'malicious').length;

        return {
            url: url,
            status: status,
            riskScore: riskScore,
            scanTime: scanStartTime,
            detectedEngines: detectedEngines,
            totalEngines: engineResults.length,
            threats: [...localAnalysis.threats, ...apiAnalysis.threats],
            engineResults: engineResults,
            details: this.generateScanDetails(riskScore, [...localAnalysis.threats, ...apiAnalysis.threats])
        };
    }

    analyzeUrlLocally(url) {
        let riskScore = 0;
        const threats = [];

        // Suspicious patterns
        const suspiciousPatterns = [
            { pattern: /(?:phishing|scam|fake|fraud)/i, score: 60, threat: 'Phishing' },
            { pattern: /(?:malware|virus|trojan)/i, score: 80, threat: 'Malware' },
            { pattern: /(?:suspicious|dangerous|harmful)/i, score: 40, threat: 'Suspicious' },
            { pattern: /(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i, score: 30, threat: 'IP Address' },
            { pattern: /(?:\.tk|\.ml|\.ga|\.cf)$/i, score: 25, threat: 'Suspicious TLD' }
        ];

        suspiciousPatterns.forEach(({ pattern, score, threat }) => {
            if (pattern.test(url)) {
                riskScore += score;
                threats.push(threat);
            }
        });

        // Non-HTTPS
        if (!url.startsWith('https://')) {
            riskScore += 15;
            threats.push('Non-HTTPS Connection');
        }

        // Unusually long URL
        if (url.length > 100) {
            riskScore += 10;
            threats.push('Unusually Long URL');
        }

        // URL shorteners
        const shorteners = ['bit.ly', 'tinyurl', 'short.link', 't.co', 'goo.gl'];
        if (shorteners.some(shortener => url.includes(shortener))) {
            riskScore += 20;
            threats.push('URL Shortener');
        }

        return {
            riskScore: Math.min(riskScore, 100),
            threats: [...new Set(threats)]
        };
    }

    async checkWithAPIs(url) {
        // Simulate API calls
        await this.delay(1000);
        
        // Simple heuristic for demonstration
        const domain = new URL(url).hostname.toLowerCase();
        let apiScore = 0;
        const apiThreats = [];

        // Known safe domains
        const safeDomains = ['google.com', 'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com'];
        if (safeDomains.some(safe => domain.includes(safe))) {
            return { riskScore: 0, threats: [] };
        }

        // Known dangerous test domains
        const dangerousDomains = ['malware', 'phishing', 'virus', 'scam', 'fake'];
        if (dangerousDomains.some(danger => domain.includes(danger))) {
            apiScore = 85;
            apiThreats.push('Malware', 'Phishing');
        }

        return { riskScore: apiScore, threats: apiThreats };
    }

    generateEngineResults(url, riskScore) {
        const engines = [...this.securityEngines];
        const baseDetectionRate = riskScore / 100;
        
        return engines.map(engine => {
            const randomFactor = (Math.random() - 0.5) * 0.3; // ±15% variation
            const detectionProbability = Math.max(0, Math.min(1, baseDetectionRate + randomFactor));
            const random = Math.random();
            
            let result;
            if (random < detectionProbability * 0.7) {
                result = 'malicious';
            } else if (random < detectionProbability * 0.9) {
                result = 'suspicious';
            } else if (random < 0.95) {
                result = 'clean';
            } else {
                result = 'timeout';
            }

            return {
                name: engine.name,
                result: result,
                weight: engine.weight
            };
        });
    }

    determineStatus(riskScore) {
        if (riskScore >= 86) return 'critical';
        if (riskScore >= 61) return 'dangerous';
        if (riskScore >= 16) return 'suspicious';
        return 'safe';
    }

    generateScanDetails(riskScore, threats) {
        if (riskScore >= 86) {
            return 'Multiple security engines detected severe threats. This URL is extremely dangerous.';
        } else if (riskScore >= 61) {
            return 'Several security engines flagged this URL as containing malware or other threats.';
        } else if (riskScore >= 16) {
            return 'Some security engines detected suspicious activity. Exercise caution.';
        } else {
            return 'No significant threats detected. This URL appears to be safe.';
        }
    }

    displayResults(scanData) {
        // Update status and score
        document.getElementById('resultStatus').textContent = this.getStatusText(scanData.status);
        document.getElementById('scoreNumber').textContent = scanData.riskScore;
        
        // Update score circle color
        const scoreCircle = document.getElementById('scoreCircle');
        scoreCircle.style.setProperty('--score-angle', `${scanData.riskScore * 3.6}deg`);
        scoreCircle.className = `score-circle ${scanData.status}`;

        // Update detection summary
        document.getElementById('detectedEngines').textContent = scanData.detectedEngines;
        document.getElementById('totalEngines').textContent = scanData.totalEngines;
        document.getElementById('scanTime').textContent = scanData.scanTime.toLocaleString();

        // Update threat breakdown
        this.displayThreatBreakdown(scanData.threats);

        // Update engines grid
        this.displayEngineResults(scanData.engineResults);

        // Show results and actions
        document.getElementById('resultsSection').style.display = 'block';
        document.getElementById('actionsSection').style.display = 'block';
    }

    displayThreatBreakdown(threats) {
        const breakdownDiv = document.getElementById('threatBreakdown');
        
        if (threats.length === 0) {
            breakdownDiv.innerHTML = '<div style="text-align: center; color: #28a745;">No threats detected</div>';
            return;
        }

        const threatHTML = `
            <h4>Threats Detected:</h4>
            <div class="threat-list">
                ${threats.map(threat => `<span class="threat-tag ${threat.toLowerCase()}">${threat}</span>`).join('')}
            </div>
        `;
        
        breakdownDiv.innerHTML = threatHTML;
    }

    displayEngineResults(engineResults) {
        const gridDiv = document.getElementById('enginesGrid');
        
        const engineHTML = engineResults.map(engine => `
            <div class="engine-item">
                <span class="engine-name">${engine.name}</span>
                <span class="engine-result ${engine.result}">${this.getEngineResultText(engine.result)}</span>
            </div>
        `).join('');
        
        gridDiv.innerHTML = engineHTML;
    }

    getStatusText(status) {
        const statusMap = {
            'safe': '✅ Safe',
            'suspicious': '⚠️ Suspicious',
            'dangerous': '⚠️ Dangerous',
            'critical': '🛑 Critical Threat'
        };
        return statusMap[status] || 'Unknown';
    }

    getEngineResultText(result) {
        const resultMap = {
            'clean': 'Clean',
            'malicious': 'Malicious',
            'suspicious': 'Suspicious',
            'timeout': 'Timeout'
        };
        return resultMap[result] || 'Unknown';
    }

    showAlertIfNeeded(scanData) {
        if (scanData.status === 'safe') {
            return;
        }

        const alertsSection = document.getElementById('alertsSection');
        const alertBanner = document.getElementById('alertBanner');
        const alertIcon = document.getElementById('alertIcon');
        const alertTitle = document.getElementById('alertTitle');
        const alertMessage = document.getElementById('alertMessage');
        const alertDetails = document.getElementById('alertDetails');
        const acknowledgeBtn = document.getElementById('acknowledgeBtn');

        // Configure alert based on threat level
        const alertConfig = this.getAlertConfig(scanData.status);
        
        alertBanner.className = `alert-banner ${scanData.status}`;
        alertIcon.textContent = alertConfig.icon;
        alertTitle.textContent = alertConfig.title;
        alertMessage.textContent = alertConfig.message;
        alertDetails.textContent = scanData.details;

        // Show acknowledgment button for critical threats
        if (scanData.status === 'critical') {
            acknowledgeBtn.style.display = 'block';
        } else {
            acknowledgeBtn.style.display = 'none';
        }

        alertsSection.style.display = 'block';

        // Play sound for critical threats
        if (scanData.status === 'critical') {
            this.playAlertSound();
        }
    }

    getAlertConfig(status) {
        const configs = {
            'suspicious': {
                icon: '⚠️',
                title: 'SUSPICIOUS ACTIVITY DETECTED',
                message: 'This URL shows signs of potentially harmful content. Exercise caution and verify the source before proceeding.'
            },
            'dangerous': {
                icon: '⚠️',
                title: 'DANGEROUS URL DETECTED',
                message: 'This URL contains malware or other serious threats. Visiting this site may harm your computer or steal personal information.'
            },
            'critical': {
                icon: '🛑',
                title: 'CRITICAL THREAT DETECTED',
                message: 'This URL is extremely dangerous and should not be visited. Multiple security engines detected severe threats.'
            }
        };
        return configs[status] || configs.suspicious;
    }

    playAlertSound() {
        // Create a simple beep sound using Web Audio API
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.value = 800;
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.5);
        } catch (error) {
            console.log('Audio alert not available:', error);
        }
    }

    acknowledgeAlert() {
        document.getElementById('alertsSection').style.display = 'none';
    }

    hideAlerts() {
        document.getElementById('alertsSection').style.display = 'none';
    }

    hideResults() {
        document.getElementById('resultsSection').style.display = 'none';
        document.getElementById('actionsSection').style.display = 'none';
    }

    showLoadingState(loading) {
        const scanButton = document.getElementById('scanButton');
        if (loading) {
            scanButton.classList.add('loading');
            scanButton.disabled = true;
        } else {
            scanButton.classList.remove('loading');
            scanButton.disabled = false;
        }
    }

    // Export Functions
    async exportPDF() {
        if (!this.currentScanData) return;

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            // Header
            doc.setFontSize(20);
            doc.text('URL Security Scan Report', 20, 30);
            
            doc.setFontSize(12);
            doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 45);
            
            // URL Information
            doc.setFontSize(14);
            doc.text('URL Analyzed:', 20, 65);
            doc.setFontSize(10);
            doc.text(this.currentScanData.url, 20, 75);
            
            // Security Status
            doc.setFontSize(14);
            doc.text('Security Status:', 20, 95);
            doc.setFontSize(12);
            doc.text(`${this.getStatusText(this.currentScanData.status)} (${this.currentScanData.riskScore}% risk)`, 20, 105);
            
            // Detection Summary
            doc.text(`Engines Detected: ${this.currentScanData.detectedEngines}/${this.currentScanData.totalEngines}`, 20, 115);
            
            // Threats
            if (this.currentScanData.threats.length > 0) {
                doc.text('Threats Detected:', 20, 135);
                this.currentScanData.threats.forEach((threat, index) => {
                    doc.text(`• ${threat}`, 30, 145 + (index * 10));
                });
            }
            
            const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
            doc.save(`security_report_${timestamp}.pdf`);
            
            this.showToast('PDF report exported successfully!', 'success');
        } catch (error) {
            console.error('PDF export failed:', error);
            
            // Fallback: create text-based report
            const reportContent = this.generateTextReport();
            const blob = new Blob([reportContent], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_report_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`;
            a.click();
            URL.revokeObjectURL(url);
            
            this.showToast('Report exported as text file', 'success');
        }
    }

    async exportJSON() {
        if (!this.currentScanData) return;

        const exportData = {
            ...this.currentScanData,
            exportTime: new Date().toISOString(),
            version: '1.0.0'
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_data_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
        a.click();
        URL.revokeObjectURL(url);

        this.showToast('JSON data exported successfully!', 'success');
    }

    async exportCSV() {
        if (!this.currentScanData) return;

        const csvContent = [
            'URL,Status,Threat_Score,Engines_Detected,Total_Engines,Threats,Scan_Time',
            `"${this.currentScanData.url}","${this.currentScanData.status}",${this.currentScanData.riskScore},${this.currentScanData.detectedEngines},${this.currentScanData.totalEngines},"${this.currentScanData.threats.join('; ')}","${this.currentScanData.scanTime.toISOString()}"`
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_results_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
        a.click();
        URL.revokeObjectURL(url);

        this.showToast('CSV data exported successfully!', 'success');
    }

    generateTextReport() {
        if (!this.currentScanData) return '';

        return `
URL Security Scan Report
========================

Generated: ${new Date().toLocaleString()}
URL Analyzed: ${this.currentScanData.url}

Security Status: ${this.getStatusText(this.currentScanData.status)} (${this.currentScanData.riskScore}% risk)
Engines Detected: ${this.currentScanData.detectedEngines}/${this.currentScanData.totalEngines}
Scan Time: ${this.currentScanData.scanTime.toLocaleString()}

Threats Detected:
${this.currentScanData.threats.map(threat => `• ${threat}`).join('\n')}

Details:
${this.currentScanData.details}

Engine Results:
${this.currentScanData.engineResults.map(engine => `• ${engine.name}: ${this.getEngineResultText(engine.result)}`).join('\n')}

Powered by URL Security Scanner v1.0.0
        `.trim();
    }

    // Share Functions
    async copyShareLink() {
        if (!this.currentScanData) return;

        const shareText = `Security scan results for ${this.currentScanData.url}: ${this.currentScanData.status.toUpperCase()} (${this.currentScanData.riskScore}% risk) - Scanned at ${this.currentScanData.scanTime.toLocaleString()}`;
        
        try {
            await navigator.clipboard.writeText(shareText);
            this.showToast('Share link copied to clipboard!', 'success');
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            this.showToast('Failed to copy to clipboard', 'error');
        }
    }

    async copyTextSummary() {
        if (!this.currentScanData) return;

        const summary = `🔒 URL Security Scan Results
URL: ${this.currentScanData.url}
Status: ${this.currentScanData.status.toUpperCase()}
Threat Score: ${this.currentScanData.riskScore}%
Engines Detected: ${this.currentScanData.detectedEngines}/${this.currentScanData.totalEngines}
Scanned: ${this.currentScanData.scanTime.toLocaleString()}

Powered by URL Security Scanner`;

        try {
            await navigator.clipboard.writeText(summary);
            this.showToast('Results copied to clipboard!', 'success');
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            this.showToast('Failed to copy to clipboard', 'error');
        }
    }

    shareViaEmail() {
        if (!this.currentScanData) return;

        const subject = encodeURIComponent('URL Security Scan Results');
        const body = encodeURIComponent(this.generateTextReport());
        const mailtoLink = `mailto:?subject=${subject}&body=${body}`;
        
        window.open(mailtoLink);
        this.showToast('Email client opened with scan results!', 'success');
    }

    // History Management
    saveToHistory(scanData) {
        try {
            const historyKey = 'scanHistory';
            chrome.storage.local.get([historyKey], (result) => {
                let history = result[historyKey] || [];
                
                // Add new scan to beginning
                history.unshift({
                    url: scanData.url,
                    status: scanData.status,
                    riskScore: scanData.riskScore,
                    scanTime: scanData.scanTime.toISOString()
                });
                
                // Keep only last 10 scans
                history = history.slice(0, 10);
                
                chrome.storage.local.set({ [historyKey]: history }, () => {
                    this.loadHistory();
                });
            });
        } catch (error) {
            console.error('Failed to save to history:', error);
        }
    }

    loadHistory() {
        try {
            chrome.storage.local.get(['scanHistory'], (result) => {
                const history = result.scanHistory || [];
                this.displayHistory(history);
            });
        } catch (error) {
            console.error('Failed to load history:', error);
            this.displayHistory([]);
        }
    }

    displayHistory(history) {
        const historyList = document.getElementById('historyList');
        
        if (history.length === 0) {
            historyList.innerHTML = '<div class="history-empty">No recent scans</div>';
            return;
        }

        const historyHTML = history.map(item => `
            <div class="history-item">
                <span class="history-url" title="${item.url}">${this.truncateUrl(item.url)}</span>
                <span class="history-status ${item.status}">${item.status}</span>
            </div>
        `).join('');
        
        historyList.innerHTML = historyHTML;
    }

    truncateUrl(url) {
        if (url.length <= 30) return url;
        return url.substring(0, 30) + '...';
    }

    clearHistory() {
        try {
            chrome.storage.local.remove(['scanHistory'], () => {
                this.loadHistory();
                this.showToast('History cleared', 'success');
            });
        } catch (error) {
            console.error('Failed to clear history:', error);
            this.showToast('Failed to clear history', 'error');
        }
    }

    // Utility Functions
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    showToast(message, type = 'info') {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = `toast show ${type}`;
        
        setTimeout(() => {
            toast.className = 'toast';
        }, 3000);
    }
}

// Initialize scanner when popup loads
document.addEventListener('DOMContentLoaded', () => {
    new URLSecurityScanner();
});