// Security Engines Data
const SECURITY_ENGINES = [
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
  { name: "Panda", weight: 2, type: "antivirus" },
  { name: "Malwarebytes", weight: 2, type: "antivirus" }
];

// Threat Categories
const THREAT_CATEGORIES = {
  malware: { name: "Malware", color: "#dc3545", severity: "high" },
  phishing: { name: "Phishing", color: "#fd7e14", severity: "high" },
  suspicious: { name: "Suspicious", color: "#ffc107", severity: "medium" },
  spam: { name: "Spam", color: "#6f42c1", severity: "low" },
  unwanted: { name: "Potentially Unwanted", color: "#20c997", severity: "low" }
};

// Known malicious patterns for demonstration
const MALICIOUS_PATTERNS = [
  'malware', 'virus', 'trojan', 'phishing', 'scam', 'fake',
  'suspicious', 'dangerous', 'harmful', 'badware', 'exploit'
];

// Application State
class URLScanner {
  constructor() {
    this.currentScan = null;
    this.scanHistory = [];
    this.settings = {
      autoScanEnabled: true,
      notificationsEnabled: true,
      saveHistoryEnabled: true,
      timeout: 30
    };
    
    this.initializeElements();
    this.attachEventListeners();
    this.loadSettings();
  }

  initializeElements() {
    // Input elements
    this.urlInput = document.getElementById('urlInput');
    this.scanBtn = document.getElementById('scanBtn');
    this.scanCurrentBtn = document.getElementById('scanCurrentBtn');
    this.pasteBtn = document.getElementById('pasteBtn');
    
    // Section elements
    this.loadingSection = document.getElementById('loadingSection');
    this.resultsSection = document.getElementById('resultsSection');
    this.historySection = document.getElementById('historySection');
    this.settingsSection = document.getElementById('settingsSection');
    this.errorSection = document.getElementById('errorSection');
    
    // Loading elements
    this.loadingStatus = document.getElementById('loadingStatus');
    this.progressFill = document.getElementById('progressFill');
    this.enginesCount = document.getElementById('enginesCount');
    
    // Result elements
    this.statusIndicator = document.getElementById('statusIndicator');
    this.statusIcon = document.getElementById('statusIcon');
    this.statusTitle = document.getElementById('statusTitle');
    this.statusDescription = document.getElementById('statusDescription');
    this.scoreCircle = document.getElementById('scoreCircle');
    this.scoreNumber = document.getElementById('scoreNumber');
    this.detectedCount = document.getElementById('detectedCount');
    this.totalEngines = document.getElementById('totalEngines');
    this.detectionFill = document.getElementById('detectionFill');
    this.threatCategories = document.getElementById('threatCategories');
    this.enginesList = document.getElementById('enginesList');
    
    // Navigation elements
    this.historyBtn = document.getElementById('historyBtn');
    this.settingsBtn = document.getElementById('settingsBtn');
    this.historyList = document.getElementById('historyList');
    
    // Action buttons
    this.toggleEngines = document.getElementById('toggleEngines');
    this.exportBtn = document.getElementById('exportBtn');
    this.shareBtn = document.getElementById('shareBtn');
    this.rescanBtn = document.getElementById('rescanBtn');
    this.retryBtn = document.getElementById('retryBtn');
    this.clearHistoryBtn = document.getElementById('clearHistoryBtn');
    
    // Error elements
    this.errorMessage = document.getElementById('errorMessage');
    
    // Settings elements
    this.autoScanEnabled = document.getElementById('autoScanEnabled');
    this.notificationsEnabled = document.getElementById('notificationsEnabled');
    this.saveHistoryEnabled = document.getElementById('saveHistoryEnabled');
    this.timeoutSelect = document.getElementById('timeoutSelect');
  }

  attachEventListeners() {
    // Scan actions
    this.scanBtn.addEventListener('click', () => this.handleScan());
    this.scanCurrentBtn.addEventListener('click', () => this.handleScanCurrent());
    this.pasteBtn.addEventListener('click', () => this.handlePaste());
    this.rescanBtn.addEventListener('click', () => this.handleRescan());
    this.retryBtn.addEventListener('click', () => this.handleRetry());
    
    // Navigation
    this.historyBtn.addEventListener('click', () => this.showHistorySection());
    this.settingsBtn.addEventListener('click', () => this.showSettingsSection());
    
    // Settings
    this.autoScanEnabled.addEventListener('change', () => this.saveSettings());
    this.notificationsEnabled.addEventListener('change', () => this.saveSettings());
    this.saveHistoryEnabled.addEventListener('change', () => this.saveSettings());
    this.timeoutSelect.addEventListener('change', () => this.saveSettings());
    
    // Other actions
    this.toggleEngines.addEventListener('click', () => this.toggleEnginesList());
    this.exportBtn.addEventListener('click', () => this.exportResults());
    this.shareBtn.addEventListener('click', () => this.shareResults());
    this.clearHistoryBtn.addEventListener('click', () => this.clearHistory());
    
    // Input handling
    this.urlInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.handleScan();
      }
    });
    
    this.urlInput.addEventListener('input', () => {
      this.validateURL();
    });
  }

  validateURL() {
    const url = this.urlInput.value.trim();
    const isValid = this.isValidURL(url);
    
    this.scanBtn.disabled = !isValid || !url;
    
    if (url && !isValid) {
      this.urlInput.style.borderColor = '#f44336';
    } else {
      this.urlInput.style.borderColor = '';
    }
  }

  isValidURL(string) {
    try {
      const url = new URL(string.startsWith('http') ? string : 'https://' + string);
      return ['http:', 'https:'].includes(url.protocol);
    } catch {
      return false;
    }
  }

  normalizeURL(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return 'https://' + url;
    }
    return url;
  }

  async handleScan() {
    const url = this.urlInput.value.trim();
    if (!url) return;
    
    const normalizedURL = this.normalizeURL(url);
    if (!this.isValidURL(normalizedURL)) {
      this.showError('Please enter a valid URL');
      return;
    }
    
    await this.performScan(normalizedURL);
  }

  async handleScanCurrent() {
    // Simulate getting current page URL
    const currentURL = window.location.href;
    this.urlInput.value = currentURL;
    await this.performScan(currentURL);
  }

  async handlePaste() {
    try {
      const text = await navigator.clipboard.readText();
      if (this.isValidURL(this.normalizeURL(text))) {
        this.urlInput.value = text;
        this.validateURL();
      } else {
        this.showError('Clipboard does not contain a valid URL');
      }
    } catch (err) {
      // Fallback for browsers that don't support clipboard API
      this.urlInput.focus();
      this.urlInput.select();
    }
  }

  async handleRescan() {
    if (this.currentScan) {
      await this.performScan(this.currentScan.url);
    }
  }

  async handleRetry() {
    this.hideError();
    if (this.urlInput.value.trim()) {
      await this.handleScan();
    }
  }

  async performScan(url) {
    try {
      this.hideAllSections();
      this.showLoadingSection();
      
      // Create scan object
      this.currentScan = {
        url: url,
        timestamp: new Date(),
        status: 'scanning'
      };
      
      // Simulate scanning process
      const result = await this.simulateScan(url);
      
      // Update current scan with results
      this.currentScan = { ...this.currentScan, ...result };
      
      // Save to history if enabled
      if (this.settings.saveHistoryEnabled) {
        this.addToHistory(this.currentScan);
      }
      
      // Show results
      this.hideLoadingSection();
      this.displayResults(result);
      
    } catch (error) {
      console.error('Scan failed:', error);
      this.hideLoadingSection();
      this.showError('Scan failed. Please try again.');
    }
  }

  async simulateScan(url) {
    const totalEngines = SECURITY_ENGINES.length;
    let completedEngines = 0;
    
    // Update loading status
    this.loadingStatus.textContent = 'Checking URL format...';
    await this.delay(500);
    
    this.loadingStatus.textContent = 'Querying security databases...';
    await this.delay(800);
    
    // Simulate engine scanning
    const engineResults = [];
    
    for (const engine of SECURITY_ENGINES) {
      await this.delay(100 + Math.random() * 200);
      
      const result = this.simulateEngineResult(url, engine);
      engineResults.push(result);
      
      completedEngines++;
      const progress = (completedEngines / totalEngines) * 100;
      
      this.progressFill.style.width = `${progress}%`;
      this.enginesCount.textContent = `${completedEngines}/${totalEngines} engines completed`;
      this.loadingStatus.textContent = `Scanning with ${engine.name}...`;
    }
    
    this.loadingStatus.textContent = 'Analyzing results...';
    await this.delay(500);
    
    // Calculate final results
    return this.calculateScanResults(url, engineResults);
  }

  simulateEngineResult(url, engine) {
    const urlLower = url.toLowerCase();
    
    // Check for malicious patterns
    const hasMaliciousPattern = MALICIOUS_PATTERNS.some(pattern => 
      urlLower.includes(pattern)
    );
    
    // Different engines have different detection rates
    let detectionChance = 0;
    
    if (hasMaliciousPattern) {
      // High chance of detection for obviously malicious URLs
      detectionChance = 0.7 + (engine.weight / 100);
    } else {
      // Low chance of false positives for clean URLs
      detectionChance = 0.01 + (Math.random() * 0.05);
    }
    
    const isDetected = Math.random() < detectionChance;
    
    let verdict = 'clean';
    let category = null;
    
    if (isDetected) {
      if (urlLower.includes('phishing') || urlLower.includes('fake')) {
        verdict = 'phishing';
        category = 'phishing';
      } else if (urlLower.includes('malware') || urlLower.includes('virus')) {
        verdict = 'malware';
        category = 'malware';
      } else {
        verdict = 'suspicious';
        category = 'suspicious';
      }
    }
    
    return {
      engine: engine.name,
      verdict: verdict,
      category: category,
      weight: engine.weight
    };
  }

  calculateScanResults(url, engineResults) {
    const totalEngines = engineResults.length;
    const detectedEngines = engineResults.filter(r => r.verdict !== 'clean');
    const detectedCount = detectedEngines.length;
    
    // Calculate threat score
    let threatScore = 0;
    if (detectedCount > 0) {
      const weightedScore = detectedEngines.reduce((sum, result) => {
        return sum + result.weight;
      }, 0);
      
      const maxPossibleWeight = SECURITY_ENGINES.reduce((sum, engine) => {
        return sum + engine.weight;
      }, 0);
      
      threatScore = Math.min(95, (weightedScore / maxPossibleWeight) * 100);
    } else {
      threatScore = Math.floor(Math.random() * 5); // 0-4% for clean URLs
    }
    
    // Determine overall status
    let status = 'safe';
    if (threatScore >= 70) {
      status = 'unsafe';
    } else if (threatScore >= 30) {
      status = 'suspicious';
    }
    
    // Count threat categories
    const categories = {};
    detectedEngines.forEach(result => {
      if (result.category) {
        categories[result.category] = (categories[result.category] || 0) + 1;
      }
    });
    
    return {
      url: url,
      status: status,
      threatScore: Math.round(threatScore),
      detectedCount: detectedCount,
      totalEngines: totalEngines,
      engineResults: engineResults,
      categories: categories,
      scanTime: new Date()
    };
  }

  displayResults(result) {
    this.hideAllSections();
    
    // Update status indicator
    this.updateStatusIndicator(result);
    
    // Update threat score
    this.updateThreatScore(result);
    
    // Update detection summary
    this.updateDetectionSummary(result);
    
    // Update threat categories
    this.updateThreatCategories(result);
    
    // Update engine results
    this.updateEngineResults(result);
    
    this.resultsSection.style.display = 'block';
  }

  updateStatusIndicator(result) {
    const { status, threatScore } = result;
    
    // Update icon and colors
    this.statusIcon.className = `status-icon ${status}`;
    
    let icon, title, description;
    
    switch (status) {
      case 'safe':
        icon = 'fa-shield-alt';
        title = 'Safe';
        description = 'This URL appears to be safe';
        break;
      case 'suspicious':
        icon = 'fa-exclamation-triangle';
        title = 'Suspicious';
        description = 'This URL may pose some risks';
        break;
      case 'unsafe':
        icon = 'fa-times-circle';
        title = 'Unsafe';
        description = 'This URL is likely malicious';
        break;
    }
    
    this.statusIcon.querySelector('i').className = `fas ${icon}`;
    this.statusTitle.textContent = title;
    this.statusDescription.textContent = description;
  }

  updateThreatScore(result) {
    const { status, threatScore } = result;
    
    this.scoreNumber.textContent = threatScore;
    this.scoreCircle.className = `score-circle ${status}`;
    
    // Animate score
    setTimeout(() => {
      this.animateNumber(this.scoreNumber, 0, threatScore, 1000);
    }, 300);
  }

  updateDetectionSummary(result) {
    const { detectedCount, totalEngines } = result;
    
    this.detectedCount.textContent = detectedCount;
    this.totalEngines.textContent = totalEngines;
    
    const detectionPercentage = (detectedCount / totalEngines) * 100;
    setTimeout(() => {
      this.detectionFill.style.width = `${detectionPercentage}%`;
    }, 500);
  }

  updateThreatCategories(result) {
    const { categories } = result;
    
    this.threatCategories.innerHTML = '';
    
    if (Object.keys(categories).length === 0) {
      this.threatCategories.style.display = 'none';
      return;
    }
    
    this.threatCategories.style.display = 'block';
    
    Object.entries(categories).forEach(([categoryKey, count]) => {
      const category = THREAT_CATEGORIES[categoryKey];
      if (category) {
        const categoryEl = this.createThreatCategoryElement(category, count);
        this.threatCategories.appendChild(categoryEl);
      }
    });
  }

  createThreatCategoryElement(category, count) {
    const div = document.createElement('div');
    div.className = `threat-category ${category.name.toLowerCase()}`;
    
    div.innerHTML = `
      <div class="category-info">
        <div class="category-icon" style="background-color: ${category.color}">
          <i class="fas fa-exclamation"></i>
        </div>
        <span class="category-name">${category.name}</span>
      </div>
      <span class="category-count">${count}</span>
    `;
    
    return div;
  }

  updateEngineResults(result) {
    const { engineResults } = result;
    
    this.enginesList.innerHTML = '';
    
    engineResults.forEach(engineResult => {
      const engineEl = this.createEngineResultElement(engineResult);
      this.enginesList.appendChild(engineEl);
    });
  }

  createEngineResultElement(engineResult) {
    const div = document.createElement('div');
    div.className = 'engine-item';
    
    const resultClass = engineResult.verdict === 'clean' ? 'clean' : engineResult.verdict;
    const resultText = engineResult.verdict === 'clean' ? 'Clean' : 
                      engineResult.verdict.charAt(0).toUpperCase() + engineResult.verdict.slice(1);
    
    div.innerHTML = `
      <span class="engine-name">${engineResult.engine}</span>
      <span class="engine-result ${resultClass}">${resultText}</span>
    `;
    
    return div;
  }

  toggleEnginesList() {
    const list = this.enginesList;
    const toggle = this.toggleEngines;
    const icon = toggle.querySelector('i');
    const text = toggle.querySelector('span');
    
    if (list.style.maxHeight === '0px' || !list.style.maxHeight) {
      list.style.maxHeight = '200px';
      text.textContent = 'Show Less';
      icon.style.transform = 'rotate(180deg)';
    } else {
      list.style.maxHeight = '0px';
      text.textContent = 'Show All';
      icon.style.transform = 'rotate(0deg)';
    }
  }

  showHistorySection() {
    this.hideAllSections();
    this.updateHistoryDisplay();
    this.historySection.style.display = 'block';
  }

  showSettingsSection() {
    this.hideAllSections();
    this.settingsSection.style.display = 'block';
  }

  showLoadingSection() {
    this.loadingSection.style.display = 'block';
    this.progressFill.style.width = '0%';
    this.enginesCount.textContent = '0/87 engines completed';
  }

  hideLoadingSection() {
    this.loadingSection.style.display = 'none';
  }

  showError(message) {
    this.hideAllSections();
    this.errorMessage.textContent = message;
    this.errorSection.style.display = 'block';
  }

  hideError() {
    this.errorSection.style.display = 'none';
  }

  hideAllSections() {
    this.resultsSection.style.display = 'none';
    this.loadingSection.style.display = 'none';
    this.historySection.style.display = 'none';
    this.settingsSection.style.display = 'none';
    this.errorSection.style.display = 'none';
  }

  updateHistoryDisplay() {
    this.historyList.innerHTML = '';
    
    if (this.scanHistory.length === 0) {
      this.historyList.innerHTML = `
        <div style="text-align: center; padding: 32px; color: var(--color-text-secondary);">
          <i class="fas fa-history" style="font-size: 48px; margin-bottom: 16px; opacity: 0.3;"></i>
          <p>No scan history yet</p>
        </div>
      `;
      return;
    }
    
    this.scanHistory.slice().reverse().forEach(scan => {
      const historyEl = this.createHistoryElement(scan);
      this.historyList.appendChild(historyEl);
    });
  }

  createHistoryElement(scan) {
    const div = document.createElement('div');
    div.className = 'history-item';
    
    const statusColor = {
      safe: 'var(--vt-safe)',
      suspicious: 'var(--vt-suspicious)',
      unsafe: 'var(--vt-unsafe)'
    }[scan.status] || 'var(--color-text-secondary)';
    
    const timeAgo = this.getTimeAgo(scan.timestamp || scan.scanTime);
    
    div.innerHTML = `
      <div class="history-info">
        <div class="history-url" title="${scan.url}">${scan.url}</div>
        <div class="history-status">${timeAgo}</div>
      </div>
      <div class="history-result">
        <span style="color: ${statusColor}; font-weight: 500;">${scan.status?.toUpperCase() || 'UNKNOWN'}</span>
        <span style="font-size: 11px; color: var(--color-text-secondary);">${scan.detectedCount || 0}/${scan.totalEngines || 87}</span>
      </div>
    `;
    
    div.addEventListener('click', () => {
      this.urlInput.value = scan.url;
      this.hideAllSections();
      this.displayResults(scan);
    });
    
    return div;
  }

  addToHistory(scan) {
    // Remove duplicate URLs
    this.scanHistory = this.scanHistory.filter(s => s.url !== scan.url);
    
    // Add new scan to beginning
    this.scanHistory.unshift(scan);
    
    // Keep only last 50 scans
    this.scanHistory = this.scanHistory.slice(0, 50);
  }

  clearHistory() {
    this.scanHistory = [];
    this.updateHistoryDisplay();
  }

  loadSettings() {
    this.autoScanEnabled.checked = this.settings.autoScanEnabled;
    this.notificationsEnabled.checked = this.settings.notificationsEnabled;
    this.saveHistoryEnabled.checked = this.settings.saveHistoryEnabled;
    this.timeoutSelect.value = this.settings.timeout;
  }

  saveSettings() {
    this.settings = {
      autoScanEnabled: this.autoScanEnabled.checked,
      notificationsEnabled: this.notificationsEnabled.checked,
      saveHistoryEnabled: this.saveHistoryEnabled.checked,
      timeout: parseInt(this.timeoutSelect.value)
    };
  }

  exportResults() {
    if (!this.currentScan) return;
    
    const reportData = {
      url: this.currentScan.url,
      scanTime: this.currentScan.scanTime,
      status: this.currentScan.status,
      threatScore: this.currentScan.threatScore,
      detectedCount: this.currentScan.detectedCount,
      totalEngines: this.currentScan.totalEngines,
      engineResults: this.currentScan.engineResults
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `url-scan-report-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async shareResults() {
    if (!this.currentScan) return;
    
    const shareText = `URL Scan Results:\n\nURL: ${this.currentScan.url}\nStatus: ${this.currentScan.status.toUpperCase()}\nThreat Score: ${this.currentScan.threatScore}%\nDetected by: ${this.currentScan.detectedCount}/${this.currentScan.totalEngines} engines`;
    
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'URL Scan Results',
          text: shareText
        });
      } catch (err) {
        console.log('Share cancelled');
      }
    } else {
      // Fallback to clipboard
      try {
        await navigator.clipboard.writeText(shareText);
        this.showNotification('Results copied to clipboard!');
      } catch (err) {
        console.error('Could not copy to clipboard');
      }
    }
  }

  showNotification(message) {
    if (!this.settings.notificationsEnabled) return;
    
    // Simple notification implementation
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: var(--vt-primary);
      color: white;
      padding: 12px 16px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2);
      z-index: 10000;
      animation: slideInRight 0.3s ease;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.style.animation = 'slideOutRight 0.3s ease';
      setTimeout(() => {
        document.body.removeChild(notification);
      }, 300);
    }, 3000);
  }

  animateNumber(element, start, end, duration) {
    const startTime = performance.now();
    
    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      const current = Math.floor(start + (end - start) * progress);
      element.textContent = current;
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    
    requestAnimationFrame(animate);
  }

  getTimeAgo(date) {
    const now = new Date();
    const scanDate = new Date(date);
    const diffMs = now - scanDate;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Initialize the application
const scanner = new URLScanner();

// Add some CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideInRight {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
  
  @keyframes slideOutRight {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(100%);
      opacity: 0;
    }
  }
`;
document.head.appendChild(style);

console.log('URLShield Scanner initialized successfully!');