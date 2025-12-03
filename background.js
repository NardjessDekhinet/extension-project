// Background Service Worker for URL Security Scanner Extension

// Extension installation handler
chrome.runtime.onInstalled.addListener((details) => {
    console.log('URL Security Scanner installed');
    
    // Initialize storage
    chrome.storage.local.set({
        scanHistory: [],
        settings: {
            enableNotifications: true,
            enableSounds: true,
            autoScanEnabled: false
        }
    });

    // Create context menu
    chrome.contextMenus.create({
        id: 'scanUrl',
        title: 'Scan URL for Security Threats',
        contexts: ['link'],
        documentUrlPatterns: ['http://*/*', 'https://*/*']
    });

    // Set default badge
    chrome.action.setBadgeText({ text: '' });
    chrome.action.setBadgeBackgroundColor({ color: '#1a73e8' });
});

// Context menu click handler
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'scanUrl' && info.linkUrl) {
        // Send URL to popup for scanning
        chrome.runtime.sendMessage({
            action: 'contextMenuScan',
            url: info.linkUrl
        });
        
        // Open popup
        chrome.action.openPopup();
    }
});

// Message handler for communication with popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    switch (request.action) {
        case 'performScan':
            handleSecurityScan(request.url).then(sendResponse);
            return true; // Keep message channel open for async response
            
        case 'updateBadge':
            updateExtensionBadge(request.status, request.score);
            break;
            
        case 'showNotification':
            if (request.critical) {
                showSecurityNotification(request.title, request.message, request.url);
            }
            break;
            
        case 'checkApiStatus':
            checkApiAvailability().then(sendResponse);
            return true;
            
        default:
            console.log('Unknown action:', request.action);
    }
});

// Security scan handler
async function handleSecurityScan(url) {
    try {
        console.log('Performing security scan for:', url);
        
        const scanResult = {
            url: url,
            timestamp: new Date().toISOString(),
            status: 'scanning'
        };

        // Check with Google Safe Browsing API
        const safeBrowsingResult = await checkGoogleSafeBrowsing(url);
        
        // Combine with local analysis
        const localAnalysis = analyzeUrlLocally(url);
        
        // Generate final result
        const finalResult = {
            ...scanResult,
            status: determineOverallStatus(safeBrowsingResult, localAnalysis),
            riskScore: calculateRiskScore(safeBrowsingResult, localAnalysis),
            apiResults: safeBrowsingResult,
            localAnalysis: localAnalysis,
            engines: generateEngineResults(url, safeBrowsingResult, localAnalysis)
        };

        // Update badge based on result
        updateExtensionBadge(finalResult.status, finalResult.riskScore);
        
        // Show notification for critical threats
        if (finalResult.status === 'critical' || finalResult.riskScore >= 80) {
            showSecurityNotification(
                'Critical Security Threat Detected',
                `The URL ${url} contains severe security threats.`,
                url
            );
        }

        return finalResult;
        
    } catch (error) {
        console.error('Scan error:', error);
        return {
            url: url,
            timestamp: new Date().toISOString(),
            status: 'error',
            error: error.message
        };
    }
}

// Google Safe Browsing API integration
async function checkGoogleSafeBrowsing(url) {
    try {
        // Note: In production, you would need a valid API key
        // This is a simulation of the API response structure
        
        const apiKey = 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY'; // Replace with actual key
        const apiUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
        
        const requestBody = {
            client: {
                clientId: "url-security-scanner",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                threatTypes: [
                    "MALWARE",
                    "SOCIAL_ENGINEERING", 
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: url }]
            }
        };

        // Simulate API response for demo
        return simulateGoogleSafeBrowsingResponse(url);
        
        /* Uncomment for actual API usage:
        const response = await fetch(`${apiUrl}?key=${apiKey}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }
        
        const data = await response.json();
        return processSafeBrowsingResponse(data);
        */
        
    } catch (error) {
        console.error('Google Safe Browsing API error:', error);
        return { status: 'error', threats: [], error: error.message };
    }
}

// Simulate Google Safe Browsing response for demo
function simulateGoogleSafeBrowsingResponse(url) {
    const domain = new URL(url).hostname.toLowerCase();
    
    // Simulate known threats
    const knownThreats = [
        'malware', 'phishing', 'scam', 'virus', 'trojan', 
        'dangerous', 'harmful', 'suspicious', 'fake'
    ];
    
    const hasKnownThreat = knownThreats.some(threat => domain.includes(threat));
    
    if (hasKnownThreat) {
        return {
            status: 'threat_detected',
            threats: ['MALWARE', 'SOCIAL_ENGINEERING'],
            confidence: 0.95
        };
    }
    
    // Random chance for other URLs to simulate false positives/edge cases
    const randomFactor = Math.random();
    if (randomFactor < 0.05) { // 5% chance of detecting threat
        return {
            status: 'suspicious',
            threats: ['POTENTIALLY_HARMFUL_APPLICATION'],
            confidence: 0.6
        };
    }
    
    return {
        status: 'safe',
        threats: [],
        confidence: 0.99
    };
}

// Local URL analysis
function analyzeUrlLocally(url) {
    let riskScore = 0;
    const detectedIssues = [];
    
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase();
        const path = urlObj.pathname.toLowerCase();
        
        // Check protocol security
        if (urlObj.protocol === 'http:') {
            riskScore += 15;
            detectedIssues.push('Non-HTTPS connection');
        }
        
        // Check for suspicious domains
        const suspiciousPatterns = [
            /(?:phishing|scam|fake|fraud)/i,
            /(?:malware|virus|trojan)/i,
            /(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/,
            /(?:\.tk|\.ml|\.ga|\.cf|\.pw)$/i
        ];
        
        suspiciousPatterns.forEach(pattern => {
            if (pattern.test(domain)) {
                riskScore += 25;
                detectedIssues.push('Suspicious domain pattern');
            }
        });
        
        // Check URL length (very long URLs can be suspicious)
        if (url.length > 200) {
            riskScore += 10;
            detectedIssues.push('Unusually long URL');
        }
        
        // Check for URL shorteners
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'short.link', 'goo.gl'];
        if (shorteners.some(shortener => domain.includes(shortener))) {
            riskScore += 20;
            detectedIssues.push('URL shortener detected');
        }
        
        // Check for suspicious path patterns
        const suspiciousPaths = [
            /\/(?:admin|login|secure|bank|paypal|amazon|apple|microsoft)/i,
            /\/(?:update|verify|confirm|account|billing)/i
        ];
        
        if (domain !== 'paypal.com' && domain !== 'amazon.com') { // Legitimate domains
            suspiciousPaths.forEach(pattern => {
                if (pattern.test(path)) {
                    riskScore += 15;
                    detectedIssues.push('Suspicious path detected');
                }
            });
        }
        
        return {
            riskScore: Math.min(riskScore, 100),
            issues: detectedIssues,
            analysis: {
                protocol: urlObj.protocol,
                domain: domain,
                urlLength: url.length
            }
        };
        
    } catch (error) {
        console.error('Local analysis error:', error);
        return {
            riskScore: 50,
            issues: ['Invalid URL format'],
            analysis: null
        };
    }
}

// Determine overall status
function determineOverallStatus(apiResult, localResult) {
    const apiThreatLevel = getApiThreatLevel(apiResult);
    const localThreatLevel = getLocalThreatLevel(localResult.riskScore);
    
    const maxThreatLevel = Math.max(apiThreatLevel, localThreatLevel);
    
    if (maxThreatLevel >= 4) return 'critical';
    if (maxThreatLevel >= 3) return 'dangerous';
    if (maxThreatLevel >= 2) return 'suspicious';
    return 'safe';
}

function getApiThreatLevel(apiResult) {
    if (apiResult.status === 'threat_detected') return 4;
    if (apiResult.status === 'suspicious') return 2;
    return 0;
}

function getLocalThreatLevel(riskScore) {
    if (riskScore >= 80) return 4;
    if (riskScore >= 60) return 3;
    if (riskScore >= 30) return 2;
    return 0;
}

// Calculate combined risk score
function calculateRiskScore(apiResult, localResult) {
    let score = localResult.riskScore;
    
    if (apiResult.status === 'threat_detected') {
        score = Math.max(score, 85);
    } else if (apiResult.status === 'suspicious') {
        score = Math.max(score, 45);
    }
    
    return Math.min(score, 100);
}

// Generate engine results simulation
function generateEngineResults(url, apiResult, localResult) {
    const engines = [
        'Google Safe Browsing', 'Microsoft Defender', 'Kaspersky', 'Norton',
        'Bitdefender', 'McAfee', 'Trend Micro', 'ESET', 'Avast', 'AVG',
        'Symantec', 'F-Secure', 'Sophos', 'Malwarebytes', 'Panda'
    ];
    
    const overallRisk = calculateRiskScore(apiResult, localResult) / 100;
    
    return engines.map(engine => {
        const randomFactor = (Math.random() - 0.5) * 0.4;
        const detectionProbability = Math.max(0, Math.min(1, overallRisk + randomFactor));
        
        let result;
        if (Math.random() < detectionProbability * 0.8) {
            result = 'malicious';
        } else if (Math.random() < detectionProbability * 0.95) {
            result = 'suspicious';   
        } else if (Math.random() < 0.98) {
            result = 'clean';
        } else {
            result = 'timeout';
        }
        
        return { name: engine, result: result };
    });
}

// Update extension badge
function updateExtensionBadge(status, score) {
    let badgeText = '';
    let badgeColor = '#1a73e8';
    
    switch (status) {
        case 'critical':
            badgeText = '!';
            badgeColor = '#dc3545';
            break;
        case 'dangerous':
            badgeText = '⚠';
            badgeColor = '#fd7e14';
            break;
        case 'suspicious':
            badgeText = '?';
            badgeColor = '#ffc107';
            break;
        case 'safe':
            badgeText = '✓';
            badgeColor = '#28a745';
            break;
    }
    
    chrome.action.setBadgeText({ text: badgeText });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });
}

// Show security notification
function showSecurityNotification(title, message, url) {
    chrome.storage.local.get(['settings'], (result) => {
        const settings = result.settings || {};
        
        if (settings.enableNotifications !== false) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: title,
                message: message,
                priority: 2
            }, (notificationId) => {
                // Auto-clear notification after 10 seconds
                setTimeout(() => {
                    chrome.notifications.clear(notificationId);
                }, 10000);
            });
        }
    });
}

// Check API availability
async function checkApiAvailability() {
    try {
        // Test Google Safe Browsing API availability
        const testUrl = 'https://safebrowsing.googleapis.com/v4/';
        const response = await fetch(testUrl, { method: 'HEAD' });
        
        return {
            googleSafeBrowsing: response.ok,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        return {
            googleSafeBrowsing: false,
            error: error.message,
            timestamp: new Date().toISOString()
        };
    }
}

// Tab update listener for automatic scanning (if enabled)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        chrome.storage.local.get(['settings'], (result) => {
            const settings = result.settings || {};
            
            if (settings.autoScanEnabled && 
                !tab.url.startsWith('chrome://') && 
                !tab.url.startsWith('moz-extension://') &&
                !tab.url.startsWith('about:')) {
                
                // Perform background scan for auto-scan feature
                handleSecurityScan(tab.url).then(result => {
                    if (result.status === 'critical' || result.riskScore >= 80) {
                        // Show warning for dangerous sites
                        chrome.tabs.sendMessage(tabId, {
                            action: 'showSecurityWarning',
                            scanResult: result
                        });
                    }
                });
            }
        });
    }
});

// Alarm listener for periodic tasks
chrome.alarms.onAlarm.addListener((alarm) => {
    switch (alarm.name) {
        case 'cleanupHistory':
            // Clean old scan history
            chrome.storage.local.get(['scanHistory'], (result) => {
                const history = result.scanHistory || [];
                const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
                
                const cleanHistory = history.filter(item => {
                    return new Date(item.scanTime).getTime() > oneWeekAgo;
                });
                
                chrome.storage.local.set({ scanHistory: cleanHistory });
            });
            break;
    }
});

// Set up periodic cleanup (once per day)
chrome.runtime.onStartup.addListener(() => {
    chrome.alarms.create('cleanupHistory', { 
        delayInMinutes: 1,
        periodInMinutes: 24 * 60 // 24 hours
    });
});

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
    // This will open the popup automatically due to default_popup in manifest
    console.log('Extension icon clicked');
});

console.log('URL Security Scanner background service worker loaded');
