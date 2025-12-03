// Content Script for URL Security Scanner Extension

// Global variables
let securityWarningOverlay = null;
let scannerInitialized = false;
let currentPageUrl = window.location.href;

// Initialize content script
function initializeContentScript() {
    if (scannerInitialized) return;
    
    console.log('URL Security Scanner content script initialized');
    scannerInitialized = true;
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener(handleMessage);
    
    // Monitor for dangerous links
    monitorPageLinks();
    
    // Check if current page is flagged
    checkCurrentPage();
    
    // Set up page change detection for SPAs
    setupPageChangeDetection();
}

// Handle messages from background script or popup
function handleMessage(message, sender, sendResponse) {
    switch (message.action) {
        case 'showSecurityWarning':
            showSecurityWarning(message.scanResult);
            break;
            
        case 'hideSecurityWarning':
            hideSecurityWarning();
            break;
            
        case 'scanSelectedLink':
            scanSelectedLink();
            break;
            
        case 'getCurrentPageUrl':
            sendResponse({ url: window.location.href });
            break;
            
        case 'injectWarningBanner':
            injectWarningBanner(message.warningData);
            break;
            
        default:
            console.log('Unknown message action:', message.action);
    }
}

// Monitor links on the page for potential threats
function monitorPageLinks() {
    // Add click listeners to all links
    document.addEventListener('click', (event) => {
        const link = event.target.closest('a');
        if (link && link.href) {
            handleLinkClick(link, event);
        }
    });
    
    // Monitor for dynamically added links
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    const links = node.querySelectorAll ? node.querySelectorAll('a[href]') : [];
                    links.forEach(link => {
                        if (isLinkSuspicious(link.href)) {
                            highlightSuspiciousLink(link);
                        }
                    });
                }
            });
        });
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Check existing links
    const existingLinks = document.querySelectorAll('a[href]');
    existingLinks.forEach(link => {
        if (isLinkSuspicious(link.href)) {
            highlightSuspiciousLink(link);
        }
    });
}

// Handle link clicks with security checking
function handleLinkClick(link, event) {
    const href = link.href;
    
    // Quick local check for obviously dangerous links
    if (isLinkObviouslyDangerous(href)) {
        event.preventDefault();
        showLinkWarningDialog(href, link);
        return;
    }
    
    // For suspicious links, add a slight delay to allow user to cancel
    if (isLinkSuspicious(href)) {
        // Could implement a small delay here for real-time scanning
        // For now, just log the suspicious click
        console.log('Suspicious link clicked:', href);
    }
}

// Check if a link is obviously dangerous
function isLinkObviouslyDangerous(url) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase();
        
        // Check for obvious phishing/malware patterns
        const dangerousPatterns = [
            /(?:phishing|scam|fake|fraud|malware|virus|trojan)/i,
            /(?:secure-?(?:paypal|amazon|apple|microsoft|google))/i,
            /(?:(?:paypal|amazon|apple|microsoft|google)-?(?:secure|verify|update))/i
        ];
        
        return dangerousPatterns.some(pattern => pattern.test(domain));
        
    } catch (error) {
        // Invalid URL might be dangerous
        return true;
    }
}

// Check if a link is suspicious (less obvious but worth flagging)
function isLinkSuspicious(url) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase();
        
        // Check for suspicious TLDs
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.pw'];
        if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
            return true;
        }
        
        // Check for IP addresses instead of domains
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
            return true;
        }
        
        // Check for URL shorteners
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'short.link', 'goo.gl'];
        if (shorteners.some(shortener => domain.includes(shortener))) {
            return true;
        }
        
        // Check for very long URLs (often used in phishing)
        if (url.length > 150) {
            return true;
        }
        
        return false;
        
    } catch (error) {
        return true; // Invalid URLs are suspicious
    }
}

// Highlight suspicious links on the page
function highlightSuspiciousLink(link) {
    if (link.dataset.securityScanned) return; // Already processed
    
    link.dataset.securityScanned = 'true';
    link.style.outline = '2px dashed #ffc107';
    link.style.outlineOffset = '2px';
    
    // Add tooltip
    link.title = '⚠️ This link may be suspicious - Click with caution';
    
    // Add warning icon
    const warningIcon = document.createElement('span');
    warningIcon.innerHTML = ' ⚠️';
    warningIcon.style.fontSize = '12px';
    warningIcon.style.color = '#ffc107';
    warningIcon.style.marginLeft = '4px';
    link.appendChild(warningIcon);
}

// Show warning dialog for dangerous links
function showLinkWarningDialog(href, linkElement) {
    const dialog = document.createElement('div');
    dialog.id = 'url-security-warning-dialog';
    dialog.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        border: 2px solid #dc3545;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        z-index: 10000;
        max-width: 400px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    dialog.innerHTML = `
        <div style="text-align: center; margin-bottom: 15px;">
            <div style="font-size: 48px; color: #dc3545; margin-bottom: 10px;">🛑</div>
            <h3 style="margin: 0; color: #dc3545; font-size: 18px;">Dangerous Link Detected</h3>
        </div>
        <p style="margin: 10px 0; font-size: 14px; color: #333;">
            This link appears to be dangerous and may contain malware or be a phishing attempt:
        </p>
        <div style="background: #f8f9fa; padding: 10px; border-radius: 4px; margin: 10px 0; word-break: break-all; font-size: 12px; color: #666;">
            ${href}
        </div>
        <div style="display: flex; gap: 10px; justify-content: center; margin-top: 20px;">
            <button id="proceed-anyway" style="background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 14px;">
                Proceed Anyway
            </button>
            <button id="cancel-navigation" style="background: #28a745; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 14px;">
                Stay Safe
            </button>
        </div>
    `;
    
    // Add backdrop
    const backdrop = document.createElement('div');
    backdrop.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.5);
        z-index: 9999;
    `;
    
    document.body.appendChild(backdrop);
    document.body.appendChild(dialog);
    
    // Handle button clicks
    dialog.querySelector('#proceed-anyway').addEventListener('click', () => {
        document.body.removeChild(backdrop);
        document.body.removeChild(dialog);
        window.open(href, '_blank');
    });
    
    dialog.querySelector('#cancel-navigation').addEventListener('click', () => {
        document.body.removeChild(backdrop);
        document.body.removeChild(dialog);
    });
    
    // Close on backdrop click
    backdrop.addEventListener('click', () => {
        document.body.removeChild(backdrop);
        document.body.removeChild(dialog);
    });
}

// Show security warning overlay for the current page
function showSecurityWarning(scanResult) {
    if (securityWarningOverlay) {
        hideSecurityWarning();
    }
    
    const overlay = document.createElement('div');
    overlay.id = 'url-security-warning-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(220, 53, 69, 0.95);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    const warningContent = document.createElement('div');
    warningContent.style.cssText = `
        background: white;
        padding: 40px;
        border-radius: 12px;
        text-align: center;
        max-width: 500px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    `;
    
    const statusColor = getStatusColor(scanResult.status);
    const statusText = getStatusText(scanResult.status);
    
    warningContent.innerHTML = `
        <div style="font-size: 64px; margin-bottom: 20px;">🛑</div>
        <h1 style="color: ${statusColor}; margin: 0 0 15px 0; font-size: 24px;">
            ${statusText}
        </h1>
        <p style="font-size: 16px; margin: 15px 0; color: #333;">
            This website has been flagged as potentially dangerous by our security scanner.
        </p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; text-align: left;">
            <strong>Threat Score:</strong> ${scanResult.riskScore}%<br>
            <strong>Detected by:</strong> ${scanResult.detectedEngines || 0} security engines<br>
            <strong>URL:</strong> <span style="word-break: break-all; font-size: 14px;">${scanResult.url}</span>
        </div>
        <div style="display: flex; gap: 15px; justify-content: center; margin-top: 30px;">
            <button id="leave-site" style="background: #28a745; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 500;">
                Leave This Site
            </button>
            <button id="continue-site" style="background: #6c757d; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 500;">
                Continue Anyway
            </button>
        </div>
        <p style="font-size: 12px; color: #666; margin-top: 20px;">
            Powered by URL Security Scanner Extension
        </p>
    `;
    
    overlay.appendChild(warningContent);
    document.body.appendChild(overlay);
    securityWarningOverlay = overlay;
    
    // Handle button clicks
    warningContent.querySelector('#leave-site').addEventListener('click', () => {
        window.history.back();
    });
    
    warningContent.querySelector('#continue-site').addEventListener('click', () => {
        hideSecurityWarning();
    });
}

// Hide security warning overlay
function hideSecurityWarning() {
    if (securityWarningOverlay) {
        document.body.removeChild(securityWarningOverlay);
        securityWarningOverlay = null;
    }
}

// Inject warning banner at top of page
function injectWarningBanner(warningData) {
    // Remove existing banner if present
    const existingBanner = document.getElementById('url-security-banner');
    if (existingBanner) {
        existingBanner.remove();
    }
    
    const banner = document.createElement('div');
    banner.id = 'url-security-banner';
    banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        background: linear-gradient(135deg, #ffc107, #fd7e14);
        color: #333;
        padding: 12px 20px;
        text-align: center;
        z-index: 999998;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        font-weight: 500;
        border-bottom: 2px solid #e67e22;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    `;
    
    banner.innerHTML = `
        <span style="margin-right: 10px;">⚠️</span>
        ${warningData.message}
        <button style="background: #fff; border: 1px solid #ddd; padding: 4px 12px; margin-left: 15px; border-radius: 4px; cursor: pointer; font-size: 12px;" onclick="this.parentElement.style.display='none'">
            Dismiss
        </button>
    `;
    
    document.body.insertBefore(banner, document.body.firstChild);
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
        if (banner.parentElement) {
            banner.remove();
        }
    }, 10000);
}

// Check current page for security issues
function checkCurrentPage() {
    // Send current page URL to background for analysis
    chrome.runtime.sendMessage({
        action: 'checkCurrentPage',
        url: window.location.href
    }, (response) => {
        if (response && response.warning) {
            injectWarningBanner(response.warning);
        }
    });
}

// Set up page change detection for Single Page Applications
function setupPageChangeDetection() {
    let lastUrl = window.location.href;
    
    const observer = new MutationObserver(() => {
        const currentUrl = window.location.href;
        if (currentUrl !== lastUrl) {
            lastUrl = currentUrl;
            currentPageUrl = currentUrl;
            
            // Page changed, check new page
            setTimeout(() => {
                checkCurrentPage();
            }, 1000); // Delay to allow page to load
        }
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Also listen for popstate events (back/forward navigation)
    window.addEventListener('popstate', () => {
        setTimeout(() => {
            checkCurrentPage();
        }, 500);
    });
}

// Utility functions
function getStatusColor(status) {
    const colors = {
        'safe': '#28a745',
        'suspicious': '#ffc107',
        'dangerous': '#fd7e14',
        'critical': '#dc3545'
    };
    return colors[status] || '#6c757d';
}

function getStatusText(status) {
    const texts = {
        'safe': 'Safe Website',
        'suspicious': 'Suspicious Website',
        'dangerous': 'Dangerous Website',
        'critical': 'Critical Security Threat'
    };
    return texts[status] || 'Security Warning';
}

// Scan selected link (for context menu functionality)
function scanSelectedLink() {
    const selection = window.getSelection();
    const selectedText = selection.toString().trim();
    
    if (selectedText && (selectedText.startsWith('http://') || selectedText.startsWith('https://'))) {
        chrome.runtime.sendMessage({
            action: 'scanSelectedUrl',
            url: selectedText
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeContentScript);
} else {
    initializeContentScript();
}

// Also initialize immediately in case DOMContentLoaded has already fired
setTimeout(initializeContentScript, 100);