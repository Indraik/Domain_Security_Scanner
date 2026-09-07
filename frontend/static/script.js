/**
 * Domain Security Scanner - Frontend Controller
 * Handles asynchronous API calls, radar animations, results rendering, and remediation guides.
 */

// Global state for current report data
window.currentReportData = null;

// Built-in remediation playbooks
const FIX_GUIDES = {
    spf: {
        title: "SPF Policy Hardening Guide",
        steps: [
            "Log in to your DNS provider / registrar management console.",
            "Navigate to DNS Zone Editor or DNS Records configuration.",
            "Locate your existing TXT record starting with <code>v=spf1</code>.",
            "If your record ends in <code>~all</code> (SoftFail) or <code>?all</code>, replace it with <code>-all</code> (HardFail) after ensuring all legitimate outbound mail servers are included.",
            "Example: <code>v=spf1 include:_spf.google.com -all</code>",
            "Save changes and wait for DNS propagation (typically 15-60 minutes)."
        ]
    },
    dmarc: {
        title: "DMARC Enforcement Guide",
        steps: [
            "Open your DNS management console.",
            "Create a new TXT record with host / name: <code>_dmarc</code> (e.g. <code>_dmarc.yourdomain.com</code>).",
            "To begin blocking unauthorized spoofed emails, set policy to quarantine or reject.",
            "Example Reject Policy: <code>v=DMARC1; p=reject; rua=mailto:security-reports@yourdomain.com; pct=100</code>",
            "Monitor incoming aggregate reports (rua) to confirm that third-party sending services (SendGrid, Mailgun, etc.) pass authentication.",
            "Save and publish the record."
        ]
    },
    dkim: {
        title: "DKIM Deployment Guide",
        steps: [
            "Access your email provider administrator dashboard (Google Workspace, Microsoft 365, etc.).",
            "Navigate to Email Authentication / DKIM settings and select 'Generate new DKIM key'.",
            "Copy the provided DNS selector TXT record name (e.g. <code>google._domainkey</code>) and value.",
            "In your DNS manager, add the TXT record with the corresponding selector and public key value.",
            "Return to your email provider console and click 'Start Authentication' once the DNS record propagates."
        ]
    },
    dnssec: {
        title: "DNSSEC Activation Guide",
        steps: [
            "Log in to your domain registrar (Namecheap, GoDaddy, Cloudflare, Google Domains, etc.).",
            "Search for 'DNSSEC' or 'DNS Security Extensions' under Advanced DNS settings.",
            "Enable DNSSEC. If your registrar manages nameservers, activation is often 1-click.",
            "If using external DNS (e.g., Cloudflare with another registrar), copy the DS record (Key Tag, Algorithm, Digest Type, Digest) and paste it into your registrar's DS Record section."
        ]
    }
};

document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scanForm");
    const domainInput = document.getElementById("domainInput");
    const scanBtn = document.getElementById("scanBtn");

    // Initialize with embedded server data if present (SSR fallback)
    const embeddedDataEl = document.getElementById("report-data");
    if (embeddedDataEl && embeddedDataEl.textContent.trim()) {
        try {
            const data = JSON.parse(embeddedDataEl.textContent);
            if (data && data.domain) {
                renderScanResults(data);
            }
        } catch (e) {
            console.error("Failed to parse embedded data:", e);
        }
    }

    // Intercept form submission for smooth async scanning
    if (scanForm) {
        scanForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const domain = domainInput.value.trim();
            if (domain) {
                executeScan(domain);
            }
        });
    }
});

/**
 * Trigger a scan from a quick-test chip
 */
function scanSampleDomain(domain) {
    const domainInput = document.getElementById("domainInput");
    if (domainInput) {
        domainInput.value = domain;
        executeScan(domain);
    }
}

/**
 * Executes asynchronous domain security scan
 */
async function executeScan(domain) {
    const idleView = document.getElementById("idleView");
    const scanningView = document.getElementById("scanningView");
    const resultsView = document.getElementById("resultsView");
    const scanBtn = document.getElementById("scanBtn");
    const targetDisplay = document.getElementById("scanningTargetDisplay");
    const errorAlert = document.getElementById("errorAlert");

    // Clear previous errors
    if (errorAlert) {
        errorAlert.classList.add("d-none");
        errorAlert.textContent = "";
    }

    // Update UI states
    if (idleView) idleView.classList.add("d-none");
    if (resultsView) resultsView.classList.add("d-none");
    if (scanningView) scanningView.classList.remove("d-none");
    if (targetDisplay) targetDisplay.textContent = domain;
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Scanning...';
    }

    // Animate progress checklist items
    const stepInterval = runProgressAnimation();

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ domain: domain })
        });

        const result = await response.json();
        clearInterval(stepInterval);

        if (!response.ok || !result.success) {
            throw new Error(result.error || "Domain scan failed.");
        }

        // Render received results
        renderScanResults(result.data);

    } catch (err) {
        clearInterval(stepInterval);
        console.error("Scan error:", err);

        // Show error and return to idle view
        if (scanningView) scanningView.classList.add("d-none");
        if (idleView) idleView.classList.remove("d-none");
        if (errorAlert) {
            errorAlert.textContent = err.message || "An unexpected error occurred during scan.";
            errorAlert.classList.remove("d-none");
        }
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="bi bi-search me-1"></i> Scan Domain';
        }
    }
}

/**
 * Runs sequential step lighting animation during scan
 */
function runProgressAnimation() {
    const steps = [
        document.getElementById("step-dns"),
        document.getElementById("step-email"),
        document.getElementById("step-web"),
        document.getElementById("step-ports"),
        document.getElementById("step-score")
    ];

    // Reset step styles
    steps.forEach(s => {
        if (s) {
            s.className = "scan-step-item";
            const icon = s.querySelector(".scan-step-icon");
            if (icon) icon.className = "bi bi-circle scan-step-icon";
        }
    });

    let current = 0;
    const interval = setInterval(() => {
        if (current < steps.length) {
            const step = steps[current];
            if (step) {
                step.classList.add("active");
                const icon = step.querySelector(".scan-step-icon");
                if (icon) icon.className = "bi bi-arrow-repeat scan-step-icon spinner-border-sm";
            }
            if (current > 0) {
                const prev = steps[current - 1];
                if (prev) {
                    prev.classList.remove("active");
                    prev.classList.add("completed");
                    const prevIcon = prev.querySelector(".scan-step-icon");
                    if (prevIcon) prevIcon.className = "bi bi-check-circle-fill scan-step-icon";
                }
            }
            current++;
        }
    }, 450);

    return interval;
}

/**
 * Populates DOM elements with scan telemetry
 */
function renderScanResults(data) {
    window.currentReportData = data;

    const idleView = document.getElementById("idleView");
    const scanningView = document.getElementById("scanningView");
    const resultsView = document.getElementById("resultsView");

    if (idleView) idleView.classList.add("d-none");
    if (scanningView) scanningView.classList.add("d-none");
    if (resultsView) resultsView.classList.remove("d-none");

    // Header info
    document.getElementById("resultDomainTitle").textContent = data.domain;
    document.getElementById("resultScanDate").textContent = `Audited: ${data.scan_date || new Date().toLocaleString()}`;

    // Score & Grade
    const scoreVal = data.score !== undefined ? data.score : 0;
    const gradeVal = data.grade || "N/A";
    const gradeClass = gradeVal.toLowerCase();

    document.getElementById("scoreDisplay").textContent = `${scoreVal}/100`;
    document.getElementById("gradeDisplay").textContent = gradeVal;

    const ring = document.getElementById("scoreRing");
    if (ring) {
        ring.className = `ring ${gradeClass}`;
    }

    // Verdict
    const verdictEl = document.getElementById("verdictBadge");
    if (verdictEl) {
        if (scoreVal >= 80) {
            verdictEl.className = "verdict strong";
            verdictEl.textContent = "SECURE";
        } else if (scoreVal >= 50) {
            verdictEl.className = "verdict medium";
            verdictEl.textContent = "MODERATE";
        } else {
            verdictEl.className = "verdict weak";
            verdictEl.textContent = "HIGH RISK";
        }
    }

    // Auth Risk Bars
    document.getElementById("spfLabel").textContent = `SPF (${data.spf_status || 'Missing'})`;
    document.getElementById("spfBar").style.width = `${data.spf_score || 0}%`;
    document.getElementById("spfBar").style.backgroundColor = (data.spf_score >= 80) ? '#22c55e' : (data.spf_score >= 50 ? '#eab308' : '#ef4444');

    document.getElementById("dmarcLabel").textContent = `DMARC (${data.dmarc_status || 'Missing'})`;
    document.getElementById("dmarcBar").style.width = `${data.dmarc_score || 0}%`;
    document.getElementById("dmarcBar").style.backgroundColor = (data.dmarc_score >= 80) ? '#22c55e' : (data.dmarc_score >= 50 ? '#eab308' : '#ef4444');

    // Telemetry Records Grid
    document.getElementById("mxRecords").textContent = (data.mx && data.mx.length) ? data.mx.join("\n") : "No MX records detected";
    document.getElementById("dmarcRecords").textContent = (data.dmarc && data.dmarc.length) ? data.dmarc.join("\n") : "No DMARC records detected";
    document.getElementById("spfRecords").textContent = (data.spf && data.spf.length) ? data.spf.join("\n") : "No SPF records detected";
    document.getElementById("dkimRecords").textContent = (data.dkim && data.dkim.length) ? data.dkim.join("\n") : "No standard DKIM records detected";
    document.getElementById("otherRecords").textContent = (data.other && data.other.length) ? data.other.join("\n") : "None";

    // Web Headers
    if (data.web_info && typeof data.web_info === 'object') {
        const lines = Object.entries(data.web_info).map(([k, v]) => `${k}: ${v}`);
        document.getElementById("webHeaders").textContent = lines.join("\n");
    } else {
        document.getElementById("webHeaders").textContent = "Web header data unavailable";
    }

    // DNSSEC
    const dnssecStatus = (data.dnssec && data.dnssec.status) ? data.dnssec.status : "Not Enabled";
    document.getElementById("dnssecStatus").textContent = dnssecStatus;
    const dnssecBadge = document.getElementById("dnssecBadge");
    if (dnssecBadge) {
        dnssecBadge.className = `card-badge ${dnssecStatus === 'Enabled' ? 'low' : 'medium'}`;
        dnssecBadge.textContent = dnssecStatus;
    }

    // HTTPS
    const httpsStatus = (data.https && data.https.status) ? data.https.status : "Unknown";
    document.getElementById("httpsStatus").textContent = httpsStatus;
    const httpsBadge = document.getElementById("httpsBadge");
    if (httpsBadge) {
        const isHttpsOk = httpsStatus.includes("Enabled");
        httpsBadge.className = `card-badge ${isHttpsOk ? 'low' : 'high'}`;
        httpsBadge.textContent = isHttpsOk ? 'Active' : 'Warning';
    }

    // Ports
    document.getElementById("portsRecords").textContent = (data.ports && data.ports.length) ? data.ports.join("\n") : "No open ports found";

    // Render Remediation Playbooks List
    renderRemediationCards(data);

    // Scroll to results cleanly
    resultsView.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Builds remediation checklist cards dynamically
 */
function renderRemediationCards(data) {
    const listEl = document.getElementById("remediationList");
    if (!listEl) return;

    listEl.innerHTML = "";

    const items = [];

    // SPF check
    if (data.spf_status === "Missing") {
        items.push({
            type: "danger",
            key: "spf",
            tag: "Critical",
            title: "Create SPF Record",
            subtitle: "Domain is unprotected against direct sender forgery"
        });
    } else if (data.spf_status === "SoftFail" || data.spf_status === "Weak") {
        items.push({
            type: "danger",
            key: "spf",
            tag: "High",
            title: "Harden SPF Policy",
            subtitle: "Change policy from ~all (SoftFail) to -all (HardFail)"
        });
    }

    // DMARC check
    if (!data.dmarc || data.dmarc.length === 0 || data.dmarc_status === "Missing") {
        items.push({
            type: "danger",
            key: "dmarc",
            tag: "Critical",
            title: "Implement DMARC Policy",
            subtitle: "Create _dmarc record with p=quarantine or p=reject"
        });
    } else if (data.dmarc_status === "Weak") {
        items.push({
            type: "warning",
            key: "dmarc",
            tag: "High",
            title: "Enforce DMARC Policy",
            subtitle: "Move from monitoring mode (p=none) to p=reject"
        });
    }

    // DKIM check
    if (!data.dkim || data.dkim.length === 0) {
        items.push({
            type: "warning",
            key: "dkim",
            tag: "Medium",
            title: "Enable DKIM Signing",
            subtitle: "Generate and publish DKIM selector keys"
        });
    }

    // DNSSEC check
    const dnssecEnabled = data.dnssec && data.dnssec.status === "Enabled";
    if (!dnssecEnabled) {
        items.push({
            type: "neutral",
            key: "dnssec",
            tag: "Recommended",
            title: "Enable DNSSEC",
            subtitle: "Protect domain from DNS spoofing and cache poisoning"
        });
    }

    if (items.length === 0) {
        listEl.innerHTML = '<div class="text-success p-3"><i class="bi bi-shield-check me-2"></i> All critical email and DNS controls are configured properly! Maintain regular monitoring.</div>';
        return;
    }

    items.forEach(item => {
        const card = document.createElement("div");
        card.className = `fix-card ${item.type}`;
        card.onclick = () => showFix(item.key);
        card.innerHTML = `
            <div class="fix-left">
                <i class="bi bi-shield-exclamation"></i>
                <div>
                    <strong>${item.title}</strong>
                    <small>${item.subtitle}</small>
                </div>
            </div>
            <span class="fix-tag ${item.type === 'danger' ? 'high' : (item.type === 'warning' ? 'medium' : 'low')}">${item.tag}</span>
        `;
        listEl.appendChild(card);
    });
}

/**
 * Opens slide-out fix panel with playbook steps
 */
function showFix(key) {
    const guide = FIX_GUIDES[key];
    if (!guide) return;

    let stepsHTML = '<div class="fix-steps">';
    guide.steps.forEach((step, index) => {
        stepsHTML += `
            <div class="fix-step">
                <div class="step-number">${index + 1}</div>
                <div class="step-text">${step}</div>
            </div>
        `;
    });
    stepsHTML += '</div>';

    document.getElementById("fixTitle").innerText = guide.title;
    document.getElementById("fixBody").innerHTML = stepsHTML;
    document.getElementById("fixPanel").classList.add("open");
}

function closeFixPanel() {
    const panel = document.getElementById("fixPanel");
    if (panel) panel.classList.remove("open");
}

/**
 * Displays metric detail in universal explanation modal
 */
function showExplanation(title, contentHTML) {
    const modalTitle = document.getElementById("explanationModalTitle");
    const modalBody = document.getElementById("explanationModalBody");
    if (modalTitle && modalBody) {
        modalTitle.innerText = title;
        modalBody.innerHTML = contentHTML;
        const modal = new bootstrap.Modal(document.getElementById("explanationModal"));
        modal.show();
    }
}

/**
 * Downloads compiled PDF report
 */
async function downloadPDF() {
    if (!window.currentReportData) {
        alert("No scan data available to export.");
        return;
    }

    const downloadBtn = document.getElementById("downloadPdfBtn");
    const originalText = downloadBtn ? downloadBtn.innerHTML : "";
    if (downloadBtn) {
        downloadBtn.disabled = true;
        downloadBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Compiling PDF...';
    }

    try {
        const response = await fetch("/api/report/pdf", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(window.currentReportData)
        });

        if (!response.ok) {
            throw new Error("PDF generation failed on server");
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        const domainClean = (window.currentReportData.domain || "domain").replace(/[^a-zA-Z0-9]/g, "_");
        a.href = url;
        a.download = `${domainClean}_security_report.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

    } catch (err) {
        console.error("Failed to download PDF:", err);
        alert("Unable to generate PDF report. Please try again.");
    } finally {
        if (downloadBtn) {
            downloadBtn.disabled = false;
            downloadBtn.innerHTML = originalText;
        }
    }
}

/**
 * Reset to idle view for a new scan
 */
function resetScan() {
    const idleView = document.getElementById("idleView");
    const resultsView = document.getElementById("resultsView");
    const domainInput = document.getElementById("domainInput");

    if (resultsView) resultsView.classList.add("d-none");
    if (idleView) idleView.classList.remove("d-none");
    if (domainInput) {
        domainInput.value = "";
        domainInput.focus();
    }
    window.currentReportData = null;
}
