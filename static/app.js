
const form = document.getElementById("investigation-form");
const pasteTab = document.getElementById("paste-tab");
const uploadTab = document.getElementById("upload-tab");
const pastePanel = document.getElementById("paste-panel");
const uploadPanel = document.getElementById("upload-panel");
const logText = document.getElementById("log-text");
const logFile = document.getElementById("log-file");
const fileLabel = document.getElementById("file-label");
const fileHelp = document.getElementById("file-help");
const characterCount = document.getElementById("character-count");
const errorMessage = document.getElementById("error-message");
const analyzeButton = document.getElementById("analyze-button");
const buttonLabel = document.getElementById("button-label");
const loadingSection = document.getElementById("loading-section");
const resultsSection = document.getElementById("results-section");

let inputMode = "paste";
let latestReport = null;

function switchMode(mode) {
    inputMode = mode;
    const pasteActive = mode === "paste";

    pasteTab.classList.toggle("active", pasteActive);
    uploadTab.classList.toggle("active", !pasteActive);
    pasteTab.setAttribute("aria-selected", String(pasteActive));
    uploadTab.setAttribute("aria-selected", String(!pasteActive));
    pastePanel.classList.toggle("hidden", !pasteActive);
    uploadPanel.classList.toggle("hidden", pasteActive);
    hideError();
}

pasteTab.addEventListener("click", () => switchMode("paste"));
uploadTab.addEventListener("click", () => switchMode("upload"));

function hideError() {
    errorMessage.textContent = "";
    errorMessage.classList.add("hidden");
}

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.remove("hidden");
}

logText.addEventListener("input", () => {
    characterCount.textContent =
        `${logText.value.length.toLocaleString()} characters`;
});

document.getElementById("clear-logs").addEventListener("click", () => {
    logText.value = "";
    characterCount.textContent = "0 characters";
    logText.focus();
});

logFile.addEventListener("change", () => {
    const file = logFile.files[0];
    fileLabel.textContent = file ? file.name : "Choose a file or drop it here";
    fileHelp.textContent = file
        ? `${(file.size / 1024).toFixed(1)} KB selected`
        : "Your file will be processed by the local application.";
});

const dropZone = document.getElementById("drop-zone");

["dragenter", "dragover"].forEach(eventName => {
    dropZone.addEventListener(eventName, event => {
        event.preventDefault();
        dropZone.classList.add("dragging");
    });
});

["dragleave", "drop"].forEach(eventName => {
    dropZone.addEventListener(eventName, event => {
        event.preventDefault();
        dropZone.classList.remove("dragging");
    });
});

dropZone.addEventListener("drop", event => {
    const file = event.dataTransfer.files[0];
    if (!file) return;

    if (!/\.(log|txt)$/i.test(file.name)) {
        showError("Choose a .log or .txt file.");
        return;
    }

    const transfer = new DataTransfer();
    transfer.items.add(file);
    logFile.files = transfer.files;
    logFile.dispatchEvent(new Event("change"));
    hideError();
});

function setLoading(loading) {
    analyzeButton.disabled = loading;
    buttonLabel.textContent = loading
        ? "Investigating..."
        : "Investigate incident";
    loadingSection.classList.toggle("hidden", !loading);
}

form.addEventListener("submit", async event => {
    event.preventDefault();
    hideError();
    resultsSection.classList.add("hidden");

    const data = new FormData();

    if (inputMode === "paste") {
        if (!logText.value.trim()) {
            showError("Paste your application logs before continuing.");
            return;
        }
        data.append("log_text", logText.value);
    } else {
        const file = logFile.files[0];
        if (!file) {
            showError("Choose a log file before continuing.");
            return;
        }
        if (!/\.(log|txt)$/i.test(file.name)) {
            showError("Choose a .log or .txt file.");
            return;
        }
        if (file.size > 5 * 1024 * 1024) {
            showError("The maximum file size is 5 MB.");
            return;
        }
        data.append("file", file);
    }

    setLoading(true);

    try {
        const response = await fetch("/api/investigate", {
            method: "POST",
            body: data
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.detail || "Investigation failed.");
        }

        latestReport = result;
        renderReport(result);
        resultsSection.classList.remove("hidden");
        resultsSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    } catch (error) {
        showError(error.message || "Could not connect to TraceLens.");
    } finally {
        setLoading(false);
    }
});

function addText(tag, text, className = "") {
    const element = document.createElement(tag);
    element.textContent = text ?? "";
    if (className) element.className = className;
    return element;
}




function evidenceToText(evidence) {
    if (typeof evidence === "string") {
        return evidence;
    }

    if (evidence && typeof evidence === "object") {
        const claim = evidence.claim
            || evidence.evidence
            || evidence.text
            || evidence.description;

        const lineNumber = evidence.line_number
            ?? evidence.line
            ?? evidence.log_line;

        if (claim) {
            return lineNumber != null
                ? `${claim} (Line ${lineNumber})`
                : claim;
        }

        return JSON.stringify(evidence);
    }

    return String(evidence ?? "");
}


function renderList(elementId, items) {
    const list = document.getElementById(elementId);
    list.replaceChildren();

    if (!Array.isArray(items) || items.length === 0) {
        list.append(addText("li", "None reported."));
        return;
    }

    items.forEach(item => list.append(addText("li", item)));
}

function renderReport(result) {
    const analysis = result.analysis || {};
    const report = result.report || {};
    const validation = result.validation || {};

    document.getElementById("result-filename").textContent =
        result.filename || "Incident report";
    document.getElementById("result-description").textContent =
        "Investigation completed. Review the evidence before taking action.";

    document.getElementById("event-count").textContent =
        analysis.event_count ?? 0;
    document.getElementById("error-count").textContent =
        analysis.error_count ?? 0;
    document.getElementById("service-count").textContent =
        new Set((analysis.timeline || []).map(event => event.service)).size;
    document.getElementById("evidence-count").textContent =
        validation.claims_checked ?? 0;

    document.getElementById("incident-summary").textContent =
        report.incident_summary || "No summary was returned.";
    document.getElementById("confidence").textContent =
        report.confidence || "Not specified";

    renderCauses(report.likely_causes || []);
    renderEvidence(validation);
    renderList("recommended-checks", report.recommended_checks || []);
    renderList("alternatives", report.alternative_explanations || []);
    renderTimeline(analysis.timeline || []);
}

function renderCauses(causes) {
    const container = document.getElementById("likely-causes");
    container.replaceChildren();

    if (!causes.length) {
        container.append(addText("p", "No likely causes were reported.", "muted"));
        return;
    }

    causes.forEach((cause, index) => {
        const item = document.createElement("section");
        item.className = "cause-item";

        item.append(addText(
            "h4",
            `${index + 1}. ${cause.hypothesis || "Possible cause"}`
        ));

        item.append(addText("h5", "Supporting evidence"));
        const evidence = document.createElement("ul");
        evidence.className = "report-list";

        (cause.supporting_evidence || []).forEach(item => {
            evidence.append(addText("li", evidenceToText(item)));
        });

        if (!evidence.children.length) {
            evidence.append(addText("li", "No evidence provided."));
        }
        item.append(evidence);

        item.append(addText("h5", "Information still needed"));
        const missing = document.createElement("ul");
        missing.className = "report-list";

        (cause.missing_evidence || []).forEach(claim => {
            missing.append(addText("li", claim));
        });

        if (!missing.children.length) {
            missing.append(addText("li", "None specified."));
        }
        item.append(missing);
        container.append(item);
    });
}

function renderEvidence(validation) {
    const verified = document.getElementById("verified-evidence");
    const unsupported = document.getElementById("unsupported-evidence");

    verified.replaceChildren();
    unsupported.replaceChildren();

    const verifiedClaims = validation.verified_claims || [];
    const unsupportedClaims = validation.unsupported_claims || [];

    document.getElementById("verification-status").textContent =
        `${verifiedClaims.length} source lines found`;

    verified.append(addText("h4", "Source lines found"));
    if (verifiedClaims.length) {
        verifiedClaims.forEach(claim => {
            verified.append(addText(
                "div",
                `Line ${claim.line_number} · ${claim.actual_level} · ` +
                `${claim.actual_service}/${claim.actual_event}: ${claim.claim}`,
                "evidence-item"
            ));
        });
    } else {
        verified.append(addText(
            "p", "No source lines were verified.", "muted"
        ));
    }

    unsupported.append(addText("h4", "Unverified references"));
    if (unsupportedClaims.length) {
        unsupportedClaims.forEach(claim => {
            unsupported.append(addText(
                "div",
                `${claim.claim} — ${claim.reason}`,
                "evidence-item bad"
            ));
        });
    } else {
        unsupported.append(addText(
            "p", "No unsupported line references were detected.", "muted"
        ));
    }
}

function renderTimeline(events) {
    const tbody = document.getElementById("timeline-body");
    tbody.replaceChildren();

    events.forEach(event => {
        const row = document.createElement("tr");
        const time = (event.timestamp || "").replace("T", " ");

        row.append(addText("td", time));
        const levelCell = document.createElement("td");
        const level = (event.level || "INFO").toLowerCase();

        levelCell.append(addText(
            "span",
            event.level || "INFO",
            `level level-${level}`
        ));

        row.append(levelCell);
        row.append(addText("td", event.service));
        row.append(addText("td", event.event));
        row.append(addText("td", event.line_number));

        tbody.append(row);
    });

    if (!events.length) {
        const row = document.createElement("tr");
        const cell = addText("td", "No events to display.");
        cell.colSpan = 5;
        row.append(cell);
        tbody.append(row);
    }
}

document.getElementById("download-report").addEventListener("click", () => {
    if (!latestReport) return;

    const blob = new Blob(
        [JSON.stringify(latestReport, null, 2)],
        { type: "application/json" }
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "tracelens-incident-report.json";
    link.click();

    URL.revokeObjectURL(url);
});
