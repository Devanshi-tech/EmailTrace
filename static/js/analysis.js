/* ==========================================================
   EmailTrace - Analysis page logic
   Talks to: GET  /api/investigation/<investigation_id>
             POST /api/analyze/<investigation_id>
   Security: all API data is untrusted and is written with
   textContent / createElement only (never innerHTML).
   ========================================================== */
(function () {
    "use strict";

    const root = document.getElementById("analysisRoot");
    const investigationId = root.dataset.investigationId;
    const NOT_AVAILABLE = "Not available";
    const NETWORK_ERROR = "Could not reach the server. Please check that the backend is running.";

    const states = {
        loading: document.getElementById("loadingState"),
        empty: document.getElementById("emptyState"),
        error: document.getElementById("errorState"),
        content: document.getElementById("analysisContent")
    };
    const errorMessageEl = document.getElementById("errorMessage");
    const retryBtn = document.getElementById("retryBtn");
    const alertArea = document.getElementById("alertArea");
    const runBtn = document.getElementById("runBtn");
    const runSpinner = document.getElementById("runSpinner");
    const runBtnText = document.getElementById("runBtnText");
    const noResultsNote = document.getElementById("noResultsNote");
    const chartsNote = document.getElementById("chartsNote");
    const summaryTable = document.getElementById("summaryTable");
    const findingsList = document.getElementById("findingsList");
    const findingsBreakdown = document.getElementById("findingsBreakdown");

    const severityBox = document.getElementById("severityBox");
    const severityEmpty = document.getElementById("severityEmpty");
    const severityCanvas = document.getElementById("severityChart");
    const evidenceBox = document.getElementById("evidenceBox");
    const evidenceEmpty = document.getElementById("evidenceEmpty");
    const evidenceCanvas = document.getElementById("evidenceChart");

    const charts = { severity: null, evidence: null };
    let runLabel = "Run Analysis";

    // ---------- Severity handling (four levels only) ----------
    const SEVERITY_LABEL = { info: "Informational", low: "Low", medium: "Medium", high: "High" };
    const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3 };

    function normalizeSeverity(value) {
        const s = String(value || "").trim().toLowerCase();
        if (s === "high" || s === "critical") return "high";
        if (s === "medium" || s === "moderate") return "medium";
        if (s === "low") return "low";
        return "info"; // informational, unknown or missing
    }

    function makeBadge(severity) {
        const sev = normalizeSeverity(severity);
        const badge = document.createElement("span");
        badge.className = "et-badge et-badge-" + sev;
        badge.textContent = SEVERITY_LABEL[sev];
        return badge;
    }

    function countBySeverity(risks) {
        const counts = { high: 0, medium: 0, low: 0, info: 0 };
        risks.forEach(function (r) { counts[normalizeSeverity(r.severity)] += 1; });
        return counts;
    }

    // ---------- Small helpers ----------
    function text(value) {
        if (value === null || value === undefined || String(value).trim() === "") {
            return NOT_AVAILABLE;
        }
        return String(value);
    }

    function asList(value) {
        return Array.isArray(value) ? value : [];
    }

    async function readJson(response) {
        try {
            return await response.json();
        } catch (e) {
            return {};
        }
    }

    function errorMessageFrom(payload, response, fallback) {
        const serverMsg = payload && (payload.error || payload.message);
        return serverMsg ? String(serverMsg) : fallback + " (HTTP " + response.status + ")";
    }

    function describeError(err) {
        return (err instanceof TypeError) ? NETWORK_ERROR : err.message;
    }

    function showState(name) {
        Object.keys(states).forEach(function (key) {
            states[key].classList.toggle("d-none", key !== name);
        });
    }

    function clearAlert() {
        alertArea.replaceChildren();
    }

    // type: "success" | "danger" | "warning" | "info"
    function showAlert(type, message) {
        clearAlert();
        const box = document.createElement("div");
        box.className = "alert alert-" + type + " mb-3";
        box.setAttribute("role", "alert");
        box.textContent = message; // safe: textContent
        alertArea.appendChild(box);
    }

    function emptyBox(message) {
        const box = document.createElement("div");
        box.className = "et-placeholder";
        box.textContent = message;
        return box;
    }

    /* ----------------------------------------------------------
       normalize(): the ONLY place that knows the API field names.
       If the backend uses different names, edit this function.
       ---------------------------------------------------------- */
    function normalize(payload) {
        const d = (payload && payload.investigation) ? payload.investigation : (payload || {});
        return {
            id: d.investigation_id || d.id || investigationId,
            status: d.status,
            analyzedAt: d.analyzed_at ?? d.analyzedAt,
            headers: asList(d.headers),
            receivedPath: asList(d.received_path),
            timeline: asList(d.timeline),
            urls: asList(d.urls),
            ips: asList(d.ips),
            domains: asList(d.domains),
            attachments: asList(d.attachments),
            contentFindings: asList(d.content_findings),
            iocs: asList(d.iocs),
            risks: asList(d.risk_indicators)
        };
    }

    // ==========================================================
    // API calls
    // ==========================================================
    async function fetchInvestigation() {
        const res = await fetch(
            "/api/investigation/" + encodeURIComponent(investigationId),
            { headers: { Accept: "application/json" } }
        );
        const payload = await readJson(res);
        if (!res.ok) {
            if (res.status === 404) {
                throw new Error("Investigation not found. Check the ID or upload the evidence again.");
            }
            throw new Error(errorMessageFrom(payload, res, "Server error"));
        }
        return normalize(payload);
    }

    // ==========================================================
    // Charts (Chart.js)
    // ==========================================================
    const CHART_ITEMS = [
        { label: "URLs", key: "urls" },
        { label: "IPs", key: "ips" },
        { label: "Domains", key: "domains" },
        { label: "Attachments", key: "attachments" },
        { label: "IOCs", key: "iocs" },
        { label: "Content findings", key: "contentFindings" }
    ];

    function cssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function destroyChart(name) {
        if (charts[name]) {
            charts[name].destroy();
            charts[name] = null;
        }
    }

    function applyChartDefaults() {
        Chart.defaults.color = cssVar("--et-muted");
        Chart.defaults.borderColor = cssVar("--et-border");
        Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    }

    function renderSeverityChart(risks) {
        const total = risks.length;
        severityBox.classList.toggle("d-none", total === 0);
        severityEmpty.classList.toggle("d-none", total !== 0);
        if (total === 0) return;

        const counts = countBySeverity(risks);
        const labels = [SEVERITY_LABEL.high, SEVERITY_LABEL.medium, SEVERITY_LABEL.low, SEVERITY_LABEL.info];
        const values = [counts.high, counts.medium, counts.low, counts.info];

        severityCanvas.setAttribute("aria-label",
            "Doughnut chart of risk indicators by severity. " +
            labels.map(function (l, i) { return l + " " + values[i]; }).join(", "));

        charts.severity = new Chart(severityCanvas, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: [cssVar("--sev-high"), cssVar("--sev-medium"),
                                      cssVar("--sev-low"), cssVar("--sev-info")],
                    borderColor: cssVar("--et-surface"),
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "60%",
                plugins: { legend: { position: "bottom" } }
            }
        });
    }

    function renderEvidenceChart(data) {
        const labels = CHART_ITEMS.map(function (i) { return i.label; });
        const values = CHART_ITEMS.map(function (i) { return data[i.key].length; });
        const total = values.reduce(function (a, b) { return a + b; }, 0);

        evidenceBox.classList.toggle("d-none", total === 0);
        evidenceEmpty.classList.toggle("d-none", total !== 0);
        if (total === 0) return;

        evidenceCanvas.setAttribute("aria-label",
            "Bar chart of extracted evidence counts. " +
            labels.map(function (l, i) { return l + " " + values[i]; }).join(", "));

        charts.evidence = new Chart(evidenceCanvas, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Items",
                    data: values,
                    backgroundColor: cssVar("--et-accent"),
                    borderRadius: 4,
                    maxBarThickness: 28
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 } },
                    y: { grid: { display: false } }
                }
            }
        });
    }

    function renderCharts(data) {
        destroyChart("severity");
        destroyChart("evidence");

        const available = (typeof window.Chart !== "undefined");
        chartsNote.classList.toggle("d-none", available);

        if (!available) {
            [severityBox, severityEmpty, evidenceBox, evidenceEmpty].forEach(function (el) {
                el.classList.add("d-none");
            });
            return;
        }

        applyChartDefaults();
        renderSeverityChart(data.risks);
        renderEvidenceChart(data);
    }

    // ==========================================================
    // Summary table and findings list
    // ==========================================================
    const SUMMARY_ITEMS = [
        { label: "Headers", key: "headers" },
        { label: "Received hops", key: "receivedPath" },
        { label: "Timeline events", key: "timeline" },
        { label: "URLs", key: "urls" },
        { label: "IPs", key: "ips" },
        { label: "Domains", key: "domains" },
        { label: "Attachments", key: "attachments" },
        { label: "Content findings", key: "contentFindings" },
        { label: "IOCs", key: "iocs" },
        { label: "Risk indicators", key: "risks" }
    ];

    function renderSummaryTable(data) {
        summaryTable.replaceChildren();

        const wrap = document.createElement("div");
        wrap.className = "table-responsive et-table-wrap";

        const table = document.createElement("table");
        table.className = "table table-striped align-middle et-table";

        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        ["Evidence type", "Count"].forEach(function (label, i) {
            const th = document.createElement("th");
            th.scope = "col";
            th.textContent = label;
            if (i === 1) th.className = "text-end";
            headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        SUMMARY_ITEMS.forEach(function (item) {
            const tr = document.createElement("tr");

            const tdLabel = document.createElement("td");
            tdLabel.textContent = item.label;
            tr.appendChild(tdLabel);

            const tdCount = document.createElement("td");
            tdCount.className = "text-end et-mono";
            tdCount.textContent = String(data[item.key].length);
            tr.appendChild(tdCount);

            tbody.appendChild(tr);
        });
        table.appendChild(tbody);

        wrap.appendChild(table);
        summaryTable.appendChild(wrap);
    }

    function renderFindings(risks) {
        findingsList.replaceChildren();

        if (risks.length === 0) {
            findingsBreakdown.textContent = "None reported.";
            findingsList.appendChild(emptyBox("No risk indicators were reported for this investigation."));
            return;
        }

        const counts = countBySeverity(risks);
        findingsBreakdown.textContent =
            "High: " + counts.high + "  |  Medium: " + counts.medium +
            "  |  Low: " + counts.low + "  |  Informational: " + counts.info;

        const sorted = risks.slice().sort(function (a, b) {
            return SEVERITY_RANK[normalizeSeverity(b.severity)] -
                   SEVERITY_RANK[normalizeSeverity(a.severity)];
        });

        sorted.forEach(function (risk) {
            const item = document.createElement("div");
            item.className = "et-risk-item";

            const head = document.createElement("div");
            head.className = "d-flex flex-wrap align-items-center gap-2";
            head.appendChild(makeBadge(risk.severity));

            const title = document.createElement("strong");
            title.textContent = text(risk.title ?? risk.indicator ?? risk.name);
            head.appendChild(title);
            item.appendChild(head);

            const desc = document.createElement("p");
            desc.className = "text-secondary small mb-0 mt-2";
            desc.textContent = text(risk.description ?? risk.evidence);
            item.appendChild(desc);

            findingsList.appendChild(item);
        });
    }

    // ==========================================================
    // Run card + full render
    // ==========================================================
    function renderRunCard(data) {
        document.getElementById("aId").textContent = text(data.id);
        document.getElementById("aAnalyzedAt").textContent = text(data.analyzedAt);

        const statusEl = document.getElementById("aStatus");
        statusEl.replaceChildren();
        const tag = document.createElement("span");
        tag.className = "et-tag";
        tag.textContent = text(data.status);
        statusEl.appendChild(tag);

        const done = String(data.status || "").trim().toLowerCase() === "completed";
        runLabel = done ? "Re-run Analysis" : "Run Analysis";
        if (!runBtn.disabled) runBtnText.textContent = runLabel;
    }

    function setRunning(isRunning) {
        runBtn.disabled = isRunning;
        runSpinner.classList.toggle("d-none", !isRunning);
        runBtnText.textContent = isRunning ? "Analyzing evidence..." : runLabel;
    }

    function render(data) {
        renderRunCard(data);

        const totalItems = SUMMARY_ITEMS.reduce(function (sum, item) {
            return sum + data[item.key].length;
        }, 0);
        noResultsNote.classList.toggle("d-none", totalItems > 0);

        renderCharts(data);
        renderSummaryTable(data);
        renderFindings(data.risks);
    }

    // ==========================================================
    // Actions
    // ==========================================================
    async function loadInvestigation() {
        showState("loading");
        try {
            const data = await fetchInvestigation();
            showState("content");   // show first so charts can measure their size
            render(data);
        } catch (err) {
            errorMessageEl.textContent = describeError(err);
            showState("error");
        }
    }

    async function runAnalysis() {
        clearAlert();
        setRunning(true);

        // 1. Start the analysis
        try {
            const res = await fetch(
                "/api/analyze/" + encodeURIComponent(investigationId),
                { method: "POST", headers: { Accept: "application/json" } }
            );
            const payload = await readJson(res);
            if (!res.ok) {
                if (res.status === 404) throw new Error("Investigation not found.");
                throw new Error(errorMessageFrom(payload, res, "Analysis failed"));
            }
        } catch (err) {
            showAlert("danger", describeError(err));
            setRunning(false);
            return;
        }

        // 2. Reload the updated results
        try {
            render(await fetchInvestigation());
            showAlert("success", "Analysis completed. Results have been updated.");
        } catch (err) {
            showAlert("warning", "Analysis finished, but the results could not be loaded. " + describeError(err));
        }
        setRunning(false);
    }

    // ---------- Start ----------
    retryBtn.addEventListener("click", loadInvestigation);
    runBtn.addEventListener("click", runAnalysis);

    if (!investigationId) {
        showState("empty");
    } else {
        loadInvestigation();
    }
})();