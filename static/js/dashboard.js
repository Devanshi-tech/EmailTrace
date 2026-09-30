/* ==========================================================
   EmailTrace - Dashboard logic
   Talks to: GET /api/investigation/<investigation_id>
   Security: all API data is untrusted. It is written with
   textContent / createElement only (never innerHTML).
   ========================================================== */
(function () {
    "use strict";

    const root = document.getElementById("dashboardRoot");
    const investigationId = root.dataset.investigationId;
    const NOT_AVAILABLE = "Not available";

    const states = {
        loading: document.getElementById("loadingState"),
        empty: document.getElementById("emptyState"),
        error: document.getElementById("errorState"),
        content: document.getElementById("dashboardContent")
    };
    const errorMessageEl = document.getElementById("errorMessage");
    const retryBtn = document.getElementById("retryBtn");
    const riskList = document.getElementById("riskList");
    const riskBreakdown = document.getElementById("riskBreakdown");
    const noEvidenceNote = document.getElementById("noEvidenceNote");

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

    // ---------- Small helpers ----------
    function text(value) {
        if (value === null || value === undefined || String(value).trim() === "") {
            return NOT_AVAILABLE;
        }
        return String(value);
    }

    function setText(id, value) {
        document.getElementById(id).textContent = text(value);
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

    function showState(name) {
        Object.keys(states).forEach(function (key) {
            states[key].classList.toggle("d-none", key !== name);
        });
    }

    /* ----------------------------------------------------------
       normalize(): the ONLY place that knows the API field names.
       If the backend uses different names, edit this function.
       ---------------------------------------------------------- */
    function normalize(payload) {
        const d = (payload && payload.investigation) ? payload.investigation : (payload || {});
        const email = d.email || {};
        return {
            id: d.investigation_id || d.id || investigationId,
            email: {
                sender: email.sender ?? email.from,
                recipient: email.recipient ?? email.to,
                subject: email.subject,
                date: email.date,
                replyTo: email.reply_to,
                returnPath: email.return_path
            },
            urls: asList(d.urls),
            ips: asList(d.ips),
            domains: asList(d.domains),
            attachments: asList(d.attachments),
            iocs: asList(d.iocs),
            risks: asList(d.risk_indicators),
            raw: d // full payload, used by the detailed sections in Step 5
        };
    }

    // ---------- Rendering ----------
    function renderEmailDetails(data) {
        setText("dId", data.id);
        setText("dSender", data.email.sender);
        setText("dRecipient", data.email.recipient);
        setText("dSubject", data.email.subject);
        setText("dDate", data.email.date);
        setText("dReplyTo", data.email.replyTo);
        setText("dReturnPath", data.email.returnPath);
    }

    function renderCards(data) {
        document.getElementById("countUrls").textContent = data.urls.length;
        document.getElementById("countIps").textContent = data.ips.length;
        document.getElementById("countDomains").textContent = data.domains.length;
        document.getElementById("countAttachments").textContent = data.attachments.length;
        document.getElementById("countIocs").textContent = data.iocs.length;
        document.getElementById("countRisks").textContent = data.risks.length;
    }

    function renderRisks(risks) {
        riskList.replaceChildren();

        if (risks.length === 0) {
            riskBreakdown.textContent = "None reported.";
            const empty = document.createElement("div");
            empty.className = "et-placeholder";
            empty.textContent = "No risk indicators were reported for this investigation.";
            riskList.appendChild(empty);
            return;
        }

        // Breakdown line, e.g. "High: 1 | Medium: 2 | Low: 0 | Informational: 1"
        const counts = { high: 0, medium: 0, low: 0, info: 0 };
        risks.forEach(function (r) { counts[normalizeSeverity(r.severity)] += 1; });
        riskBreakdown.textContent =
            "High: " + counts.high + "  |  Medium: " + counts.medium +
            "  |  Low: " + counts.low + "  |  Informational: " + counts.info;

        // Highest severity first
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

            riskList.appendChild(item);
        });
    }

    function render(data) {
        renderEmailDetails(data);
        renderCards(data);
        renderRisks(data.risks);

        const totalItems = data.urls.length + data.ips.length + data.domains.length +
                           data.attachments.length + data.iocs.length + data.risks.length;
        noEvidenceNote.classList.toggle("d-none", totalItems > 0);
    }

    // ---------- Load from API ----------
    async function loadInvestigation() {
        showState("loading");
        try {
            const res = await fetch(
                "/api/investigation/" + encodeURIComponent(investigationId),
                { headers: { Accept: "application/json" } }
            );
            const payload = await readJson(res);

            if (!res.ok) {
                if (res.status === 404) {
                    throw new Error("Investigation not found. Check the ID or upload the evidence again.");
                }
                const serverMsg = payload && (payload.error || payload.message);
                throw new Error(serverMsg ? String(serverMsg) : "Server error (HTTP " + res.status + ").");
            }

            render(normalize(payload));
            showState("content");
        } catch (err) {
            errorMessageEl.textContent = (err instanceof TypeError)
                ? "Could not reach the server. Please check that the backend is running."
                : err.message;
            showState("error");
        }
    }

    // ---------- Start ----------
    retryBtn.addEventListener("click", loadInvestigation);

    if (!investigationId) {
        showState("empty");
    } else {
        loadInvestigation();
    }
})();