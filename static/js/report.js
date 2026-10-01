/* ==========================================================
   EmailTrace - Report page logic
   Talks to: GET /api/investigation/<investigation_id>/report
   Security: all API data is untrusted. It is written with
   textContent / createElement only (never innerHTML).
   URLs are shown as plain text; no <a> elements are created
   from extracted data.
   ========================================================== */
(function () {
    "use strict";

    const root = document.getElementById("reportRoot");
    const investigationId = root.dataset.investigationId;
    const NOT_AVAILABLE = "Not available";
    const DASH = "\u2014";

    const states = {
        loading: document.getElementById("loadingState"),
        empty: document.getElementById("emptyState"),
        error: document.getElementById("errorState"),
        content: document.getElementById("reportContent")
    };
    const errorMessageEl = document.getElementById("errorMessage");
    const retryBtn = document.getElementById("retryBtn");
    const printBtn = document.getElementById("printBtn");
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

    function bySeverityDesc(a, b) {
        return SEVERITY_RANK[normalizeSeverity(b.severity)] -
               SEVERITY_RANK[normalizeSeverity(a.severity)];
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

    function formatSize(bytes) {
        if (typeof bytes !== "number" || !isFinite(bytes) || bytes < 0) {
            return bytes; // strings / missing values are handled by text()
        }
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / (1024 * 1024)).toFixed(2) + " MB";
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

    function serverLabel(index) {
        return index < 26 ? "Server " + String.fromCharCode(65 + index) : "Server " + (index + 1);
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
            analyzedAt: d.analyzed_at ?? d.analyzedAt,
            email: {
                sender: email.sender ?? email.from,
                recipient: email.recipient ?? email.to,
                subject: email.subject,
                date: email.date,
                replyTo: email.reply_to,
                returnPath: email.return_path
            },
            headers: asList(d.headers),
            receivedPath: asList(d.received_path),
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
    // Safe table builder
    // ==========================================================
    function makeTags(value) {
        const items = Array.isArray(value) ? value : (value ? [value] : []);
        const wrap = document.createElement("div");
        if (items.length === 0) {
            const none = document.createElement("span");
            none.className = "text-secondary small";
            none.textContent = "None detected";
            wrap.appendChild(none);
            return wrap;
        }
        wrap.className = "d-flex flex-wrap gap-1";
        items.forEach(function (item) {
            const tag = document.createElement("span");
            tag.className = "et-tag";
            tag.textContent = String(item);
            wrap.appendChild(tag);
        });
        return wrap;
    }

    function cellContent(col, row) {
        const v = col.value(row);
        if (col.type === "severity") return makeBadge(v);
        if (col.type === "tags") return makeTags(v);

        let el;
        if (col.type === "bold") {
            el = document.createElement("strong");
        } else {
            el = document.createElement("span");
            if (col.type === "mono") el.className = "et-mono";
        }
        el.textContent = text(v); // safe: textContent
        return el;
    }

    function emptyBox(message) {
        const box = document.createElement("div");
        box.className = "et-placeholder";
        box.textContent = message;
        return box;
    }

    function buildTable(container, columns, rows, emptyMessage) {
        container.replaceChildren();
        if (rows.length === 0) {
            container.appendChild(emptyBox(emptyMessage));
            return;
        }

        const wrap = document.createElement("div");
        wrap.className = "table-responsive et-table-wrap";

        const table = document.createElement("table");
        table.className = "table table-striped align-middle et-table";

        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        columns.forEach(function (col) {
            const th = document.createElement("th");
            th.scope = "col";
            th.textContent = col.label;
            headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        rows.forEach(function (row) {
            const tr = document.createElement("tr");
            columns.forEach(function (col) {
                const td = document.createElement("td");
                td.appendChild(cellContent(col, row));
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);

        wrap.appendChild(table);
        container.appendChild(wrap);
    }

    // ==========================================================
    // Report sections (one table per section)
    // ==========================================================
    const SECTIONS = [
        {
            key: "headers", target: "rptHeaders",
            empty: "No headers were extracted.",
            columns: [
                { label: "Header", type: "bold", value: function (r) { return r.name; } },
                { label: "Value", type: "mono", value: function (r) { return r.value; } }
            ]
        },
        {
            key: "receivedPath", target: "rptReceived",
            empty: "No Received headers were found, so the delivery path is unavailable.",
            // Builds: Server A -> Server B -> Server C -> Recipient
            prepare: function (rows, data) {
                const ordered = rows.slice().sort(function (a, b) {
                    return (Number(a.hop) || 0) - (Number(b.hop) || 0);
                });
                if (ordered.length === 0) return [];
                const mapped = ordered.map(function (h, i) {
                    return {
                        server: serverLabel(i),
                        by: h.by,
                        from: h.from ?? h.from_host,
                        ip: h.ip,
                        timestamp: h.timestamp
                    };
                });
                mapped.push({
                    server: "Recipient", by: data.email.recipient,
                    from: DASH, ip: DASH, timestamp: DASH
                });
                return mapped;
            },
            columns: [
                { label: "Step", type: "bold", value: function (r) { return r.server; } },
                { label: "Server", type: "mono", value: function (r) { return r.by; } },
                { label: "Received from", type: "mono", value: function (r) { return r.from; } },
                { label: "IP", type: "mono", value: function (r) { return r.ip; } },
                { label: "Time", type: "mono", value: function (r) { return r.timestamp; } }
            ]
        },
        {
            key: "ips", target: "rptIps",
            empty: "No IP addresses were extracted.",
            columns: [
                { label: "IP", type: "mono", value: function (r) { return r.ip; } },
                { label: "Type", value: function (r) { return r.type; } },
                { label: "Source", value: function (r) { return r.source; } },
                { label: "Classification", value: function (r) { return r.classification; } }
            ]
        },
        {
            key: "urls", target: "rptUrls",
            empty: "No URLs were extracted.",
            columns: [
                { label: "URL", type: "mono", value: function (r) { return r.url; } },
                { label: "Hostname", type: "mono", value: function (r) { return r.hostname; } },
                { label: "Indicators", type: "tags", value: function (r) { return r.indicators; } }
            ]
        },
        {
            key: "domains", target: "rptDomains",
            empty: "No domains were extracted.",
            columns: [
                { label: "Domain", type: "mono", value: function (r) { return r.domain; } },
                { label: "Source", value: function (r) { return r.source; } },
                { label: "Suspicious Indicators", type: "tags", value: function (r) { return r.indicators; } }
            ]
        },
        {
            key: "attachments", target: "rptAttachments",
            empty: "This email has no attachments.",
            columns: [
                { label: "Filename", type: "mono", value: function (r) { return r.filename; } },
                { label: "MIME Type", type: "mono", value: function (r) { return r.mime_type; } },
                { label: "Size", value: function (r) { return formatSize(r.size); } },
                { label: "SHA-256", type: "mono", value: function (r) { return r.sha256; } }
            ]
        },
        {
            key: "contentFindings", target: "rptContent",
            empty: "No content indicators were detected.",
            prepare: function (rows) { return rows.slice().sort(bySeverityDesc); },
            columns: [
                { label: "Detected Indicator", value: function (r) { return r.indicator; } },
                { label: "Evidence", value: function (r) { return r.evidence; } },
                { label: "Severity", type: "severity", value: function (r) { return r.severity; } }
            ]
        },
        {
            key: "iocs", target: "rptIocs",
            empty: "No indicators of compromise were detected.",
            columns: [
                { label: "Type", type: "bold", value: function (r) { return r.type; } },
                { label: "Value", type: "mono", value: function (r) { return r.value; } },
                { label: "Source", value: function (r) { return r.source; } }
            ]
        },
        {
            key: "risks", target: "rptRisks",
            empty: "No risk indicators were reported for this investigation.",
            prepare: function (rows) { return rows.slice().sort(bySeverityDesc); },
            columns: [
                { label: "Severity", type: "severity", value: function (r) { return r.severity; } },
                { label: "Indicator", type: "bold", value: function (r) { return r.title ?? r.indicator ?? r.name; } },
                { label: "Description", value: function (r) { return r.description ?? r.evidence; } }
            ]
        }
    ];

    function renderSections(data) {
        SECTIONS.forEach(function (section) {
            const rows = section.prepare ? section.prepare(data[section.key], data) : data[section.key];
            buildTable(document.getElementById(section.target), section.columns, rows, section.empty);
        });
    }

    function renderRiskBreakdown(risks) {
        const el = document.getElementById("rptRiskBreakdown");
        if (risks.length === 0) {
            el.textContent = "None reported.";
            return;
        }
        const counts = { high: 0, medium: 0, low: 0, info: 0 };
        risks.forEach(function (r) { counts[normalizeSeverity(r.severity)] += 1; });
        el.textContent =
            "High: " + counts.high + "  |  Medium: " + counts.medium +
            "  |  Low: " + counts.low + "  |  Informational: " + counts.info;
    }

    // ==========================================================
    // Full render
    // ==========================================================
    function render(data) {
        setText("rId", data.id);
        setText("rAnalyzed", data.analyzedAt);
        setText("rGenerated", new Date().toLocaleString());

        setText("rSender", data.email.sender);
        setText("rRecipient", data.email.recipient);
        setText("rSubject", data.email.subject);
        setText("rDate", data.email.date);
        setText("rReplyTo", data.email.replyTo);
        setText("rReturnPath", data.email.returnPath);

        renderSections(data);
        renderRiskBreakdown(data.risks);

        const totalItems = data.headers.length + data.receivedPath.length + data.urls.length +
                           data.ips.length + data.domains.length + data.attachments.length +
                           data.contentFindings.length + data.iocs.length + data.risks.length;
        noEvidenceNote.classList.toggle("d-none", totalItems > 0);
    }

    // ---------- Load from API ----------
    async function loadReport() {
        showState("loading");
        try {
            const res = await fetch(
                "/api/investigation/" + encodeURIComponent(investigationId) + "/report",
                { headers: { Accept: "application/json" } }
            );
            const payload = await readJson(res);

            if (!res.ok) {
                if (res.status === 404) {
                    throw new Error("Report not found. Check the ID or upload the evidence again.");
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
    retryBtn.addEventListener("click", loadReport);
    printBtn.addEventListener("click", function () { window.print(); });

    if (!investigationId) {
        showState("empty");
    } else {
        loadReport();
    }
})();