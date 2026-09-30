/* ==========================================================
   EmailTrace - Dashboard logic
   Talks to: GET /api/investigation/<investigation_id>
   Security: all API data is untrusted. It is written with
   textContent / createElement only (never innerHTML).
   URLs are shown as plain text; no <a> elements are created
   from extracted data.
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

    function formatSize(bytes) {
        if (typeof bytes !== "number" || !isFinite(bytes) || bytes < 0) {
            return bytes; // let text() handle strings / missing values
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

    /* ----------------------------------------------------------
       normalize(): the ONLY place that knows the top-level API
       field names. If the backend uses different names, edit here.
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
    // Safe table builder
    // ==========================================================

    // A list of indicator strings shown as neutral tags
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

    // Build the content of one table cell from a column definition
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
        table.className = "table table-striped table-hover align-middle et-table";

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
    // Section definitions (one table per section)
    // ==========================================================
    const SECTIONS = [
        {
            key: "headers", table: "tblHeaders", count: "cntHeaders",
            empty: "No headers were extracted.",
            columns: [
                { label: "Header", type: "bold", value: function (r) { return r.name; } },
                { label: "Value", type: "mono", value: function (r) { return r.value; } }
            ]
        },
        {
            key: "timeline", table: "tblTimeline", count: "cntTimeline",
            empty: "No timeline events were extracted.",
            columns: [
                { label: "Timestamp", type: "mono", value: function (r) { return r.timestamp; } },
                { label: "Event", value: function (r) { return r.event; } },
                { label: "Source", value: function (r) { return r.source; } }
            ]
        },
        {
            key: "ips", table: "tblIps", count: "cntIps",
            empty: "No IP addresses were extracted.",
            columns: [
                { label: "IP", type: "mono", value: function (r) { return r.ip; } },
                { label: "Type", value: function (r) { return r.type; } },
                { label: "Source", value: function (r) { return r.source; } },
                { label: "Classification", value: function (r) { return r.classification; } }
            ]
        },
        {
            key: "urls", table: "tblUrls", count: "cntUrls",
            empty: "No URLs were extracted.",
            columns: [
                { label: "URL", type: "mono", value: function (r) { return r.url; } },
                { label: "Hostname", type: "mono", value: function (r) { return r.hostname; } },
                { label: "Indicators", type: "tags", value: function (r) { return r.indicators; } }
            ]
        },
        {
            key: "domains", table: "tblDomains", count: "cntDomains",
            empty: "No domains were extracted.",
            columns: [
                { label: "Domain", type: "mono", value: function (r) { return r.domain; } },
                { label: "Source", value: function (r) { return r.source; } },
                { label: "Suspicious Indicators", type: "tags", value: function (r) { return r.indicators; } }
            ]
        },
        {
            key: "attachments", table: "tblAttachments", count: "cntAttachments",
            empty: "This email has no attachments.",
            columns: [
                { label: "Filename", type: "mono", value: function (r) { return r.filename; } },
                { label: "MIME Type", type: "mono", value: function (r) { return r.mime_type; } },
                { label: "Size", value: function (r) { return formatSize(r.size); } },
                { label: "SHA-256", type: "mono", value: function (r) { return r.sha256; } }
            ]
        },
        {
            key: "contentFindings", table: "tblContent", count: "cntContent",
            empty: "No content indicators were detected.",
            prepare: function (rows) {   // highest severity first
                return rows.slice().sort(function (a, b) {
                    return SEVERITY_RANK[normalizeSeverity(b.severity)] -
                           SEVERITY_RANK[normalizeSeverity(a.severity)];
                });
            },
            columns: [
                { label: "Detected Indicator", value: function (r) { return r.indicator; } },
                { label: "Evidence", value: function (r) { return r.evidence; } },
                { label: "Severity", type: "severity", value: function (r) { return r.severity; } }
            ]
        },
        {
            key: "iocs", table: "tblIocs", count: "cntIocs",
            empty: "No indicators of compromise were detected.",
            columns: [
                { label: "Type", type: "bold", value: function (r) { return r.type; } },
                { label: "Value", type: "mono", value: function (r) { return r.value; } },
                { label: "Source", value: function (r) { return r.source; } }
            ]
        }
    ];

    function renderSections(data) {
        SECTIONS.forEach(function (section) {
            const rows = section.prepare ? section.prepare(data[section.key]) : data[section.key];
            buildTable(document.getElementById(section.table), section.columns, rows, section.empty);
            document.getElementById(section.count).textContent = rows.length;
        });
    }

    // ==========================================================
    // Received path: Server A -> Server B -> Server C -> Recipient
    // ==========================================================
    function serverLabel(index) {
        return index < 26 ? "Server " + String.fromCharCode(65 + index) : "Server " + (index + 1);
    }

    function hopRow(label, value) {
        const row = document.createElement("div");
        row.className = "et-hop-row";

        const l = document.createElement("span");
        l.className = "et-hop-key";
        l.textContent = label;

        const v = document.createElement("span");
        v.className = "et-mono";
        v.textContent = text(value);

        row.appendChild(l);
        row.appendChild(v);
        return row;
    }

    function makeArrow() {
        const arrow = document.createElement("div");
        arrow.className = "et-hop-arrow";
        arrow.setAttribute("aria-hidden", "true");
        arrow.textContent = "\u2193"; // down arrow
        return arrow;
    }

    function renderReceivedPath(hops, recipient) {
        const container = document.getElementById("receivedPath");
        container.replaceChildren();

        if (hops.length === 0) {
            container.appendChild(emptyBox("No Received headers were found, so the delivery path is unavailable."));
            return;
        }

        // Order by hop number if the backend provides it (stable sort keeps original order otherwise)
        const ordered = hops.slice().sort(function (a, b) {
            return (Number(a.hop) || 0) - (Number(b.hop) || 0);
        });

        const chain = document.createElement("div");
        chain.className = "et-hop-chain";

        ordered.forEach(function (hop, i) {
            const node = document.createElement("div");
            node.className = "et-hop";

            const label = document.createElement("div");
            label.className = "et-hop-label";
            label.textContent = serverLabel(i);
            node.appendChild(label);

            const name = document.createElement("div");
            name.className = "et-hop-title et-mono";
            name.textContent = text(hop.by);
            node.appendChild(name);

            node.appendChild(hopRow("Received from", hop.from ?? hop.from_host));
            node.appendChild(hopRow("IP", hop.ip));
            node.appendChild(hopRow("Time", hop.timestamp));

            chain.appendChild(node);
            chain.appendChild(makeArrow());
        });

        const end = document.createElement("div");
        end.className = "et-hop et-hop-end";

        const endLabel = document.createElement("div");
        endLabel.className = "et-hop-label";
        endLabel.textContent = "Recipient";
        end.appendChild(endLabel);

        const endName = document.createElement("div");
        endName.className = "et-hop-title et-mono";
        endName.textContent = text(recipient);
        end.appendChild(endName);

        chain.appendChild(end);
        container.appendChild(chain);
    }

    // ==========================================================
    // Email details, summary cards, risk indicators (Step 4)
    // ==========================================================
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
            riskList.appendChild(emptyBox("No risk indicators were reported for this investigation."));
            return;
        }

        const counts = { high: 0, medium: 0, low: 0, info: 0 };
        risks.forEach(function (r) { counts[normalizeSeverity(r.severity)] += 1; });
        riskBreakdown.textContent =
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

            riskList.appendChild(item);
        });
    }

    function render(data) {
        renderEmailDetails(data);
        renderCards(data);
        renderRisks(data.risks);
        renderReceivedPath(data.receivedPath, data.email.recipient);
        renderSections(data);

        const totalItems = data.headers.length + data.receivedPath.length + data.timeline.length +
                           data.urls.length + data.ips.length + data.domains.length +
                           data.attachments.length + data.contentFindings.length +
                           data.iocs.length + data.risks.length;
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