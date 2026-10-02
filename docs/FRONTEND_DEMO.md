# EmailTrace Frontend: Demo Guide and Integration Notes

## Demo script (about 5 minutes)

1. **Home** (`/`): "EmailTrace is an email fraud investigation platform. Seven capabilities are shown here, and the notice reminds users to upload only simulated or authorized evidence."
2. **Upload** (`/upload`): choose a `.eml` file. Point out the filename and size display. Try a `.txt` file to show validation. Upload to show the loading states (Uploading, then Analyzing).
3. **Dashboard** (`/dashboard/<id>`): walk through the email details, the six summary cards, and the risk indicators with four severity levels. Scroll to the Received Path chain (Server A, B, C, Recipient), then the IP, URL, domain, attachment, content and IOC tables.
4. **Analysis** (`/analysis/<id>`): click Re-run Analysis, then show the severity doughnut and the evidence bar chart.
5. **Report** (`/report/<id>`): click Print / Save as PDF and show the clean white print layout and the closing statement.

## Security talking points

- Extracted email content is **untrusted**. It is always written with `textContent` or `createElement`, never `innerHTML`.
- URLs are shown as **plain text**. No clickable links are created from email data.
- The UI never shows a "malicious" verdict. Findings use four severity levels: Informational, Low, Medium, High.
- A Content Security Policy restricts scripts to the same origin.
- Bootstrap and Chart.js are served locally, so there are no third-party requests.
- Upload is limited to `.eml`, non-empty, maximum 10 MB (client-side check; the backend must validate too).

## Pre-demo checklist

- [ ] `static/vendor/` contains the three downloaded files
- [ ] Backend is running and `/api/*` responds
- [ ] A simulated `.eml` test file is ready
- [ ] Browser zoom is at 100%, and the window is wide enough for the desktop layout
- [ ] Disconnect Wi-Fi once to confirm the UI still loads

## Backend integration (for the backend teammate)

### 1. Page routes required

`base.html` calls `url_for('dashboard', investigation_id=None)`, so each investigation page needs **both** routes below or the pages will crash with a `BuildError`.

```python
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload")
def upload():
    return render_template("upload.html")

@app.route("/dashboard", defaults={"investigation_id": None})
@app.route("/dashboard/<investigation_id>")
def dashboard(investigation_id):
    return render_template("dashboard.html", investigation_id=investigation_id)

@app.route("/analysis", defaults={"investigation_id": None})
@app.route("/analysis/<investigation_id>")
def analysis(investigation_id):
    return render_template("analysis.html", investigation_id=investigation_id)

@app.route("/report", defaults={"investigation_id": None})
@app.route("/report/<investigation_id>")
def report(investigation_id):
    return render_template("report.html", investigation_id=investigation_id)
```

### 2. API contract the UI expects

| Call | Used by | Expected result |
|---|---|---|
| `POST /api/upload` (form field `file`) | upload.js | `{"investigation_id": "..."}` or `{"error": "..."}` |
| `POST /api/analyze/<id>` | upload.js, analysis.js | 2xx on success, or `{"error": "..."}` |
| `GET /api/investigation/<id>` | dashboard.js, analysis.js | JSON below |
| `GET /api/investigation/<id>/report` | report.js | Same JSON as above |

```json
{
  "investigation_id": "",
  "analyzed_at": "",
  "status": "completed",
  "email": {"sender": "", "recipient": "", "subject": "", "date": "", "reply_to": "", "return_path": ""},
  "headers": [{"name": "", "value": ""}],
  "received_path": [{"hop": 1, "from": "", "by": "", "ip": "", "timestamp": ""}],
  "timeline": [{"timestamp": "", "event": "", "source": ""}],
  "ips": [{"ip": "", "type": "", "source": "", "classification": ""}],
  "urls": [{"url": "", "hostname": "", "indicators": []}],
  "domains": [{"domain": "", "source": "", "indicators": []}],
  "attachments": [{"filename": "", "mime_type": "", "size": 0, "sha256": ""}],
  "content_findings": [{"indicator": "", "evidence": "", "severity": "low"}],
  "iocs": [{"type": "", "value": "", "source": ""}],
  "risk_indicators": [{"title": "", "severity": "high", "description": ""}]
}
```

Severity values: `info`, `low`, `medium`, `high` (`critical` is displayed as High). Missing lists are treated as empty.

If the backend uses different field names, only the `normalize()` function at the top of `dashboard.js`, `analysis.js` and `report.js` needs changing.