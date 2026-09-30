/* ==========================================================
   EmailTrace - Upload page logic
   Talks to: POST /api/upload, POST /api/analyze/<id>
   Security: all dynamic text is written with textContent
   (never innerHTML), because file names and server
   messages are treated as untrusted.
   ========================================================== */
(function () {
    "use strict";

    const MAX_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB (change if backend allows more)
    const UPLOAD_FIELD_NAME = "file";        // must match the backend form field name

    const form = document.getElementById("uploadForm");
    const fileInput = document.getElementById("evidenceFile");
    const fileInfo = document.getElementById("fileInfo");
    const fileNameEl = document.getElementById("fileName");
    const fileSizeEl = document.getElementById("fileSize");
    const uploadBtn = document.getElementById("uploadBtn");
    const uploadBtnText = document.getElementById("uploadBtnText");
    const uploadSpinner = document.getElementById("uploadSpinner");
    const resetBtn = document.getElementById("resetBtn");
    const alertArea = document.getElementById("alertArea");

    // ---------- Helpers ----------

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / (1024 * 1024)).toFixed(2) + " MB";
    }

    function clearAlert() {
        alertArea.replaceChildren();
    }

    // type: "success" | "danger" | "info" | "warning"
    function showAlert(type, message) {
        clearAlert();
        const box = document.createElement("div");
        box.className = "alert alert-" + type + " mb-3";
        box.setAttribute("role", "alert");
        box.textContent = message; // safe: textContent
        alertArea.appendChild(box);
    }

    function setLoading(isLoading, label) {
        uploadBtn.disabled = isLoading || !fileInput.files.length;
        fileInput.disabled = isLoading;
        resetBtn.disabled = isLoading;
        uploadSpinner.classList.toggle("d-none", !isLoading);
        uploadBtnText.textContent = isLoading ? label : "Upload Evidence";
    }

    function resetSelection() {
        fileInput.value = "";
        fileInfo.classList.add("d-none");
        fileNameEl.textContent = "";
        fileSizeEl.textContent = "";
        uploadBtn.disabled = true;
    }

    // Returns an error message string, or null if the file is acceptable
    function validateFile(file) {
        if (!file.name.toLowerCase().endsWith(".eml")) {
            return "Invalid file type. Please select a .eml file.";
        }
        if (file.size === 0) {
            return "The selected file is empty.";
        }
        if (file.size > MAX_SIZE_BYTES) {
            return "File is too large (" + formatSize(file.size) + "). Maximum allowed size is " +
                   formatSize(MAX_SIZE_BYTES) + ".";
        }
        return null;
    }

    // Safely parse a JSON response; return {} if body is not JSON
    async function readJson(response) {
        try {
            return await response.json();
        } catch (e) {
            return {};
        }
    }

    function errorMessageFrom(data, response, fallback) {
        const serverMsg = data && (data.error || data.message);
        return serverMsg ? String(serverMsg) : fallback + " (HTTP " + response.status + ")";
    }

    // ---------- Events ----------

    fileInput.addEventListener("change", function () {
        clearAlert();
        const file = fileInput.files[0];

        if (!file) {
            resetSelection();
            return;
        }

        const problem = validateFile(file);
        if (problem) {
            resetSelection();
            showAlert("danger", problem);
            return;
        }

        fileNameEl.textContent = file.name;            // safe: textContent
        fileSizeEl.textContent = formatSize(file.size);
        fileInfo.classList.remove("d-none");
        uploadBtn.disabled = false;
    });

    resetBtn.addEventListener("click", function () {
        clearAlert();
        resetSelection();
    });

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        clearAlert();

        const file = fileInput.files[0];
        if (!file) {
            showAlert("warning", "Please select a .eml file first.");
            return;
        }
        const problem = validateFile(file);
        if (problem) {
            showAlert("danger", problem);
            return;
        }

        try {
            // ---- 1. Upload ----
            setLoading(true, "Uploading...");
            const formData = new FormData();
            formData.append(UPLOAD_FIELD_NAME, file);

            const uploadRes = await fetch("/api/upload", { method: "POST", body: formData });
            const uploadData = await readJson(uploadRes);
            if (!uploadRes.ok) {
                throw new Error(errorMessageFrom(uploadData, uploadRes, "Upload failed"));
            }

            const investigationId = uploadData.investigation_id || uploadData.id; // response key
            if (!investigationId) {
                throw new Error("The server did not return an investigation ID.");
            }

            // ---- 2. Analyze ----
            setLoading(true, "Analyzing evidence...");
            const analyzeRes = await fetch(
                "/api/analyze/" + encodeURIComponent(investigationId),
                { method: "POST" }
            );
            const analyzeData = await readJson(analyzeRes);
            if (!analyzeRes.ok) {
                throw new Error(errorMessageFrom(analyzeData, analyzeRes, "Analysis failed"));
            }

            // ---- 3. Success: go to the dashboard ----
            showAlert("success", "Analysis complete. Investigation ID: " + investigationId +
                                 ". Opening dashboard...");
            const base = form.dataset.dashboardBase; // from url_for('dashboard') in the template
            setTimeout(function () {
                window.location.href = base + "/" + encodeURIComponent(investigationId);
            }, 1000);

        } catch (err) {
            // Network failure or a thrown API error
            const msg = err instanceof TypeError
                ? "Could not reach the server. Please check that the backend is running."
                : err.message;
            showAlert("danger", msg);
            setLoading(false);
        }
    });
})();