"""
Attachment analysis for the EmailTrace forensics engine.

analyze_attachments(parsed, result) -> fills result["attachments"] and adds
                                       attachment indicators
sniff_type(data)                    -> file type from leading signature bytes

Principles:
- Attachments are byte strings in memory. They are hashed with SHA-256 and
  their first bytes are compared with a few well-known signatures. They are
  never written to disk, opened as a program, extracted or executed.
- Archives are not opened. An encrypted ZIP is recognised from one header bit.
- Indicators describe static facts about the name and content. They are
  evidence for an investigator, not a verdict, and each one lists ordinary
  reasons it can occur.
- Frontends should escape filenames when displaying them. A raw name can
  contain characters that reorder the text shown on screen.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from .email_parser import ParsedEmail
from .schema import make_attachment_record, make_indicator

MAX_ATTACHMENTS = 200
EVIDENCE_LIMIT = 5
PADDING_SPACES = 5

EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "msi", "msp", "jar", "lnk", "cpl", "reg",
    "sh", "chm", "url",
}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "ppam", "xlam", "sldm"}
ARCHIVE_EXTENSIONS = {
    "zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "iso", "img", "cab", "ace", "arj",
}
# Extensions whose files are ZIP containers but are not archives in the usual sense.
ZIP_CONTAINER_EXTENSIONS = {
    "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "dotm", "xlsb",
    "odt", "ods", "odp", "jar", "apk", "epub",
}
# Harmless-looking extensions that are often placed before a real one.
DECOY_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif",
}
TEXT_EXTENSIONS = {"txt", "csv", "html", "htm", "xml", "json", "log"}

EXECUTABLE_TYPES = {"pe", "elf"}
TYPE_LABELS = {
    "pe": "Windows executable (PE)", "elf": "Linux executable (ELF)", "pdf": "PDF",
    "zip": "ZIP container", "ole": "legacy Office (OLE)", "png": "PNG image",
    "jpeg": "JPEG image", "gif": "GIF image", "rar": "RAR archive",
    "7z": "7-Zip archive", "gzip": "gzip data", "rtf": "RTF document",
}

# extension -> content types that are normal for it
EXT_EXPECTED: Dict[str, frozenset] = {
    "pdf": frozenset({"pdf"}),
    "png": frozenset({"png"}),
    "jpg": frozenset({"jpeg"}), "jpeg": frozenset({"jpeg"}),
    "gif": frozenset({"gif"}),
    "zip": frozenset({"zip"}),
    "rar": frozenset({"rar"}), "7z": frozenset({"7z"}), "gz": frozenset({"gzip"}),
    "rtf": frozenset({"rtf"}),
    "exe": frozenset({"pe"}), "dll": frozenset({"pe"}), "scr": frozenset({"pe"}),
    # Word, Excel and PowerPoint files are legitimately either OLE, ZIP or (Word) RTF
    "doc": frozenset({"ole", "zip", "rtf"}), "xls": frozenset({"ole", "zip"}),
    "ppt": frozenset({"ole", "zip"}),
}
for _ext in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp"):
    EXT_EXPECTED[_ext] = frozenset({"zip"})

MIME_EXPECTED: Dict[str, frozenset] = {
    "application/pdf": frozenset({"pdf"}),
    "image/png": frozenset({"png"}),
    "image/jpeg": frozenset({"jpeg"}), "image/jpg": frozenset({"jpeg"}),
    "image/gif": frozenset({"gif"}),
    "application/zip": frozenset({"zip"}),
    "application/x-zip-compressed": frozenset({"zip"}),
    "application/x-msdownload": frozenset({"pe"}),
    "application/x-dosexec": frozenset({"pe"}),
    "application/rtf": frozenset({"rtf"}), "text/rtf": frozenset({"rtf"}),
    "application/msword": frozenset({"ole", "zip", "rtf"}),
    "application/vnd.ms-excel": frozenset({"ole", "zip"}),
    "application/vnd.ms-powerpoint": frozenset({"ole", "zip"}),
}
OPENXML_PREFIX = "application/vnd.openxmlformats-officedocument."

_SIGNATURES = (
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"{\\rtf", "rtf"),
    (b"\x7fELF", "elf"),
)

_BIDI_CHARS = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# (flag, indicator title, severity, explanation). Order = order of indicators.
FLAG_RULES = [
    ("masquerading_executable", "Executable content under a non-executable file name", "high",
     "The first bytes identify a program file, but the name suggests a different "
     "kind of file. Mislabelled content is worth examining before anything is opened."),
    ("executable_extension", "Attachment has an executable or script file type", "medium",
     "These file types can run code when opened. Mail gateways often block them, "
     "and some organisations send them on purpose."),
    ("double_extension", "Attachment name has a document extension before an executable one", "medium",
     "A name such as invoice.pdf.exe can look like a document when extensions are hidden."),
    ("encrypted_archive", "Attachment is an encrypted ZIP archive", "medium",
     "The contents cannot be inspected by scanners without the password. "
     "Password-protected archives are also used for ordinary confidential files."),
    ("macro_enabled_document", "Attachment is a macro-enabled Office document", "medium",
     "Macros run code when the recipient enables them. Many business documents "
     "use macros legitimately. The file was not opened."),
    ("content_type_mismatch", "File content does not match the file extension", "medium",
     "The leading bytes identify a different file type than the extension "
     "implies. Renamed or mis-saved files also cause this."),
    ("bidi_or_control_characters", "Attachment name contains direction-control or control characters", "medium",
     "Direction-override characters can make a name display in a different "
     "order than it is stored, hiding the real extension. Names are shown escaped here."),
    ("declared_mime_mismatch", "Declared MIME type does not match file content", "low",
     "The Content-Type header names one kind of file and the leading bytes "
     "suggest another. Some mail software labels files imprecisely."),
    ("archive", "Attachment is an archive", "low",
     "Archives can carry other files. Their contents are not opened or inspected "
     "by this engine."),
    ("padded_filename", "Attachment name is padded with spaces or trailing dots", "low",
     "Long runs of spaces can push a real extension out of view in file lists."),
    ("path_in_filename", "Attachment name contains a path separator", "low",
     "File names normally do not include folders. Software that saves attachments "
     "should strip any path."),
    ("missing_filename", "Attachment has no file name", "info",
     "Some mail software omits names. The MIME type and hash are still recorded."),
    ("attached_message", "An email message is attached", "info",
     "The attached message is hashed but not analyzed recursively."),
]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _has_pe_header(data: bytes) -> bool:
    if len(data) < 68 or data[:2] != b"MZ":
        return False
    offset = int.from_bytes(data[60:64], "little")
    return 64 <= offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\x00\x00"


def sniff_type(data: bytes) -> Optional[str]:
    """Identify a file type from its leading bytes, or return None."""
    if _has_pe_header(data):
        return "pe"
    for signature, name in _SIGNATURES:
        if data.startswith(signature):
            return name
    return None


def _extensions(filename: str) -> List[str]:
    """Extensions after the first dot, lowercase, with padding removed."""
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    base = base.strip().rstrip(". ")
    return [part.strip() for part in base.lower().split(".")[1:] if part.strip()]


def _safe_name(filename: str) -> str:
    """Filename for display: control and direction characters shown as escapes."""
    return "".join(
        f"\\u{ord(c):04x}" if c in _BIDI_CHARS or ord(c) < 32 else c for c in filename
    )


def _expected_for_mime(mime: Optional[str]) -> Optional[frozenset]:
    if not mime:
        return None
    if mime.startswith(OPENXML_PREFIX):
        return frozenset({"zip"})
    return MIME_EXPECTED.get(mime)


# --------------------------------------------------------------------------
# Single attachment analysis
# --------------------------------------------------------------------------

def _analyze_one(item: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    payload: bytes = item.get("payload") or b""
    filename: Optional[str] = item.get("filename")
    mime = (item.get("mime_type") or "").lower() or None
    disposition = item.get("content_disposition")

    detected = sniff_type(payload)
    exts = _extensions(filename) if filename else []
    ext = exts[-1] if exts else ""
    flags: List[str] = []
    notes: Dict[str, str] = {}

    def flag(name: str, note: str) -> None:
        flags.append(name)
        notes[name] = note

    if filename:
        if detected in EXECUTABLE_TYPES and ext not in EXECUTABLE_EXTENSIONS:
            shown = f"named .{ext}" if ext else "with no extension"
            flag("masquerading_executable",
                 f"content starts with a {TYPE_LABELS[detected]} signature but the file is {shown}")
        elif detected is not None and (
            (ext in EXT_EXPECTED and detected not in EXT_EXPECTED[ext])
            or (ext in TEXT_EXTENSIONS)
        ):
            flag("content_type_mismatch",
                 f"extension .{ext}, content looks like {TYPE_LABELS[detected]}")

        if ext in EXECUTABLE_EXTENSIONS:
            flag("executable_extension", f"extension .{ext}")
        if len(exts) >= 2 and ext in EXECUTABLE_EXTENSIONS and exts[-2] in DECOY_EXTENSIONS:
            flag("double_extension", f"extensions .{exts[-2]}.{ext}")
        if ext in MACRO_EXTENSIONS:
            flag("macro_enabled_document", f"extension .{ext}")

        odd = sorted({f"U+{ord(c):04X}" for c in filename if c in _BIDI_CHARS or ord(c) < 32})
        if odd:
            flag("bidi_or_control_characters", "characters " + ", ".join(odd))
        if re.search(r" {%d,}" % PADDING_SPACES, filename):
            flag("padded_filename", f"{PADDING_SPACES} or more consecutive spaces")
        elif filename != filename.rstrip(". "):
            flag("padded_filename", "trailing spaces or dots")
        if "/" in filename or "\\" in filename:
            flag("path_in_filename", "name contains / or \\")
    elif disposition == "attachment" and mime != "message/rfc822":
        flag("missing_filename", "no filename in Content-Disposition or Content-Type")

    if detected == "zip" and payload.startswith(b"PK\x03\x04") and len(payload) >= 8 \
            and payload[6] & 0x01:
        flag("encrypted_archive", "ZIP header marks the entry as encrypted")
    if ext in ARCHIVE_EXTENSIONS or detected in {"rar", "7z", "gzip"} or (
        detected == "zip" and ext not in ZIP_CONTAINER_EXTENSIONS
    ):
        flag("archive", f"extension .{ext}" if ext in ARCHIVE_EXTENSIONS
             else f"content looks like {TYPE_LABELS[detected]}")

    expected = _expected_for_mime(mime)
    if expected and detected is not None and detected not in expected:
        flag("declared_mime_mismatch",
             f"declared {mime}, content looks like {TYPE_LABELS[detected]}")
    if mime == "message/rfc822":
        flag("attached_message", "message/rfc822 part")

    record = make_attachment_record(
        filename=filename,
        mime_type=mime,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        content_disposition=disposition,
        extension=ext or None,
        detected_type=detected,
        flags=flags,
    )
    return record, notes


# --------------------------------------------------------------------------
# Indicators
# --------------------------------------------------------------------------

def _build_indicators(
    records: List[Dict[str, Any]], notes: Dict[Tuple[int, str], str]
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for flag, title, severity, explanation in FLAG_RULES:
        matches = [(i, r) for i, r in enumerate(records) if flag in r["flags"]]
        if not matches:
            continue
        shown = []
        for index, rec in matches[:EVIDENCE_LIMIT]:
            name = _safe_name(rec["filename"]) if rec["filename"] else "(no name)"
            entry = (f"{name} ({rec['mime_type'] or 'unknown type'}, "
                     f"{rec['size_bytes']} bytes, sha256 {rec['sha256'][:16]}...)")
            note = notes.get((index, flag))
            if note:
                entry += f" [{note}]"
            shown.append(entry)
        evidence = f"{len(matches)} attachment(s): " + "; ".join(shown)
        if len(matches) > len(shown):
            evidence += f"; and {len(matches) - len(shown)} more"
        out.append(make_indicator(title, severity, f"{evidence}. {explanation}", "attachment"))
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_attachments(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Hash and statically inspect every attachment. Nothing is opened or run."""
    records: List[Dict[str, Any]] = []
    notes: Dict[Tuple[int, str], str] = {}

    for index, item in enumerate(parsed.attachments[:MAX_ATTACHMENTS]):
        record, item_notes = _analyze_one(item)
        records.append(record)
        for flag, note in item_notes.items():
            notes[(index, flag)] = note

    if len(parsed.attachments) > MAX_ATTACHMENTS:
        result["headers"]["meta"]["warnings"].append(
            f"Attachment list capped at {MAX_ATTACHMENTS}; "
            f"{len(parsed.attachments) - MAX_ATTACHMENTS} more attachments ignored"
        )

    result["attachments"] = records
    result["risk_indicators"].extend(_build_indicators(records, notes))