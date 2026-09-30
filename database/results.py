import ipaddress
import json
import logging
import re
import unicodedata
from urllib.parse import urlsplit

from database.database import CHILD_TABLES, get_db

logger = logging.getLogger(__name__)

SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
NOW_SQL = "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"
INSERT_COLUMNS = {table: columns + ("raw_json",) for table, columns in CHILD_TABLES.items()}
NOT_STORED = object()


def _text(value, limit=2048):
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        ch for ch in value if unicodedata.category(ch) not in {"Cc", "Cs"}
    ).strip()
    if not cleaned:
        return None
    return cleaned[:limit]


def _flag(value):
    return 1 if value is True else 0


def _count(value):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _raw(item):
    return json.dumps(item)


def _as_fields(item, key):
    if isinstance(item, str):
        return {key: item}
    if isinstance(item, dict):
        return item
    return None


def _domain_from_url(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _ioc_row(item):
    fields = _as_fields(item, "value")
    if fields is None:
        return None
    value = _text(fields.get("value"))
    if value is None:
        return None
    return (
        _text(fields.get("type"), 255),
        value,
        _text(fields.get("description")),
        _text(fields.get("severity"), 255),
        _raw(item),
    )


def _url_row(item):
    fields = _as_fields(item, "url")
    if fields is None:
        return None
    url = _text(fields.get("url"), 8192)
    if url is None:
        return None
    domain = _text(fields.get("domain"), 255) or _domain_from_url(url)
    return (
        url,
        domain.lower() if domain else None,
        _flag(fields.get("suspicious")),
        _raw(item),
    )


def _ip_row(item):
    fields = _as_fields(item, "ip")
    if fields is None:
        return None
    candidate = _text(fields.get("ip"), 64)
    if candidate is None:
        return None
    try:
        address = str(ipaddress.ip_address(candidate))
    except ValueError:
        return None
    return (
        address,
        _count(fields.get("hop_index")),
        _text(fields.get("source"), 255),
        _raw(item),
    )


def _attachment_row(item):
    if not isinstance(item, dict):
        return None
    filename = _text(item.get("filename"), 255)
    digest = item.get("sha256")
    sha256 = (
        digest.lower()
        if isinstance(digest, str) and SHA256_PATTERN.fullmatch(digest)
        else None
    )
    if filename is None and sha256 is None:
        return None
    return (
        filename,
        _text(item.get("content_type"), 255),
        _count(item.get("size")),
        sha256,
        _flag(item.get("suspicious")),
        _raw(item),
    )


def _domain_row(item):
    fields = _as_fields(item, "domain")
    if fields is None:
        return None
    domain = _text(fields.get("domain"), 255)
    if domain is None:
        return None
    if not _flag(fields.get("suspicious")):
        return NOT_STORED
    return (domain.lower(), _text(fields.get("reason")), _raw(item))


SOURCES = (
    ("ips", "ip_addresses", _ip_row),
    ("urls", "urls", _url_row),
    ("attachments", "attachments", _attachment_row),
    ("domains", "suspicious_domains", _domain_row),
    ("iocs", "iocs", _ioc_row),
)


def build_rows(result):
    rows = {table: [] for table in CHILD_TABLES}
    skipped = 0
    for key, table, builder in SOURCES:
        for index, item in enumerate(result.get(key, [])):
            row = builder(item)
            if row is None:
                skipped += 1
                logger.warning("Skipped malformed element %d in '%s'", index, key)
            elif row is not NOT_STORED:
                rows[table].append(row)
    return rows, skipped


def claim_for_analysis(investigation_id):
    db = get_db()
    cursor = db.execute(
        "UPDATE investigations SET status = 'analyzing', error_message = NULL, "
        f"updated_at = {NOW_SQL} WHERE id = ? AND status != 'analyzing'",
        (investigation_id,),
    )
    db.commit()
    return cursor.rowcount == 1


def get_stored_filename(investigation_id):
    row = get_db().execute(
        "SELECT stored_filename FROM evidence WHERE investigation_id = ?",
        (investigation_id,),
    ).fetchone()
    return row["stored_filename"] if row else None


def save_results(investigation_id, result, rows):
    db = get_db()
    try:
        for table in CHILD_TABLES:
            db.execute(
                f"DELETE FROM {table} WHERE investigation_id = ?", (investigation_id,)
            )
        db.execute(
            "DELETE FROM analysis_results WHERE investigation_id = ?", (investigation_id,)
        )
        db.execute(
            "INSERT INTO analysis_results (investigation_id, result_json) VALUES (?, ?)",
            (investigation_id, json.dumps(result)),
        )
        for table, table_rows in rows.items():
            columns = INSERT_COLUMNS[table]
            placeholders = ", ".join("?" * (len(columns) + 1))
            db.executemany(
                f"INSERT INTO {table} (investigation_id, {', '.join(columns)}) "
                f"VALUES ({placeholders})",
                [(investigation_id, *row) for row in table_rows],
            )
        db.execute(
            "UPDATE investigations SET status = 'completed', error_message = NULL, "
            f"analyzed_at = {NOW_SQL}, updated_at = {NOW_SQL} WHERE id = ?",
            (investigation_id,),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def mark_failed(investigation_id, message):
    db = get_db()
    db.execute(
        "UPDATE investigations SET status = 'failed', error_message = ?, "
        f"updated_at = {NOW_SQL} WHERE id = ?",
        (message, investigation_id),
    )
    db.commit()


def recover_interrupted_analyses():
    db = get_db()
    cursor = db.execute(
        "UPDATE investigations SET status = 'failed', "
        f"error_message = 'Analysis was interrupted', updated_at = {NOW_SQL} "
        "WHERE status = 'analyzing'"
    )
    db.commit()
    return cursor.rowcount