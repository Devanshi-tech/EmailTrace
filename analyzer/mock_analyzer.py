def analyze_email(file_path):
    return {
        "sender": {
            "address": "attacker@example.test",
            "display_name": "Billing Team",
            "domain": "example.test",
        },
        "recipient": {"address": "victim@example.test"},
        "headers": {
            "from": "attacker@example.test",
            "to": "victim@example.test",
            "subject": "Test invoice",
            "message-id": "<test-001@example.test>",
        },
        "received_paths": [
            {
                "hop": 0,
                "from": "mail.example.test",
                "by": "mx.example.test",
                "ip": "192.0.2.10",
            }
        ],
        "ips": [
            {"ip": "192.0.2.10", "hop_index": 0, "source": "received"},
            "203.0.113.5",
        ],
        "timestamps": ["2026-09-29T10:00:00Z"],
        "urls": [
            {
                "url": "http://example.test/invoice",
                "domain": "example.test",
                "suspicious": True,
            }
        ],
        "domains": [
            {
                "domain": "example.test",
                "suspicious": True,
                "reason": "Mock indicator",
            }
        ],
        "attachments": [
            {
                "filename": "invoice.pdf.exe",
                "content_type": "application/octet-stream",
                "size": 1024,
                "sha256": "0" * 64,
                "suspicious": True,
            }
        ],
        "content_analysis": {"urgency_language": True},
        "iocs": [
            {
                "type": "url",
                "value": "http://example.test/invoice",
                "description": "Mock IOC",
                "severity": "medium",
            }
        ],
        "risk_indicators": [
            "mock: double extension attachment",
            "mock: urgency language",
        ],
    }