from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "filename",
    [
        "valid.txt",
        "valid.exe",
        "valid.eml.exe",
        "valid.msg",
        "valid.pdf",
        "valid",
        "valid.eml.txt",
    ],
)
def test_non_eml_extension_rejected(app, upload, db_rows, filename):
    response = upload(filename=filename)
    assert response.status_code == 400
    assert response.get_json() == {"error": "Only .eml files are accepted"}
    assert list(Path(app.config["UPLOAD_FOLDER"]).iterdir()) == []
    assert db_rows("SELECT COUNT(*) AS n FROM investigations")[0]["n"] == 0