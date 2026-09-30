from io import BytesIO
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def make_file(content=b"hello world", filename="test.txt"):
    return {
        "file": (
            filename,
            BytesIO(content),
            "text/plain",
        )
    }


def fake_clamav_clean(file_path):
    return {
        "available": True,
        "detected": False,
        "scanner": "ClamAV",
        "return_code": 0,
        "message": "No known malware detected.",
    }


def fake_yara_clean(file_path, rules_path):
    return {
        "available": True,
        "detected": False,
        "matches": [],
        "scanner": "YARA",
        "message": "No configured YARA rules matched.",
    }


def fake_clamav_detected(file_path):
    return {
        "available": True,
        "detected": True,
        "scanner": "ClamAV",
        "return_code": 1,
        "message": "Test-Malware FOUND",
    }


def fake_yara_detected(file_path, rules_path):
    return {
        "available": True,
        "detected": True,
        "matches": ["Test_Rule"],
        "scanner": "YARA",
        "message": "YARA rules matched suspicious patterns.",
    }


def test_root():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["message"] == "File Safety Analyzer backend is running."
    assert "version" in data


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert "version" in data


def test_analyze_txt_file():
    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ):
        response = client.post(
            "/analyze",
            files=make_file(
                b"This is a harmless text file.",
                "safe.txt",
            ),
        )

    assert response.status_code == 200

    data = response.json()

    assert data["filename"] == "safe.txt"
    assert data["size"] > 0
    assert len(data["sha256"]) == 64
    assert data["mime_type"] == "text/plain"
    assert data["risk_level"] == "LOW"
    assert data["malware_detection"]["detected"] is False
    assert data["malware_detection"]["clamav"]["available"] is True
    assert data["malware_detection"]["yara"]["available"] is True


def test_empty_file():
    response = client.post(
        "/analyze",
        files=make_file(
            b"",
            "empty.txt",
        ),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded file is empty."


def test_missing_filename():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "",
                BytesIO(b"hello"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 422


def test_large_file():
    large_content = b"A" * (20 * 1024 * 1024 + 1)

    response = client.post(
        "/analyze",
        files=make_file(
            large_content,
            "large.txt",
        ),
    )

    assert response.status_code == 413
    assert "20 MB" in response.json()["detail"]


def test_executable_extension_gets_risk():
    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ), patch(
        "backend.main.magic.from_file",
        return_value="application/x-dosexec",
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "danger.exe",
                    BytesIO(b"MZ" + b"\x00" * 100),
                    "application/octet-stream",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] >= 40
    assert data["risk_level"] in {"MEDIUM", "HIGH"}
    assert data["extension_mismatch"] is False


def test_extension_mismatch():
    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ), patch(
        "backend.main.magic.from_file",
        return_value="application/pdf",
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "fake.txt",
                    BytesIO(b"%PDF-1.7\nfake pdf"),
                    "text/plain",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["extension_mismatch"] is True
    assert data["risk_score"] >= 30


def test_valid_pdf():
    pdf_content = b"%PDF-1.7\nThis is a test PDF."

    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ), patch(
        "backend.main.magic.from_file",
        return_value="application/pdf",
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "document.pdf",
                    BytesIO(pdf_content),
                    "application/pdf",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["filename"] == "document.pdf"
    assert data["extension_mismatch"] is False
    assert "PDF header is valid." in data["findings"]


def test_invalid_pdf():
    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ), patch(
        "backend.main.magic.from_file",
        return_value="application/pdf",
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "fake.pdf",
                    BytesIO(b"not a real pdf"),
                    "application/pdf",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] >= 30
    assert "PDF header is invalid or missing." in data["findings"]


def test_clean_clamav_result():
    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ):
        response = client.post(
            "/analyze",
            files=make_file(
                b"harmless content",
                "clean.txt",
            ),
        )

    data = response.json()

    assert data["malware_detection"]["detected"] is False
    assert data["malware_detection"]["clamav"]["detected"] is False


def test_clamav_detection():
    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_detected,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ):
        response = client.post(
            "/analyze",
            files=make_file(
                b"test content",
                "suspicious.txt",
            ),
        )

    assert response.status_code == 200

    data = response.json()

    assert data["malware_detection"]["detected"] is True
    assert data["malware_detection"]["clamav"]["detected"] is True
    assert data["risk_score"] >= 90
    assert data["risk_level"] == "HIGH"


def test_yara_detection():
    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_detected,
    ):
        response = client.post(
            "/analyze",
            files=make_file(
                b"suspicious yara test",
                "suspicious.txt",
            ),
        )

    assert response.status_code == 200

    data = response.json()

    assert data["malware_detection"]["detected"] is True
    assert data["malware_detection"]["yara"]["detected"] is True
    assert "Test_Rule" in data["malware_detection"]["yara"]["matches"]
    assert data["risk_score"] >= 20


def test_zip_archive_inspection():
    import zipfile

    zip_buffer = BytesIO()

    with zipfile.ZipFile(
        zip_buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "document.txt",
            "harmless document",
        )

    zip_buffer.seek(0)

    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ), patch(
        "backend.main.magic.from_file",
        return_value="application/zip",
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "archive.zip",
                    zip_buffer,
                    "application/zip",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["archive_file_count"] == 1
    assert data["archive_contains_suspicious_file"] is False


def test_zip_with_suspicious_file():
    import zipfile

    zip_buffer = BytesIO()

    with zipfile.ZipFile(
        zip_buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "payload.exe",
            b"fake executable content",
        )

    zip_buffer.seek(0)

    with patch(
        "backend.main.scan_with_clamav",
        side_effect=fake_clamav_clean,
    ), patch(
        "backend.main.scan_with_yara",
        side_effect=fake_yara_clean,
    ), patch(
        "backend.main.magic.from_file",
        return_value="application/zip",
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "archive.zip",
                    zip_buffer,
                    "application/zip",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["archive_file_count"] == 1
    assert data["archive_contains_suspicious_file"] is True
    assert data["risk_score"] >= 30
    