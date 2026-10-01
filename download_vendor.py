"""
Downloads Bootstrap and Chart.js into static/vendor/ so EmailTrace
works offline. Run once, then commit the downloaded files.
"""
import pathlib
import urllib.request

BASE = "https://cdn.jsdelivr.net/npm"
FILES = {
    "bootstrap/bootstrap.min.css":
        BASE + "/bootstrap@5.3.3/dist/css/bootstrap.min.css",
    "bootstrap/bootstrap.bundle.min.js":
        BASE + "/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js",
    "chartjs/chart.umd.min.js":
        BASE + "/chart.js@4.4.3/dist/chart.umd.min.js",
}

ROOT = pathlib.Path(__file__).resolve().parent / "static" / "vendor"


def main():
    for relative_path, url in FILES.items():
        destination = ROOT / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        print("Downloading " + relative_path + " ...", end=" ")
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read()
        if len(data) < 10_000:
            raise SystemExit("\nDownload looks incomplete: " + relative_path)
        destination.write_bytes(data)
        print("OK (" + str(round(len(data) / 1024)) + " KB)")
    print("\nDone. Files saved in static/vendor/")


if __name__ == "__main__":
    main()