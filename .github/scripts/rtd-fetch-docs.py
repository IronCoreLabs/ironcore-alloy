"""Download pre-built docs HTML from a GitHub Actions artifact.

Used by ReadTheDocs build commands (.readthedocs.yaml).
Requires GITHUB_TOKEN, READTHEDOCS_GIT_COMMIT_HASH, and READTHEDOCS_OUTPUT
environment variables.
"""

import json
import os
import subprocess
import sys
import zipfile

REPO = "IronCoreLabs/ironcore-alloy"

commit = os.environ.get("READTHEDOCS_GIT_COMMIT_HASH")
token = os.environ.get("GITHUB_TOKEN")
output = os.environ.get("READTHEDOCS_OUTPUT")

if not commit or not token or not output:
    print("Missing required environment variables", file=sys.stderr)
    sys.exit(1)

artifact_name = f"docs-html-{commit}"
api_url = f"https://api.github.com/repos/{REPO}/actions/artifacts?name={artifact_name}"
headers = ["-H", f"Authorization: Bearer {token}"]

# Find the artifact
result = subprocess.run(
    ["curl", "-sf"] + headers + [api_url],
    capture_output=True, text=True
)
if result.returncode != 0:
    print(f"Failed to query GitHub API: {result.stderr}", file=sys.stderr)
    sys.exit(1)

data = json.loads(result.stdout)
artifacts = data.get("artifacts", [])
if not artifacts:
    print(f"No artifact found named {artifact_name}", file=sys.stderr)
    sys.exit(1)

download_url = artifacts[0]["archive_download_url"]

# Download the zip
zip_path = "/tmp/docs.zip"
result = subprocess.run(
    ["curl", "-sfL"] + headers + [download_url, "-o", zip_path],
    capture_output=True, text=True
)
if result.returncode != 0:
    print(f"Failed to download artifact: {result.stderr}", file=sys.stderr)
    sys.exit(1)

# Extract to RTD output
html_dir = os.path.join(output, "html")
os.makedirs(html_dir, exist_ok=True)
with zipfile.ZipFile(zip_path) as zf:
    zf.extractall(html_dir)

print(f"Docs extracted to {html_dir}")
