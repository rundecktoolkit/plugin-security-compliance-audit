#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ORG="${ORG:-rundecktoolkit}"
REPO="${REPO:-plugin-security-compliance-audit}"
TAG="${TAG:-v1.0.0}"
VERSION="${VERSION:-1.0.0}"
RELEASE_NAME="${RELEASE_NAME:-plugin-security-compliance-audit ${TAG}}"
NOTES_FILE="${NOTES_FILE:-$ROOT_DIR/docs/release-notes-v1.0.0.md}"
SOURCE_JAR="${SOURCE_JAR:-}"
DIST_DIR="$ROOT_DIR/dist"
ASSET_NAME="plugin-security-compliance-audit-${VERSION}.jar"
ASSET_PATH="$DIST_DIR/$ASSET_NAME"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "error: GITHUB_TOKEN is required" >&2
  exit 1
fi

if [[ ! -f "$NOTES_FILE" ]]; then
  echo "error: release notes file not found: $NOTES_FILE" >&2
  exit 1
fi

mkdir -p "$DIST_DIR"

if [[ -n "$SOURCE_JAR" ]]; then
  cp "$SOURCE_JAR" "$ASSET_PATH"
fi

if [[ ! -f "$ASSET_PATH" ]]; then
  echo "error: release asset not found: $ASSET_PATH" >&2
  echo "hint: provide SOURCE_JAR=/path/to/built-plugin.jar" >&2
  exit 1
fi

REPO_API="https://api.github.com/repos/${ORG}/${REPO}"
if ! curl -fsS -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" "$REPO_API" >/dev/null; then
  echo "error: repository ${ORG}/${REPO} does not exist or token cannot access it" >&2
  exit 1
fi

export NOTES_FILE TAG RELEASE_NAME
REL_BODY=$(python3 - <<'PY'
import json
import os
from pathlib import Path

notes = Path(os.environ["NOTES_FILE"]).read_text()
print(json.dumps({
  "tag_name": os.environ["TAG"],
  "name": os.environ["RELEASE_NAME"],
  "body": notes,
  "draft": False,
  "prerelease": False,
}))
PY
)

REL_RESP="$(curl -sS -X POST "${REPO_API}/releases" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -d "$REL_BODY")"

UPLOAD_URL="$(printf "%s" "$REL_RESP" | sed -n 's/.*"upload_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed 's/{?name,label}//')"
if [[ -z "$UPLOAD_URL" ]]; then
  REL_RESP="$(curl -sS "${REPO_API}/releases/tags/${TAG}" \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json")"
  UPLOAD_URL="$(printf "%s" "$REL_RESP" | sed -n 's/.*"upload_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed 's/{?name,label}//')"
fi
if [[ -z "$UPLOAD_URL" ]]; then
  echo "error: could not obtain release upload URL" >&2
  echo "$REL_RESP" >&2
  exit 1
fi

curl -sS -X POST "${UPLOAD_URL}?name=${ASSET_NAME}" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${ASSET_PATH}" >/dev/null

echo "release published: https://github.com/${ORG}/${REPO}/releases/tag/${TAG}"
