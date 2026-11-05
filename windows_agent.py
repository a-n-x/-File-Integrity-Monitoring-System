"""FIMS Windows/local monitoring agent.

Polls configured folders, computes SHA-256 hashes, and sends only paths,
hashes, and change metadata to the FIMS dashboard over HTTPS.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

import requests

CONFIG_PATH = Path(__file__).with_name("agent_config.json")
STATE_PATH = Path(__file__).with_name("fims_agent_state.json")


def sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def scan_folder(folder: Path) -> dict:
    current = {}
    for root, dirs, files in os.walk(folder, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
        for filename in files:
            path = Path(root) / filename
            if path.is_symlink() or not path.is_file():
                continue
            digest = sha256_file(path)
            if digest:
                current[str(path.resolve())] = digest
    return current


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"Warning: could not read {path.name}; starting with empty state.")
        return default


def save_state(state: dict):
    temp = STATE_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temp.replace(STATE_PATH)


def main():
    if not CONFIG_PATH.exists():
        print("Missing agent_config.json. Copy agent_config.example.json to agent_config.json and edit it.")
        return 1

    config = load_json(CONFIG_PATH, {})
    dashboard_url = str(config.get("dashboard_url", "")).strip().rstrip("/")
    token = str(config.get("agent_token", "")).strip()
    folders = config.get("folders", [])
    interval = max(5, int(config.get("scan_interval_seconds", 10)))

    if not dashboard_url.startswith("https://"):
        print("dashboard_url must begin with https://")
        return 1
    if len(token) < 32:
        print("agent_token is missing or too short. Copy FIM_AGENT_TOKEN from Render Environment.")
        return 1
    if not isinstance(folders, list) or not folders:
        print("Add at least one folder path to the folders list in agent_config.json.")
        return 1

    valid_folders = []
    for value in folders:
        folder = Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()
        if folder.is_dir():
            valid_folders.append(folder)
        else:
            print(f"Skipping unavailable folder: {folder}")
    if not valid_folders:
        print("No valid folders found. Check the folder paths in agent_config.json.")
        return 1

    state = load_json(STATE_PATH, {"version": 1, "folders": {}})
    state.setdefault("folders", {})
    endpoint = dashboard_url + "/api/agent/sync"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print("FIMS local agent started. Press Ctrl+C to stop.")
    print("Only file paths, SHA-256 hashes, and event metadata are sent; file contents stay on this computer.")

    try:
        while True:
            payload_folders = []
            payload_events = []
            pending_updates = {}

            for folder in valid_folders:
                folder_key = str(folder)
                current = scan_folder(folder)
                previous = state["folders"].get(folder_key)

                if previous is None:
                    baseline = [{"path": path, "sha256": digest} for path, digest in current.items()]
                    payload_folders.append({"path": folder_key, "baseline_files": baseline})
                    print(f"Baseline queued: {folder_key} ({len(current)} files)")
                else:
                    old = previous
                    for path, digest in current.items():
                        if path not in old:
                            payload_events.append({"event_type": "FILE_CREATED", "file_path": path,
                                "details": f"New file detected by local agent. SHA-256: {digest}"})
                        elif old[path] != digest:
                            payload_events.append({"event_type": "FILE_MODIFIED", "file_path": path,
                                "details": f"SHA-256 changed from {old[path]} to {digest}"})
                    for path, old_digest in old.items():
                        if path not in current:
                            payload_events.append({"event_type": "FILE_DELETED", "file_path": path,
                                "details": f"Previously monitored file is missing. Previous SHA-256: {old_digest}"})
                    payload_folders.append({"path": folder_key, "baseline_files": []})

                pending_updates[folder_key] = current

            try:
                response = requests.post(endpoint, headers=headers,
                    json={"folders": payload_folders, "events": payload_events}, timeout=30)
                if response.status_code == 200:
                    result = response.json()
                    state["folders"].update(pending_updates)
                    save_state(state)
                    if payload_events:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Uploaded {result.get('events_recorded', 0)} event(s).")
                    else:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sync OK; no changes detected.")
                else:
                    print(f"Server returned {response.status_code}: {response.text[:300]}")
            except requests.RequestException as exc:
                print(f"Could not reach FIMS dashboard: {exc}")

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nFIMS local agent stopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
