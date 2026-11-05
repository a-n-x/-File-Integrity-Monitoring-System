# File Integrity Monitoring System (FIMS)

A Python/Flask cybersecurity project for monitoring selected files and directories using SHA-256 hashes, storing baseline and event data in SQLite, and presenting monitoring information through a web dashboard.

## Features in the submitted application

- User login and dashboard
- Register monitored folders
- Generate SHA-256 file baselines
- Compare current file hashes with stored baselines
- Record detected file creation and modification events
- View audit logs and integrity hashes
- Optional VirusTotal, Hybrid Analysis, and NIST NVD lookups

## Technology

Python 3, Flask, SQLite, SHA-256, Requests, HTML/CSS.

## Run locally

1. Install Python 3.10 or newer.
2. Create and activate a virtual environment.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Set environment variables (copy `.env.example` to `.env`, then load the values using your preferred environment-variable tool). Never commit `.env`.
5. Set `FIM_USERNAME`, `FIM_PASSWORD`, and `FLASK_SECRET_KEY` before starting the application.
6. Run:

   ```bash
   python app.py
   ```

7. Open `http://127.0.0.1:5000`.

## Deploy on Render

This repository includes `render.yaml` as a starting point.

1. Push this repository to GitHub.
2. In Render, create a Blueprint or Web Service from the GitHub repository.
3. Configure `FIM_USERNAME` and a strong `FIM_PASSWORD` in Render's environment settings.
4. Add a persistent disk mounted at `/var/data` before relying on SQLite data across deploys/restarts. Without persistent storage, local SQLite data may be lost when the service is replaced.
5. Add API keys only in Render's environment settings if you choose to enable those integrations.
6. Deploy and test the public URL.


## Monitor folders on your Windows computer with the local agent

The hosted Flask service cannot directly read your laptop's `C:\` drive. The optional local agent solves this by scanning folders on your computer and sending **only file paths, SHA-256 hashes, and change-event metadata** to the hosted dashboard over HTTPS. File contents are not uploaded.

1. Commit and push the updated `app.py`, `render.yaml`, `windows_agent.py`, and the new agent files to GitHub. Render should sync and redeploy the Blueprint.
2. In Render, open the FIMS web service → **Environment** and copy the generated `FIM_AGENT_TOKEN` value. Treat it like a password.
3. On Windows, install Python 3.10+ if needed. Download the project files and open Command Prompt in the project folder.
4. Install the agent dependency: `py -m pip install -r requirements-agent.txt`.
5. Copy `agent_config.example.json` to `agent_config.json`.
6. Edit `agent_config.json`: set `dashboard_url` to your exact Render URL, paste the `FIM_AGENT_TOKEN`, and add one or more existing Windows folders. Start with a small test folder you create, such as `C:/Users/Public/Documents/FIMS-Test`.
7. Run `py windows_agent.py`. Keep the terminal open while monitoring.
8. On first run, the agent registers the folder and creates a SHA-256 baseline. Create or edit a test text file inside that folder. Within the next scan interval, check the dashboard's Audit Logs for `FILE_CREATED` or `FILE_MODIFIED`. Delete the test file to verify `FILE_DELETED`.

The agent stores its last-seen hashes in `fims_agent_state.json` on the local computer so it can compare scans. Keep this file with the agent between runs. If you delete it, the next run will establish a fresh local comparison state; existing cloud baseline rows are not automatically overwritten.

**Security and limitations:** Keep `agent_config.json` and `fims_agent_state.json` private; never commit them. Use a dedicated test folder first and do not monitor sensitive folders until you have reviewed the behavior. The free Render filesystem is ephemeral, so cloud-side SQLite records can be lost after service replacement/restarts; this setup is a portfolio/demo deployment, not durable production storage. The agent sends hashes and paths, not file contents.

## Important deployment limitation

The current application runs on the machine where the Flask process is hosted. A cloud deployment cannot directly monitor folders on your personal Windows laptop. In the cloud, it can only access files available to the cloud service. To monitor a personal computer while using a cloud dashboard, the project needs a separate local monitoring agent that securely sends events to the hosted service.

## Scope and known limitations

This repository preserves the submitted application's current monitoring behavior. The current scan implementation detects newly created and modified files; it does not currently record deleted files, despite deletion monitoring being described in the academic report. A production-ready version should implement and test deletion detection, periodic/background scanning, CSRF protection, stronger authentication, and restricted folder access before public use.

## Security

- Do not upload `.env`, API keys, passwords, database files, or personal file paths.
- Use unique strong credentials and a unique Flask secret.
- Treat any credentials previously embedded in source code as exposed and rotate them.
- Do not use this demonstration deployment to monitor sensitive or production data.
