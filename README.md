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

## Important deployment limitation

The current application runs on the machine where the Flask process is hosted. A cloud deployment cannot directly monitor folders on your personal Windows laptop. In the cloud, it can only access files available to the cloud service. To monitor a personal computer while using a cloud dashboard, the project needs a separate local monitoring agent that securely sends events to the hosted service.

## Scope and known limitations

This repository preserves the submitted application's current monitoring behavior. The current scan implementation detects newly created and modified files; it does not currently record deleted files, despite deletion monitoring being described in the academic report. A production-ready version should implement and test deletion detection, periodic/background scanning, CSRF protection, stronger authentication, and restricted folder access before public use.

## Security

- Do not upload `.env`, API keys, passwords, database files, or personal file paths.
- Use unique strong credentials and a unique Flask secret.
- Treat any credentials previously embedded in source code as exposed and rotate them.
- Do not use this demonstration deployment to monitor sensitive or production data.
