# Verification & Portfolio Evidence

This directory holds visual proof and documentation screenshots for the SOAR Phishing Triage system:

1. **`01-local-report.png`**:
   - Terminal output of the Python triage engine (`phish_triage.py`) running across three sample emails in offline mode, showing detected verdict badges, risk scores, trigger reasons, and output report paths.

2. **`02-playbook-designer.png` & `02b-run-history.png`**:
   - Azure Logic App designer view and live run history of `Sentinel-Phishing-Triage-Playbook`, displaying the Sentinel incident trigger, triage variable initialization, sequential entity loop, and successful VirusTotal enrichment with secure credential masking.

3. **`03-incident-comment.png`**:
   - Microsoft Sentinel incident Comments tab showing the automated triage comment posted by the playbook with incident details, verdict, and findings summary.

4. **`04-teams-alert.png`**:
   - Microsoft Teams channel message showing the SOAR Adaptive Card alert with incident metadata, triage verdict, findings summary, and the Open incident button.
