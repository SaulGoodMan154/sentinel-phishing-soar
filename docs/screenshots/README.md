# Verification & Portfolio Evidence

This directory holds visual proof and documentation screenshots for the SOAR Phishing Triage system:

1. **`01-local-report.png`**:
   - Terminal output of the Python triage engine (`phish_triage.py`) running across three sample emails in offline mode, showing detected verdict badges, risk scores, trigger reasons, and output report paths.

2. **`02-playbook-designer.png`**:
   - Azure Logic App designer view of `Sentinel-Phishing-Triage-Playbook`, displaying the Sentinel incident trigger, triage variable initialization, evaluation scope, incident comment action, and Teams notification condition.

3. **`03-incident-comment.png`**:
   - Microsoft Sentinel incident Comments tab showing the automated triage comment posted by the playbook with incident details, verdict, and findings summary.

4. **`04-teams-alert.png`**:
   - Microsoft Teams channel message showing the SOAR Adaptive Card alert with incident metadata, triage verdict, findings summary, and the Open incident button.
