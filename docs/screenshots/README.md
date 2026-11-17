# Screenshot Placeholders & Portfolio Proof

This directory holds visual proof and documentation screenshots for the SOAR Phishing Triage system:

1. **`01-local-report.png`**:
   - Screenshot of the local Python terminal triage execution (`python phish_triage.py samples/*.eml -o reports`) showing the colorized status output and generated Markdown report.

2. **`02-playbook-designer.png`**:
   - Screenshot of the Azure Logic App Designer in the Azure Portal showing the workflow steps:
     - Incident Trigger
     - VirusTotal Enrichment
     - Sentinel Incident Comment
     - Microsoft Teams Adaptive Card Action

3. **`03-incident-comment.png`**:
   - Screenshot of a Microsoft Sentinel incident activity log showing the automated triage comment posted by the Logic App playbook.

4. **`04-teams-alert.png`**:
   - Screenshot of the Microsoft Teams channel showing the Adaptive Card triage notification with verdict, severity, and defanged indicators.
