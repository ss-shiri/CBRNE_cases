# CBRNE Weekly OSINT Dossier

Automated weekly open-source intelligence (OSINT) dossier generator covering the most significant CBRNE (Chemical, Biological, Radiological, Nuclear, Explosive) safety, regulatory, and security development over the preceding 7 days.

Each weekly case is published in two versions:
1. **English (`index.html`)**
2. **Primary Reporting Language of the Event's Location (`index-native.html`)** with automatic `LTR` / `RTL` directionality.

When a new week runs, the prior week's dossier is moved into `archive/` and indexed in `archive.html`.

## Setup

1. Create a GitHub repository and add the files above.
2. In **Settings → Secrets and variables → Actions**, add `GEMINI_API_KEY`.
3. In **Settings → Pages**, set the source to deploy from the main branch (`/ (root)`).
4. Trigger **Weekly CBRNE OSINT Dossier** manually once via the **Actions** tab to generate the initial issue.
