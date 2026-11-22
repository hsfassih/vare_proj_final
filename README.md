# Malware Analyzer

Malware Analyzer is a Python/Flask web application for inspecting Windows portable executable (PE) files. It combines:

- Static PE analysis using `pefile`
- EMBER-based malware scoring through `static_model.txt`
- VirusTotal hash lookup and upload support
- Random Forest malware-family classification
- Optional dynamic analysis using Procmon, Noriben, and Regshot
- Web pages for uploads, analysis results, risk indicators, and model visualizations

The application currently targets Windows, especially for dynamic analysis.

## Requirements

- Windows 10/11 or a Windows VM
- Python 3.13 (matching the included Azure deployment workflow)
- Internet access for VirusTotal queries
- Optional VirusTotal API key
- Optional Azure Monitor/OpenTelemetry configuration

Do not run malware samples on a production or personal workstation. Dynamic analysis should be performed only inside an isolated disposable Windows VM with networking disabled or strictly controlled.

## Setup

### 1. Clone the repository

```powershell
git clone https://github.com/hs-fassih/vare_proj_final.git
cd vare_proj_final
```

### 2. Create and activate a virtual environment

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell prevents activation, allow scripts for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Verify required model and tool files

The repository should contain:

- `static_model.txt` for static EMBER-style scoring
- `malware_family_classifier.pkl` for family classification
- `Procmon.exe` and/or `Procmon64.exe` for dynamic analysis
- `Noriben.py`
- `Regshot_cmd-x64-ANSI.exe`

Keep these files in the project root. Static analysis requires `static_model.txt`.

### 5. Configure API and application values

Before running the application:

1. Open `app.py`.
2. Replace `VIRUSTOTAL_API_KEY` with your own VirusTotal API key.
3. Replace `app.config['SECRET_KEY']` with a random Flask secret key.

Never commit real API keys or secret keys to source control.

Azure Monitor telemetry is optional. The application will start even when telemetry is unavailable.

### 6. Start the application

```powershell
python app.py
```

Open `http://127.0.0.1:5000/` in a browser.

Flask runs in debug mode by default when started through `app.py`. Do not use the debug server for an internet-facing production deployment.

## Using the Analyzer

1. Open the home page.
2. Upload a supported file: `.exe`, `.dll`, `.sys`, `.scr`, `.ocx`, or `.cpl`.
3. Review static analysis results, including PE headers, sections, imports, entropy, resources, strings, and the malware score.
4. VirusTotal results are included when a report is available or an upload completes successfully.
5. If dynamic tools are installed and `Procmon` is available, start dynamic analysis from the result workflow.

Dynamic analysis launches the submitted executable and captures behavior. Only upload samples in a dedicated malware-analysis environment.

## Model Training

The included training script reads `training.csv` and `test.csv`, trains a Random Forest classifier, and writes:

- `malware_family_classifier.pkl`
- `confusion_matrix.png`
- `feature_importance.png`

Run:

```powershell
python malware_classifier.py
```

The script maps model labels to `Trojan`, `Ransomware`, `RAT`, and `Worm`.

## Azure Deployment

The repository includes a GitHub Actions workflow for building and deploying to Azure App Service staging. The workflow:

- Uses Python 3.13
- Creates a virtual environment
- Installs `requirements.txt`
- Uploads the application as a deployment artifact

Deployment requires the Azure federated-identity credentials and App Service secrets configured in the GitHub repository.

## Important Notes

- Results are advisory and should not be treated as a definitive malware verdict.
- Static and dynamic analysis both require complete and compatible model/tool files.
- Uploaded files are stored temporarily in the system temporary directory and removed after static analysis.
- Dynamic analysis output is written to `OUTPUT/`.
- Running unknown executables can modify files and the Windows registry or make network connections.
