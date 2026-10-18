# TraceLens — Log-Based Incident Investigation

TraceLens is a local incident investigation tool that analyzes application logs, identifies errors and configuration changes, selects supporting evidence, and generates an investigation report using a locally running language model.

## Features

- **Log parsing:** Extracts timestamps, severity levels, services, event names, and event details.
- **Incident analysis:** Summarizes errors, configuration changes, timelines, and warnings preceding errors.
- **Local LLM investigation:** Uses Ollama to generate possible explanations and recommended investigation steps.
- **Evidence selection:** Selects relevant log entries and associates them with source line numbers.
- **Report validation:** Checks cited events and field values against parsed source logs.
- **Web interface:** Provides a browser-based interface for submitting logs and reviewing reports.

## Technology Stack

- Python
- FastAPI
- Ollama
- HTML, CSS, JavaScript
- pytest

## Prerequisites

- Python installed
- Ollama installed and running
- A compatible local model downloaded in Ollama

## Setup

Clone the repository and enter the project directory:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd System_failure_invest_agent
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the required packages used by the project:

```powershell
pip install fastapi uvicorn requests pydantic pandas scikit-learn pytest python-multipart jinja2
```

Make sure Ollama is running and your configured model is available locally.

## Run the Application

```powershell
python -m uvicorn src.app:app --reload
```

Open http://127.0.0.1:8000 in your browser.

## Run Tests

```powershell
python -m pytest -v
```

## Sample Data and Outputs

- `data/` contains sample incident logs and example reports.
- `Sample_outputs/` contains example investigation reports.
- `test_report_validator.py` tests evidence-validation behavior.
- `test_ollama.py` tests local Ollama connectivity.

## Limitations

TraceLens generates investigative hypotheses, not guaranteed root causes. Temporal correlation and verified log evidence do not independently establish causation. Review recommendations and supporting evidence before drawing operational conclusions.

## Project Status

Developed as a local software incident investigation project.
