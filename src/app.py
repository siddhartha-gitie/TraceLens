
import sys
import json
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

# Resolve project directories.
BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from log_parser import parse_log_line
from incident_analyzer import analyze_incident
from investigator import investigate_incident
from report_validator import validate_report

app = FastAPI(title="TraceLens")

app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={},
    )


@app.post("/api/investigate")
async def investigate(
    file: UploadFile | None = File(default=None),
    log_text: str = Form(default=""),
):
    has_file = file is not None and bool(file.filename)
    has_text = bool(log_text.strip())

    if has_file and has_text:
        raise HTTPException(
            status_code=400,
            detail="Choose either a file or pasted logs, not both.",
        )

    if not has_file and not has_text:
        raise HTTPException(
            status_code=400,
            detail="Upload a log file or paste your logs first.",
        )

    if has_file:
        if Path(file.filename).suffix.lower() not in {".log", ".txt"}:
            raise HTTPException(
                status_code=400,
                detail="Upload a .log or .txt file.",
            )

        content = await file.read(MAX_FILE_SIZE + 1)

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File is too large. Maximum size is 5 MB.",
            )

        try:
            log_text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail="The file must use UTF-8 text encoding.",
            ) from exc

        filename = Path(file.filename).name

    else:
        if len(log_text.encode("utf-8")) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Pasted logs exceed the 5 MB limit.",
            )

        filename = "pasted_logs.txt"

    if not log_text.strip():
        raise HTTPException(
            status_code=400,
            detail="The supplied logs are empty.",
        )

    # Parse events while preserving original physical line numbers.
    events = []

    for line_number, line in enumerate(log_text.splitlines(), start=1):
        event = parse_log_line(line)

        if event is not None:
            event["line_number"] = line_number
            events.append(event)

    if not events:
        raise HTTPException(
            status_code=400,
            detail="No supported log entries were found.",
        )

    try:
        analysis = analyze_incident(events)

        # Pass both the analysis and original source events to the LLM.
        report = investigate_incident(analysis, events)

        # Independently validate evidence citations against source events.
        validation = validate_report(report, events)

        return {
            "filename": filename,
            "analysis": json.loads(
                json.dumps(analysis, default=str)
            ),
            "report": report,
            "validation": validation,
        }

    except HTTPException:
        raise

    except Exception as exc:
        # Keep the detailed exception in the terminal for debugging.
        print(
            f"Investigation failed: "
            f"{type(exc).__name__}: {exc}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Investigation failed. Check the server terminal "
                "for the specific error."
            ),
        ) from exc
      