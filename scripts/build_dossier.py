import datetime
import json
import os
import shutil
from pathlib import Path
from typing import Any

from google import genai
from google.genai import types
from jinja2 import Environment, FileSystemLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
ARCHIVE_DIR = ROOT_DIR / "archive"
TEMPLATES_DIR = ROOT_DIR / "templates"
MANIFEST_PATH = ARCHIVE_DIR / "manifest.json"

INDEX_EN = ROOT_DIR / "index.html"
INDEX_NATIVE = ROOT_DIR / "index-native.html"
ARCHIVE_INDEX = ROOT_DIR / "archive.html"

RTL_LANG_CODES = {"ar", "he", "fa", "ur", "ps", "yi", "dv"}

EN_UI = {
    "current_case": "Current Dossier",
    "archive": "Archive",
    "severity": "Threat Level",
    "location": "Location",
    "source_lang": "Primary Reporting Language",
    "domain": "CBRNE Domain",
    "primary_location": "Primary Jurisdiction",
    "confidence": "OSINT Confidence",
    "executive_summary": "Executive Summary",
    "technical_analysis": "Technical & Safety Assessment",
    "osint_findings": "Key OSINT Findings",
    "timeline": "Chronology",
    "sources_and_docs": "Verified Sources & Documents",
    "archive_badge": "Dossier Repository",
    "archive_title": "Archived Weekly Cases",
    "cases_count_label": "Archived Cases",
    "no_archive": "No prior weekly dossiers archived yet.",
    "disclaimer": "For analytical & safety awareness only; no hazardous synthesis instructions.",
}

NATIVE_UI_FALLBACK = {
    "current_case": "Current Dossier",
    "archive": "Archive",
    "severity": "Severity",
    "location": "Location",
    "source_lang": "Language",
    "domain": "Domain",
    "primary_location": "Jurisdiction",
    "confidence": "Confidence",
    "executive_summary": "Executive Summary",
    "technical_analysis": "Technical Assessment",
    "osint_findings": "OSINT Findings",
    "timeline": "Timeline",
    "sources_and_docs": "Sources & Documents",
    "archive_badge": "Archive",
    "archive_title": "Archived Cases",
    "cases_count_label": "Cases",
    "no_archive": "No archived cases yet.",
    "disclaimer": "Open-source analytical dossier.",
}


def get_week_stamp(now: datetime.datetime) -> tuple[str, str]:
    iso_year, iso_week, _ = now.isocalendar()
    case_id = f"CASE-{iso_year}-W{iso_week:02d}"
    start_dt = now - datetime.timedelta(days=7)
    date_range = f"{start_dt.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}"
    return case_id, date_range


def load_manifest() -> list[dict[str, Any]]:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return []


def save_manifest(entries: list[dict[str, Any]]) -> None:
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def archive_previous_issue(manifest: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Moves current week's live files into archive/ if they exist and aren't archived yet."""
    if not INDEX_EN.exists():
        return manifest

    first_line = INDEX_EN.read_text(encoding="utf-8")
    # Extract current case ID from <title>CASE-YYYY-Www — ...
    if "<title>CASE-" not in first_line:
        return manifest

    title_start = first_line.index("<title>CASE-") + len("<title>")
    title_end = first_line.index("</title>", title_start)
    prev_title_tag = first_line[title_start:title_end]
    prev_case_id = prev_title_tag.split(" — ", 1)[0].strip()

    if any(entry.get("case_id") == prev_case_id for entry in manifest):
        return manifest

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    en_archive_name = f"{prev_case_id.lower()}-en.html"
    shutil.copy2(INDEX_EN, ARCHIVE_DIR / en_archive_name)

    native_archive_name: str | None = None
    native_code = "native"
    native_label = "NATIVE"
    title_en = prev_title_tag.split(" — ", 1)[-1].strip()
    country = "International"
    category = "CBRNE"
    date_range = prev_case_id

    if INDEX_NATIVE.exists():
        native_html = INDEX_NATIVE.read_text(encoding="utf-8")
        if 'lang="' in native_html:
            c_start = native_html.index('lang="') + len('lang="')
            c_end = native_html.index('"', c_start)
            native_code = native_html[c_start:c_end].strip() or "native"
        native_archive_name = f"{prev_case_id.lower()}-{native_code}.html"
        shutil.copy2(INDEX_NATIVE, ARCHIVE_DIR / native_archive_name)

    manifest.insert(
        0,
        {
            "case_id": prev_case_id,
            "date_range": date_range,
            "category": category,
            "country": country,
            "title_en": title_en,
            "en_file": en_archive_name,
            "native_file": native_archive_name,
            "native_label": native_label,
        },
    )
    return manifest


def generate_cbrne_payload(case_id: str, date_range: str) -> dict[str, Any]:
    client = genai.Client()

    prompt = f"""
You are a senior open-source intelligence (OSINT) analyst specializing in CBRNE
(Chemical, Biological, Radiological, Nuclear, and Explosive) safety, regulatory incidents,
proliferation/security developments, and public-health or environmental alerts.

Task:
1. Search live news, official agencies (such as IAEA, OPCW, WHO, CDC, national regulators,
   and credible regional/international outlets) for developments over the past 7 days ({date_range}).
2. Select the SINGLE most significant CBRNE-related development from the past 7 days.
   Do NOT provide actionable instructions, recipes, or blueprints for weapons or hazardous agents.
   Keep analysis strictly focused on factual reporting, safety, governance, monitoring, and OSINT.
3. Identify the primary country/jurisdiction involved, its primary reporting language ISO 639-1 code
   (e.g., "ru" for Russia, "he" for Israel, "zh" for China, "ja" for Japan, "uk" for Ukraine,
   "fa" for Iran, "fr" for France, "de" for Germany, "en" for English-speaking jurisdictions),
   and a short uppercase label for the native language (e.g., "РУССКИЙ", "עברית", "中文", "EN").
4. Produce a complete dossier in TWO languages:
   - "en": Written in clear, objective English.
   - "native": Written in the primary reporting language of the event's location (e.g., Russian
     if in Russia, Hebrew if in Israel). Include standard international technical terms or
     acronyms in parentheses where helpful for precision. Also provide localized UI labels for
     the dossier sections in that language.
5. Every item in "sources" must use real, verifiable URLs returned by Google Search during this run.
"""

    response_schema = types.Schema(
        type=types.Type.OBJECT,
        required=[
            "category",
            "severity",
            "confidence",
            "country",
            "region",
            "native_lang_code",
            "native_lang_label",
            "en",
            "native",
            "sources",
        ],
        properties={
            "category": types.Schema(
                type=types.Type.STRING,
                enum=["Chemical", "Biological", "Radiological", "Nuclear", "Explosive"],
            ),
            "severity": types.Schema(
                type=types.Type.STRING,
                enum=["Low", "Moderate", "High", "Critical"],
            ),
            "confidence": types.Schema(
                type=types.Type.STRING,
                enum=["Low", "Moderate", "High"],
            ),
            "country": types.Schema(type=types.Type.STRING),
            "region": types.Schema(type=types.Type.STRING),
            "native_lang_code": types.Schema(type=types.Type.STRING),
            "native_lang_label": types.Schema(type=types.Type.STRING),
            "en": types.Schema(
                type=types.Type.OBJECT,
                required=[
                    "title",
                    "executive_summary",
                    "technical_analysis",
                    "osint_findings",
                    "timeline",
                ],
                properties={
                    "title": types.Schema(type=types.Type.STRING),
                    "executive_summary": types.Schema(type=types.Type.STRING),
                    "technical_analysis": types.Schema(type=types.Type.STRING),
                    "osint_findings": types.Schema(
                        type=types.Type.ARRAY,
                        items=types.Schema(type=types.Type.STRING),
                    ),
                    "timeline": types.Schema(
                        type=types.Type.ARRAY,
                        items=types.Schema(
                            type=types.Type.OBJECT,
                            required=["date", "event"],
                            properties={
                                "date": types.Schema(type=types.Type.STRING),
                                "event": types.Schema(type=types.Type.STRING),
                            },
                        ),
                    ),
                },
            ),
            "native": types.Schema(
                type=types.Type.OBJECT,
                required=[
                    "title",
                    "executive_summary",
                    "technical_analysis",
                    "osint_findings",
                    "timeline",
                    "ui_labels",
                ],
                properties={
                    "title": types.Schema(type=types.Type.STRING),
                    "executive_summary": types.Schema(type=types.Type.STRING),
                    "technical_analysis": types.Schema(type=types.Type.STRING),
                    "osint_findings": types.Schema(
                        type=types.Type.ARRAY,
                        items=types.Schema(type=types.Type.STRING),
                    ),
                    "timeline": types.Schema(
                        type=types.Type.ARRAY,
                        items=types.Schema(
                            type=types.Type.OBJECT,
                            required=["date", "event"],
                            properties={
                                "date": types.Schema(type=types.Type.STRING),
                                "event": types.Schema(type=types.Type.STRING),
                            },
                        ),
                    ),
                    "ui_labels": types.Schema(
                        type=types.Type.OBJECT,
                        required=[
                            "current_case",
                            "archive",
                            "severity",
                            "location",
                            "source_lang",
                            "domain",
                            "primary_location",
                            "confidence",
                            "executive_summary",
                            "technical_analysis",
                            "osint_findings",
                            "timeline",
                            "sources_and_docs",
                        ],
                        properties={
                            "current_case": types.Schema(type=types.Type.STRING),
                            "archive": types.Schema(type=types.Type.STRING),
                            "severity": types.Schema(type=types.Type.STRING),
                            "location": types.Schema(type=types.Type.STRING),
                            "source_lang": types.Schema(type=types.Type.STRING),
                            "domain": types.Schema(type=types.Type.STRING),
                            "primary_location": types.Schema(type=types.Type.STRING),
                            "confidence": types.Schema(type=types.Type.STRING),
                            "executive_summary": types.Schema(type=types.Type.STRING),
                            "technical_analysis": types.Schema(type=types.Type.STRING),
                            "osint_findings": types.Schema(type=types.Type.STRING),
                            "timeline": types.Schema(type=types.Type.STRING),
                            "sources_and_docs": types.Schema(type=types.Type.STRING),
                        },
                    ),
                },
            ),
            "sources": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(
                    type=types.Type.OBJECT,
                    required=["title", "url", "publisher", "language_label"],
                    properties={
                        "title": types.Schema(type=types.Type.STRING),
                        "url": types.Schema(type=types.Type.STRING),
                        "publisher": types.Schema(type=types.Type.STRING),
                        "language_label": types.Schema(type=types.Type.STRING),
                    },
                ),
            ),
        },
    )

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            tools=[{"google_search": {}}],
            response_mime_type="application/json",
            response_schema=response_schema,
            temperature=0.2,
        ),
    )

    data = json.loads(response.text)
    data["case_id"] = case_id
    data["date_range"] = date_range
    return data


def render_pages(payload: dict[str, Any], manifest: list[dict[str, Any]]) -> None:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)
    template = env.get_template("dossier.html")

    native_code = (payload.get("native_lang_code") or "en").lower().strip()
    native_label = (payload.get("native_lang_label") or native_code.upper()).strip()
    native_dir = "rtl" if native_code in RTL_LANG_CODES else "ltr"

    common_ctx = {
        "case_id": payload["case_id"],
        "date_range": payload["date_range"],
        "category": payload["category"],
        "severity": payload["severity"],
        "confidence": payload["confidence"],
        "country": payload["country"],
        "region": payload["region"],
        "sources": payload.get("sources", []),
        "root_prefix": "",
        "show_lang_switch": True,
        "en_href": "index.html",
        "native_href": "index-native.html",
        "native_label": native_label,
        "is_archive_index": False,
    }

    en_data = payload["en"]
    en_html = template.render(
        **common_ctx,
        lang_code="en",
        text_dir="ltr",
        active_variant="en",
        title=en_data["title"],
        executive_summary=en_data["executive_summary"],
        technical_analysis=en_data["technical_analysis"],
        osint_findings=en_data.get("osint_findings", []),
        timeline=en_data.get("timeline", []),
        ui=EN_UI,
    )
    INDEX_EN.write_text(en_html, encoding="utf-8")

    native_data = payload["native"]
    native_ui = {**NATIVE_UI_FALLBACK, **native_data.get("ui_labels", {})}
    native_html = template.render(
        **common_ctx,
        lang_code=native_code,
        text_dir=native_dir,
        active_variant="native",
        title=native_data["title"],
        executive_summary=native_data["executive_summary"],
        technical_analysis=native_data["technical_analysis"],
        osint_findings=native_data.get("osint_findings", []),
        timeline=native_data.get("timeline", []),
        ui=native_ui,
    )
    INDEX_NATIVE.write_text(native_html, encoding="utf-8")

    # Update manifest metadata for current case so archive index reflects accurate info
    updated_manifest = [
        entry for entry in manifest if entry.get("case_id") != payload["case_id"]
    ]
    archive_html = template.render(
        is_archive_index=True,
        lang_code="en",
        text_dir="ltr",
        root_prefix="",
        show_lang_switch=False,
        entries=updated_manifest,
        ui=EN_UI,
    )
    ARCHIVE_INDEX.write_text(archive_html, encoding="utf-8")


def main() -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    case_id, date_range = get_week_stamp(now)

    manifest = load_manifest()
    manifest = archive_previous_issue(manifest)

    payload = generate_cbrne_payload(case_id, date_range)
    render_pages(payload, manifest)
    save_manifest(manifest)


if __name__ == "__main__":
    main()
