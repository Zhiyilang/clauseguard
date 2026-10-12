"""
HTML report builder for ClauseGuard.

Produces a clean, self-contained HTML file (no external assets) so the user can
open it in any browser and screenshot it for a demo, or share it.
"""

from __future__ import annotations

from html import escape
from typing import Dict, List

from .core import AnalysisResult, Finding

SEV_META = {
    1: ("WATCH", "#b7791f", "rgba(183,121,31,0.12)"),
    2: ("CAUTION", "#dd6b20", "rgba(221,107,32,0.12)"),
    3: ("HIGH", "#c53030", "rgba(197,48,48,0.12)"),
}

BAND_COLOR = {
    "HIGH": "#c53030",
    "MEDIUM": "#dd6b20",
    "LOW": "#2f855a",
    "MINIMAL": "#2f855a",
}


def _finding_card(f: Finding) -> str:
    label, color, bg = SEV_META[f.severity]
    return f"""
    <div class="card" style="border-left:5px solid {color}; background:{bg};">
      <div class="fhead">
        <span class="badge" style="background:{color};">{label}</span>
        <span class="ftitle">{escape(f.title)}</span>
        <span class="fcount">×{f.occurrences}</span>
      </div>
      <div class="fcat">{escape(f.category)}</div>
      <div class="ftext"><b>Found:</b> …{escape(f.matched_text)}…</div>
      <div class="fwhy"><b>Why it matters:</b> {escape(f.explanation)}</div>
      <div class="ftip"><b>Tip:</b> {escape(f.tip)}</div>
    </div>
    """


def build_html(result: AnalysisResult, source_name: str = "contract") -> str:
    band = result.risk_band
    band_color = BAND_COLOR.get(band, "#2f855a")
    cards = "".join(_finding_card(f) for f in sorted(result.findings, key=lambda x: -x.severity))
    if not cards:
        cards = '<div class="card">No high-risk clause patterns detected. '
        "This is a screening result, not a clean bill of health — read it yourself.</div>"

    missing = "".join(f"<li>{escape(c)}</li>" for c in result.missing_standard_clauses)
    missing_block = (
        f'<div class="section"><h3>Potentially missing standard clauses</h3>'
        f"<ul>{missing}</ul></div>"
        if missing
        else ""
    )

    hi = sum(1 for f in result.findings if f.severity == 3)
    med = sum(1 for f in result.findings if f.severity == 2)
    low = sum(1 for f in result.findings if f.severity == 1)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClauseGuard Report — {escape(source_name)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         max-width: 880px; margin: 24px auto; padding: 0 18px; color:#1a202c; }}
  h1 {{ font-size: 24px; margin-bottom: 4px; }}
  .meta {{ color:#718096; font-size: 14px; margin-bottom: 18px; }}
  .scorebox {{ display:flex; gap:14px; align-items:center; padding:16px 18px;
              border-radius:10px; background:{band_color}1a; border:1px solid {band_color}55; }}
  .scoreband {{ font-size: 26px; font-weight:700; color:{band_color}; }}
  .scorenum {{ font-size: 14px; color:#4a5568; }}
  .legend {{ font-size:13px; color:#718096; margin:10px 0 0; }}
  .section {{ margin-top: 22px; }}
  h3 {{ font-size: 17px; margin-bottom: 8px; }}
  .card {{ border:1px solid #e2e8f0; border-radius:8px; padding:12px 14px; margin:10px 0; }}
  .fhead {{ display:flex; align-items:center; gap:10px; }}
  .badge {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:20px; }}
  .ftitle {{ font-weight:600; }}
  .fcount {{ margin-left:auto; color:#718096; font-size:13px; }}
  .fcat {{ color:#718096; font-size:12px; margin:4px 0 8px; }}
  .ftext, .fwhy, .ftip {{ font-size:14px; line-height:1.5; margin:4px 0; }}
  ul {{ margin: 6px 0; }}
  .footer {{ margin-top:26px; font-size:12px; color:#a0aec0; border-top:1px solid #edf2f7; padding-top:12px; }}
</style></head>
<body>
  <h1>ClauseGuard — Contract Risk Report</h1>
  <div class="meta">Source: {escape(source_name)} · {result.word_count} words analyzed · offline analysis</div>

  <div class="scorebox">
    <div>
      <div class="scoreband">RISK: {band}</div>
      <div class="scorenum">Score {result.risk_score} · {hi} high · {med} caution · {low} watch</div>
    </div>
  </div>
  <p class="legend">Severity: HIGH = review before signing · CAUTION = understand the trade-off · WATCH = note it.</p>

  <div class="section"><h3>Findings</h3>{cards}</div>
  {missing_block}

  <div class="section"><h3>Summary</h3><p>{escape(result.summary)}</p></div>

  <div class="footer">
    ClauseGuard v1.0 — a transparent, offline rule engine. This is a screening tool,
    not legal advice. Always confirm with a qualified lawyer for important agreements.
  </div>
</body></html>"""
