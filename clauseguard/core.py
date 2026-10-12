"""
ClauseGuard — offline contract risk analyzer (zero third-party dependencies).

Why this exists
--------------
Most people sign contracts (rentals, freelance gigs, SaaS terms, loans) without
spotting the clauses that can hurt them. ClauseGuard reads a contract as plain
text and flags the high-risk clauses a lawyer would look for first, then explains
each one in plain language and assigns an overall risk score.

It is 100% offline. No API keys, no network, no ML model downloads. The "AI" here
is a transparent, auditable rule engine: every finding cites the matched text and
a human-readable reason, so the user can verify it instead of trusting a black box.

This is intentional: for a tool people trust with legal documents, explainability
beats a fuzzy neural net.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Clause detectors
# ---------------------------------------------------------------------------
# Each detector is a small, self-contained rule. We keep them declarative so the
# engine stays easy to audit and extend. Patterns are matched case-insensitively.
#
# severity: 1 = watch, 2 = caution, 3 = high risk
# ---------------------------------------------------------------------------

@dataclass
class Detector:
    key: str
    title: str
    severity: int
    patterns: List[str]            # regex, matched case-insensitive
    explanation: str
    tip: str
    category: str = "General"


DETECTORS: List[Detector] = [
    Detector(
        key="auto_renewal",
        title="Automatic renewal (auto-renew)",
        severity=2,
        category="Term & Termination",
        patterns=[
            r"automatically\s+renew",
            r"auto[-\s]?renew",
            r"shall\s+renew\s+for\s+successive",
            r"evergreen",
            r"renew\s+automatically",
        ],
        explanation=(
            "The contract renews itself unless you actively cancel it. Many people "
            "miss the cancellation window and get locked into another term or charged "
            "again."
        ),
        tip=(
            "Look for the notice period required to cancel (e.g. 30/60 days before "
            "renewal). Set a calendar reminder before that date."
        ),
    ),
    Detector(
        key="unilateral_change",
        title="Provider can change terms unilaterally",
        severity=2,
        category="Mutual Obligations",
        patterns=[
            r"may\s+(change|modify|update|amend)\s+(the\s+)?(terms|agreement|policy)",
            r"reserve[s]?\s+the\s+right\s+to\s+(change|modify|update|amend)",
            r"without\s+(prior\s+)?notice",
            r"at\s+its\s+(sole\s+)?discretion",
        ],
        explanation=(
            "The other party can alter the deal (price, scope, terms) after you sign, "
            "sometimes without telling you in advance."
        ),
        tip=(
            "Try to negotiate a clause requiring written notice and your consent for "
            "material changes, or at least a right to terminate if changes are unacceptable."
        ),
    ),
    Detector(
        key="liability_cap",
        title="Liability cap / limitation of liability",
        severity=2,
        category="Liability & Indemnity",
        patterns=[
            r"limitation\s+of\s+liability",
            r"in\s+no\s+event\s+shall",
            r"liable\s+for\s+(any\s+)?(indirect|consequential|incidental)",
            r"aggregate\s+liability",
            r"shall\s+not\s+exceed",
        ],
        explanation=(
            "The other party limits how much they can be forced to pay you if something "
            "goes wrong. This often excludes indirect/consequential damages, which can "
            "be the largest part of a real loss."
        ),
        tip=(
            "Check whether the cap is reasonable vs. the value of the deal, and whether "
            "exclusions (indirect, consequential) are acceptable to you."
        ),
    ),
    Detector(
        key="indemnification",
        title="Broad indemnification / hold harmless",
        severity=3,
        category="Liability & Indemnity",
        patterns=[
            r"indemnif(y|ies|ication)",
            r"hold\s+(him|her|them|it|us|the\s+company)\s+harmless",
            r"defend,\s+indemnify",
        ],
        explanation=(
            "You may be required to cover the other party's legal costs and losses, "
            "including claims you did not directly cause. Broad indemnities can expose "
            "you to large, unpredictable liability."
        ),
        tip=(
            "Narrow the scope to losses caused by your breach or negligence only, and cap "
            "the indemnity amount."
        ),
    ),
    Detector(
        key="arbitration_waiver",
        title="Mandatory arbitration / class-action waiver",
        severity=2,
        category="Dispute Resolution",
        patterns=[
            r"binding\s+arbitration",
            r"waive\s+(any\s+)?(right\s+to\s+a\s+)?(jury|trial|class\s+action)",
            r"class[-\s]?action\s+waiv",
            r"disputes?\s+shall\s+be\s+resolved\s+by\s+arbitration",
        ],
        explanation=(
            "You may be forced to resolve disputes through private arbitration instead of "
            "court, and may give up the right to join a class action. Arbitration can be "
            "costly and limits your options."
        ),
        tip=(
            "Decide if you are comfortable giving up court access. Some jurisdictions let "
            "you opt out within a window — look for that."
        ),
    ),
    Detector(
        key="governing_law",
        title="Governing law / jurisdiction (foreign or unfavorable)",
        severity=1,
        category="Dispute Resolution",
        patterns=[
            r"governed\s+by\s+the\s+laws?\s+of",
            r"jurisdiction\s+of\s+(the\s+)?(courts?\s+of|.*state|.*country)",
            r"venue\s+shall\s+be",
        ],
        explanation=(
            "Disputes are decided under a specific location's laws and courts. If it is "
            "far away or unfamiliar, pursuing a claim becomes expensive and hard."
        ),
        tip=(
            "Prefer a jurisdiction where you can realistically enforce your rights. Note "
            "the venue so you understand where you would have to sue or be sued."
        ),
    ),
    Detector(
        key="penalty_termination",
        title="Early-termination penalty / liquidated damages",
        severity=2,
        category="Term & Termination",
        patterns=[
            r"early\s+termination\s+fee",
            r"liquidated\s+damages",
            r"penalty\s+for\s+(termination|cancellation)",
            r"charge[d]?\s+.*for\s+cancel",
            r"termination\s+fee",
        ],
        explanation=(
            "Ending the contract early can trigger a fixed fee or calculated damages. "
            "These can be surprisingly large relative to the deal."
        ),
        tip=(
            "Quantify the worst-case exit cost before signing and confirm whether the "
            "penalty is enforceable under local law."
        ),
    ),
    Detector(
        key="ip_assignment",
        title="Broad IP / work-product assignment",
        severity=3,
        category="IP & Data",
        patterns=[
            r"(all|any|exclusive)\s+rights\s+(in|to)\s+(the\s+)?(work|deliverable|ip|intellectual)",
            r"assign[s]?\s+(all|any)?\s*(intellectual\s+property|ip|rights)",
            r"work\s+(made\s+for\s+hire|product\s+shall\s+belong)",
            r"ownership\s+of\s+(the\s+)?(work|deliverable|code)\s+(vests|shall\s+vest)",
        ],
        explanation=(
            "You may be signing over ownership of everything you create, including "
            "background IP or future improvements, with no carve-out for your pre-existing "
            "work."
        ),
        tip=(
            "Carve out pre-existing IP, limit assignment to final deliverables, and keep a "
            "license to reuse your own tools and know-how."
        ),
    ),
    Detector(
        key="non_compete",
        title="Non-compete / non-solicitation",
        severity=2,
        category="Restrictive Covenants",
        patterns=[
            r"non[-\s]?compete",
            r"shall\s+not\s+(engage|work|provide\s+services)\s+with",
            r"non[-\s]?solicit",
            r"not\s+compete\s+with",
        ],
        explanation=(
            "You may be restricted from working with certain clients or competitors for a "
            "period, which can limit your future income."
        ),
        tip=(
            "Check the duration, geography, and scope. Overly broad non-competes are "
            "unenforceable in many places — but being sued is still costly."
        ),
    ),
    Detector(
        key="data_privacy",
        title="Data collection / privacy / consent",
        severity=2,
        category="IP & Data",
        patterns=[
            r"(collect|process|share|sell)\s+(your\s+)?(personal\s+)?data",
            r"consent\s+to\s+(the\s+)?(processing|sharing|collection)",
            r"privacy\s+policy",
            r"may\s+(share|sell|transfer)\s+(your\s+)?(data|information)\s+with\s+third",
        ],
        explanation=(
            "The contract may let the other party collect, share, or sell your data, or "
            "data of your customers, often with broad consent language."
        ),
        tip=(
            "Limit data use to what is necessary, require notice for sharing, and confirm "
            "compliance with privacy law (GDPR/CCPA etc.) if relevant."
        ),
    ),
    Detector(
        key="payment_terms",
        title="Unclear or one-sided payment terms",
        severity=2,
        category="Payment",
        patterns=[
            r"net\s*\d{1,3}\s*(days|d)",
            r"(payment|invoice)\s+due\s+within",
            r"may\s+(withhold|offset|deduct)\s+(payment|fees)",
            r"(late|interest)\s+(fee|charge)\s+of\s+\d",
            r"reserve[s]?\s+the\s+right\s+to\s+(withhold|offset)",
        ],
        explanation=(
            "Payment timing, with holding rights, or late fees may be one-sided — e.g. you "
            "get paid slowly while penalties for you are steep."
        ),
        tip=(
            "Aim for mutual and symmetric terms: clear due dates, capped late fees, and no "
            "unilateral withholding."
        ),
    ),
    Detector(
        key="personal_guarantee",
        title="Personal guarantee",
        severity=3,
        category="Liability & Indemnity",
        patterns=[
            r"personal\s+(guarantee|guaranty|guarantee)",
            r"jointly\s+and\s+severally\s+liable",
            r"personally\s+liable",
            r"guarantee\s+payment\s+of",
        ],
        explanation=(
            "You may be personally on the hook — meaning your own assets (not just a "
            "company's) can be pursued if the other side claims a loss."
        ),
        tip=(
            "Avoid personal guarantees where possible, or limit them in amount and duration."
        ),
    ),
    Detector(
        key="no_refund",
        title="No-refund / non-cancellable",
        severity=1,
        category="Payment",
        patterns=[
            r"(no|non[-\s]?)(refund|cancel)",
            r"non[-\s]?cancellable",
            r"fees\s+(are\s+)?(non[-\s]?refundable|not\s+refundable)",
            r"all\s+sales\s+(are\s+)?final",
        ],
        explanation=(
            "Money you pay may be non-refundable and the commitment non-cancellable, so "
            "you bear the full risk if the service disappoints."
        ),
        tip=(
            "Confirm what happens if they fail to deliver, and avoid large upfront "
            "non-refundable sums."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    detector_key: str
    title: str
    severity: int
    category: str
    matched_text: str
    explanation: str
    tip: str
    occurrences: int = 1


@dataclass
class AnalysisResult:
    findings: List[Finding] = field(default_factory=list)
    word_count: int = 0
    risk_score: int = 0
    risk_band: str = ""
    missing_standard_clauses: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict:
        return {
            "word_count": self.word_count,
            "risk_score": self.risk_score,
            "risk_band": self.band(),
            "findings": [
                {
                    "key": f.detector_key,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "matched_text": f.matched_text,
                    "explanation": f.explanation,
                    "tip": f.tip,
                    "occurrences": f.occurrences,
                }
                for f in self.findings
            ],
            "missing_clauses": self.missing_standard_clauses,
            "summary": self.summary,
        }

    def band(self) -> str:
        if self.risk_score >= 12:
            return "HIGH"
        if self.risk_score >= 6:
            return "MEDIUM"
        if self.risk_score >= 1:
            return "LOW"
        return "MINIMAL"


# Standard clauses a healthy contract normally contains. If absent, we warn.
EXPECTED_CLAUSES = {
    "governing_law": ["governing law", "jurisdiction", "venue"],
    "liability_cap": ["limitation of liability", "liable", "aggregate liability"],
    "termination": ["termination", "term of this agreement", "notice period"],
    "payment": ["payment", "invoice", "fees"],
    "confidentiality": ["confidential", "non-disclosure", "nda"],
}


def analyze(text: str) -> AnalysisResult:
    """Run the full rule engine over contract text and return a structured result."""
    if not text or not text.strip():
        raise ValueError("Contract text is empty.")

    text_lower = text.lower()
    words = re.findall(r"[A-Za-z]+", text)
    result = AnalysisResult(word_count=len(words))

    for det in DETECTORS:
        matched_spans = []
        for pat in det.patterns:
            for m in re.finditer(pat, text_lower, flags=re.IGNORECASE):
                # pull a readable window around the match
                start = max(0, m.start() - 40)
                end = min(len(text), m.end() + 60)
                snippet = text[start:end].replace("\n", " ").strip()
                matched_spans.append(snippet)
        if matched_spans:
            # dedupe while keeping order
            seen = set()
            uniq = []
            for s in matched_spans:
                if s not in seen:
                    seen.add(s)
                    uniq.append(s)
            result.findings.append(
                Finding(
                    detector_key=det.key,
                    title=det.title,
                    severity=det.severity,
                    category=det.category,
                    matched_text=uniq[0][:160],
                    explanation=det.explanation,
                    tip=det.tip,
                    occurrences=len(uniq),
                )
            )

    # Risk score: weight by severity, plus a small bump for breadth.
    sev_weight = {1: 1, 2: 2, 3: 4}
    raw = sum(sev_weight[f.severity] for f in result.findings)
    breadth = len(result.findings)
    result.risk_score = raw + (breadth if breadth > 6 else 0)
    result.risk_band = result.band()

    # Missing standard clauses (only warn if contract is substantive)
    if result.word_count >= 150:
        for key, kws in EXPECTED_CLAUSES.items():
            if not any(kw in text_lower for kw in kws):
                label = {
                    "governing_law": "Governing law / jurisdiction",
                    "liability_cap": "Limitation of liability",
                    "termination": "Termination / notice",
                    "payment": "Payment terms",
                    "confidentiality": "Confidentiality",
                }[key]
                result.missing_standard_clauses.append(label)

    result.summary = _summarize(result)
    return result


def _summarize(result: AnalysisResult) -> str:
    n = len(result.findings)
    hi = sum(1 for f in result.findings if f.severity == 3)
    med = sum(1 for f in result.findings if f.severity == 2)
    low = sum(1 for f in result.findings if f.severity == 1)
    band = result.band()
    parts = [
        f"Analyzed {result.word_count} words. Overall risk: {band} (score {result.risk_score}).",
        f"Found {n} notable clause type(s): {hi} high, {med} caution, {low} watch.",
    ]
    if result.missing_standard_clauses:
        parts.append(
            "Potentially missing standard clauses: "
            + ", ".join(result.missing_standard_clauses)
            + "."
        )
    if hi:
        parts.append(
            "Top priority: review the high-severity clauses (indemnity, IP assignment, "
            "personal guarantee) before signing."
        )
    return " ".join(parts)
