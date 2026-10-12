# ClauseGuard 🛡️ — Offline Contract Risk Analyzer

> Read the fine print *before* you sign. ClauseGuard flags the high-risk clauses a
> lawyer looks at first and explains them in plain language — 100% offline, zero
> dependencies, no API keys.

Most people sign rentals, freelance gigs, SaaS terms, and loans without spotting
the clauses that can hurt them. ClauseGuard turns a wall of legal text into a
short, prioritized risk report you can actually act on.

## ✨ Why ClauseGuard

- **Offline & private** — your contract never leaves your machine. No network, no cloud, no API calls.
- **Zero dependencies** — pure Python standard library. Runs anywhere Python 3.8+ runs.
- **Transparent, not a black box** — every finding cites the matched text and a plain-language reason you can verify.
- **Explains, scores, advises** — each finding comes with *why it matters* and a *practical tip*.

## 🚀 Quick start

```bash
# Analyze a contract
python -m clauseguard.cli examples/sample_contract.txt

# Machine-readable output
python -m clauseguard.cli examples/sample_contract.txt --json

# Pretty HTML report (great for screenshots / demos)
python -m clauseguard.cli examples/sample_contract.txt --html report.html
```

## 🔍 What it detects

| Category | Example clauses caught |
|---|---|
| Term & Termination | Auto-renewal, early-termination penalties |
| Liability & Indemnity | Liability caps, broad indemnification, personal guarantees |
| Dispute Resolution | Binding arbitration, class-action waiver, far-away governing law |
| IP & Data | Broad IP assignment, data sharing/consent |
| Payment | One-sided payment timing, withholding, late fees, no-refund |
| Restrictive Covenants | Non-compete / non-solicitation |

It also warns when standard clauses (governing law, limitation of liability,
termination, payment, confidentiality) appear to be **missing** from a substantive contract.

## 🧠 How the "AI" works

ClauseGuard uses a transparent, auditable **rule engine**: each detector is a
small, declarative pattern with a severity, an explanation, and a tip. We
deliberately avoid opaque ML here — for legal documents, *explainability beats a
fuzzy model you can't interrogate*. The risk score weights findings by severity
and adds a breadth bonus when many distinct risk categories appear.

This design choice is also why it's a strong fit for small-business and
everyday-use AI app contests: it ships a real, data-backed decision (risk score +
explainable findings), not a chat box.

## 📦 Project layout

```
clauseguard/
  core.py     # analysis engine + clause detectors
  cli.py      # command-line interface
  report.py   # self-contained HTML report builder
examples/
  sample_contract.txt   # demo contract packed with risky clauses
```

## ⚠️ Disclaimer

ClauseGuard is a **screening tool, not legal advice**. Always confirm important
agreements with a qualified lawyer.

## 📄 License

MIT — free to use, modify, and build upon.
