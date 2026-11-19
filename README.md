# CyberDesk - Cybercrime Investigation Support Toolkit

**A hackathon-style demo dashboard that helps a police cybercell desk organise
cybercrime complaints, route them with explainable rules, analyse suspicious
links, look up bank branches, and keep an evidence timeline per case.**

Built with nothing but the Python standard library and vanilla HTML/CSS/JS.
No frameworks, no build step, no API keys, no database server.

> **Demo scope, stated plainly:** CyberDesk is an original demonstration
> project, inspired by the *shape* of law-enforcement OSINT suites. It is not
> an official police system. All case files are **fictional**. It never looks
> up people, never touches Aadhaar/PAN/phone-subscriber records, and never
> accesses government databases. Live checks only query public technical
> infrastructure data (DNS, TLS certificates, RBI-published IFSC data).

---

## What it does

| Module | What it shows | Data |
| --- | --- | --- |
| **Dashboard** | Case counts by category, status and priority, like a cybercell morning overview | fictional case file |
| **Case files** | 10 fictional complaints with full narratives and per-case evidence timelines | fictional case file |
| **Complaint triage** | Routes a free-text complaint to a category (Phishing, UPI fraud, Investment scam, Identity misuse, Harassment, Ransomware, Lottery scam) and extracts indicators: URLs, IPs, UPI handles, emails, phones, IFSC codes | runs live in your browser session |
| **URL analyser** | Scores a suspicious link with structural heuristics (brand impersonation, risky TLD, punycode, `@` trick, plain-HTTP logins...), plus **live** DNS resolution and TLS certificate expiry | heuristics + live public infrastructure |
| **Bank IFSC lookup** | Validates an IFSC and resolves the bank branch for mule-account leads | **live** public API (ifsc.razorpay.com, RBI-published data) with a labelled offline fallback |

Every screen labels where its data comes from: `fictional`, `live`,
`heuristic` or `offline sample`. Nothing is silently simulated.

---

## Quick start

```bash
git clone https://github.com/Subhradeeppramanick/simple-project.git
cd simple-project
python server.py
```

Open **http://127.0.0.1:8000** in a browser. Python 3.8+ is the only requirement.

Try these in the demo:

- **Triage:** paste *"Got an SMS that my SBI account will be blocked, clicked
  the link and entered my OTP and card details, 84500 debited to fastpay247@ybl"*
  → routed to **Phishing** with the matched keywords and extracted IOCs shown.
- **URL analyser:** `http://sbi-kyc-verify.top/login` → scores **90/100
  (LIKELY PHISHING)** with every signal explained.
- **IFSC lookup:** `SBIN0000001` → State Bank of India, Kolkata Main branch.

---

## API

The backend is `server.py` (~150 lines of `http.server`):

```
GET  /api/stats            case counts for the dashboard
GET  /api/cases            all fictional cases
GET  /api/case?id=CD-...   one case with its evidence timeline
POST /api/triage           {"text": "..."}  -> category, confidence, matched keywords, IOCs
POST /api/analyze          {"url": "..."}   -> score, verdict, signals, DNS, TLS
GET  /api/ifsc?code=...    -> bank, branch, city, payment rails, data source
```

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://sbi-kyc-verify.top/login"}'
```

---

## Project structure

```
server.py        web server + JSON API (stdlib http.server)
triage.py        rules-based complaint categorisation + IOC extraction
urlintel.py      URL heuristics + live DNS / TLS infrastructure checks
bankintel.py     IFSC validation + live lookup with offline fallback
data/cases.json  10 fictional case files with timelines
static/          dashboard frontend (HTML, CSS, JS - no frameworks)
tests/           offline unit tests (17 tests, no network needed)
```

Run the tests:

```bash
python -m unittest discover -s tests
```

---

## Design choices worth talking about

- **Explainable triage, not a black box.** Each routing decision returns the
  exact keywords that fired and every category's score, so an officer can
  audit it. That matters more in policing software than a clever model.
- **Infrastructure, not people.** The URL analyser and IFSC lookup only touch
  public technical data. The modules a real LEA suite has for person lookups
  (subscriber records, Aadhaar/PAN linkage, vehicle ownership) are
  deliberately absent - they require lawful access a demo cannot and should
  not have.
- **Honest degradation.** If the demo runs without internet, live checks
  report themselves unavailable and the IFSC module falls back to a small
  bundled sample, clearly labelled as offline data.
- **Zero dependencies.** Standard library everywhere, so the whole project
  can be reviewed, run and demonstrated on any machine in minutes.

## Roadmap

- Complaint intake form that writes new fictional cases at runtime
- PDF export of a case summary with its timeline
- Optional SQLite persistence behind the same API

## License

MIT - see [LICENSE](LICENSE).
