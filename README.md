# CyberDesk - Cybercrime Investigation Support Toolkit

**A hackathon-style demo dashboard that helps a police cybercell desk organise
cybercrime complaints, route them with explainable rules, analyse suspicious
links, look up bank branches, and keep an evidence timeline per case.**

Built with nothing but the Python standard library and vanilla HTML/CSS/JS.
No frameworks, no build step, no API keys, no database server.

> **Demo scope, stated plainly:** CyberDesk is a personal portfolio project,
> inspired by the *shape* of law-enforcement OSINT suites. It is not an
> official police system and has no connection to, or endorsement from, any
> police, government or military body. All case files are **fictional**. It
> never looks up people, never touches Aadhaar/PAN/phone-subscriber records,
> and never accesses government databases.
>
> **Offline by default.** Out of the box the app makes no outside network
> requests. It does not accept typed complaints (triage runs only on bundled
> fictional samples), the URL analyser only scores the text of a link, and
> the IFSC lookup uses a small bundled sample. Live DNS/TLS and IFSC lookups
> exist only as an opt-in for local use (see below). Do not enter real
> complaints or personal data. This is not legal advice or legal clearance.

---

## What it does

| Module | What it shows | Data |
| --- | --- | --- |
| **Dashboard** | Case counts by category, status and priority, like a cybercell morning overview | fictional case file |
| **Case files** | 10 fictional complaints with full narratives and per-case evidence timelines | fictional case file |
| **Complaint triage** | Routes a bundled fictional sample complaint to a category (Phishing, UPI fraud, Investment scam, Identity misuse, Harassment, Ransomware, Lottery scam) with matched keywords, and extracts indicators: URLs, IPs, UPI handles, emails, phones, IFSC codes. Typed text is rejected. | bundled fictional samples |
| **URL analyser** | Scores a link with structural heuristics (brand impersonation, risky TLD, punycode, `@` trick, plain-HTTP logins...). Offline: nothing is fetched. Optional live DNS/TLS checks for local use only. | heuristics (offline by default) |
| **Bank IFSC lookup** | Validates an IFSC format and resolves the branch from a small bundled sample (SBIN0000001, HDFC0000123, ICIC0000001). Optional live lookup via ifsc.razorpay.com for local use only. | offline sample by default |

Every screen labels where its data comes from. Sample data uses reserved
`.example` domains and placeholder payment handles and phone numbers, not
real ones.

---

## Quick start

```bash
git clone https://github.com/Subhradeeppramanick/cyberdesk.git
cd cyberdesk
python server.py
```

Open **http://127.0.0.1:8000** in a browser. Python 3.8+ is the only requirement.

Try these in the demo:

- **Triage:** pick sample `CD-2026-1001` → routed to **Phishing** with the
  matched keywords and extracted indicators shown.
- **URL analyser:** `http://sbi-kyc-verify.example/login` → scores **80/100
  (LIKELY PHISHING)** with every signal explained.
- **IFSC lookup:** `SBIN0000001` → State Bank of India, Kolkata Main branch
  (from the bundled sample).

Optional, local use only: `python server.py --enable-live-checks` turns on
live DNS/TLS and IFSC lookups. It refuses to start unless bound to
`127.0.0.1`, and live URL checks only connect to public IP addresses (not
loopback, private or link-local ones). Do not expose this mode to the internet.

---

## API

The backend is `server.py` (stdlib `http.server`):

```
GET  /api/stats            case counts for the dashboard
GET  /api/cases            all fictional cases
GET  /api/case?id=CD-...   one case with its evidence timeline
GET  /api/samples          fictional sample complaints
POST /api/triage           {"sample_id": "CD-..."} -> category, confidence, matched keywords, IOCs
                           (free text is rejected with HTTP 400)
POST /api/analyze          {"url": "..."}   -> score, verdict, signals (+ DNS/TLS only with --enable-live-checks)
GET  /api/ifsc?code=...    -> bank, branch, city, payment rails, data source
```

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://sbi-kyc-verify.example/login"}'
```

---

## Project structure

```
server.py        web server + JSON API (stdlib http.server)
triage.py        rules-based complaint categorisation + IOC extraction
urlintel.py      URL heuristics + optional guarded live DNS / TLS checks
bankintel.py     IFSC validation + offline sample (optional live lookup)
data/cases.json  10 fictional case files with timelines
static/          dashboard frontend (HTML, CSS, JS - no frameworks)
tests/           offline unit tests (25 tests, no network needed)
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
- **Infrastructure, not people.** The URL analyser and IFSC lookup only deal
  with technical data. The modules a real LEA suite has for person lookups
  (subscriber records, Aadhaar/PAN linkage, vehicle ownership) are
  deliberately absent - they require lawful access a demo cannot and should
  not have.
- **Safe by default.** No outside requests, no free-text intake, request-size
  and rate limits, security headers, and live checks that refuse non-public
  IP targets and only run when explicitly enabled on loopback.
- **Zero dependencies.** Standard library everywhere, so the whole project
  can be reviewed, run and demonstrated on any machine in minutes.

## Roadmap

- PDF export of a case summary with its timeline
- Optional SQLite persistence behind the same API

## License

MIT - see [LICENSE](LICENSE).
