# Open-Forensics

**A digital forensics simulator for training CERT and DFIR analysts.** Ten incident
folders, nothing but logs, fifteen thousand lines to sift through. You get whatever the
client managed to collect, and you have to establish the facts, reconstruct what the
attacker did, and prove it.

**Static application**: three files opened in a browser are enough. No dependencies, no
server, no network connection, no data transmitted.

🔗 **Live demo**: <https://spellskite-coding.github.io/Open-Forensics/>

Companion app to [Open-SOC](https://github.com/Spellskite-coding/Open-SOC): where Open-SOC trains decision-making
under pressure, Open-Forensics trains methodical reconstruction.

---

## Getting started

```bash
git clone <your-repo> Open-Forensics
cd Open-Forensics
```

Then, either:

* open `index.html` directly in your browser, or
* try it online right away: <https://spellskite-coding.github.io/Open-Forensics/>, or
* serve the folder locally, recommended for classroom use:

```bash
python3 -m http.server 8000
# then http://localhost:8000/
```

The test suite opens the same way: `tests/run.html`. It runs in the browser and displays
`ALL TESTS PASS` or the list of failures. No external tooling, no `npm install`.

---

## How a case unfolds

**1. The briefing.** The client's engagement letter, the technical scope, the collection
conditions, and above all **the limitations**: which logs are missing, over what period,
and why. A missing log is an investigative limitation to document, not an excuse.
Conversely, a log that is present and covers the period allows you to conclude an event
did *not* happen — and that is often the heaviest conclusion of all.

**2. The logs.** That's all there is: no disk image, no memory capture. Each exhibit is a
stream of timestamped events, where the few useful lines are buried in the client's normal
activity. The left-hand panel offers a **cross-exhibit search** that looks for the same
string across every exhibit: that's how you trace an address, an account, or a filename
from one log to another. Each exhibit also has its own filter, with matches highlighted.

**3. The findings.** About a dozen factual questions per case, validated one by one like
checkpoints: attacker's address, compromised account, timestamp of the initial entry point,
binary's hash, volume exfiltrated, real scope of the compromise. Answers are normalized
leniently — case, accents, thousand separators, French or ISO timestamps, and "defanged"
indicators (`hxxp://`, `[.]`) are all accepted.

**4. The attack chain.** For each of the twelve ATT&CK tactics, you identify the event in
the case that demonstrates it and the matching technique. The pool of events also contains
legitimate activity: not everything is meant to be placed. And **declaring that a tactic
was not observed earns just as many points as finding one**: stating that no exfiltration
occurred, when the logs allow you to demonstrate that, is a legitimate investigative
finding.

**5. The write-up.** The CERT deliverable, scored on its length and on the case indicators
it cites. A report that offers no evidence to back up its claims isn't usable.

**You can close a case at any time**, without having found everything. The score will be
partial, but the debrief will be complete.

---

## The ten cases

| | Case | Difficulty | Estimated time | Findings | Log lines |
|---|---|---|---|---|---|
| CASE-01 | Ransomware via exposed RDP — freight carrier | easy | 35 min | 11 | 1,220 |
| CASE-02 | Wire transfer fraud after session theft — law firm | easy | 45 min | 11 | 1,150 |
| CASE-03 | Blueprint leak ahead of a resignation — engineering firm | easy | 40 min | 10 | 1,003 |
| CASE-04 | Webshell and customer database theft — online store | medium | 60 min | 12 | 1,421 |
| CASE-05 | Update downloaded from a fake mirror — manufacturing | medium | 55 min | 12 | 1,572 |
| CASE-06 | Cryptomining on the CI pipeline — software vendor | medium | 55 min | 12 | 1,493 |
| CASE-07 | Fake vendor in the ERP — accounting firm | medium | 60 min | 12 | 1,441 |
| CASE-08 | DCSync and golden ticket — local government | hard | 110 min | 16 | 2,163 |
| CASE-09 | Wiped logs and forged timestamps — fintech | hard | 100 min | 15 | 2,002 |
| CASE-10 | Hypervisor encryption — hospital | hard | 95 min | 15 | 1,888 |

Roughly **eleven hours of investigation**, 126 findings, 120 tactics to qualify, and
15,353 log lines — of which less than 3% carry the attack. Difficulty scales the subtlety
of each case, the number of sources to cross-reference, and the duration: a hard case takes
two hours and won't yield to a single search.

Every case includes at least two unobserved tactics, and several contain legitimate
activity that looks deceptively like the attack — a colleague plugging in a USB drive, a
routine accounting operation, a developer cloning a repository. Ruling those out explicitly
is part of the job.

> **Instructors:** ground truth lives in `js/data/cas-*.js`. Every file carries a warning
> at the top. Ask students not to open them before working the case — it's the only way to
> cheat, and it's explicit.

---

## Scoring

| Item | Points |
|---|---|
| Finding established | 6 |
| Wrong answer | −0.5, capped at −3 per finding |
| Hint revealed | −2 |
| Correct event in the attack chain | 3 per tactic |
| Correct technique in the attack chain | 1.5 per tactic |
| Write-up | up to 8 (length, then one and three indicators cited) |

The debrief gives a score out of 100, a grade from A to E, and four axes: fact
establishment, chain reconstruction, written delivery, autonomy. Then, for **every**
finding — found or not — the expected answer, yours, **where it was located** in the
exhibits, and **why it mattered**. Same for every tactic in the chain. All of it followed
by the real story of the incident, the case's lessons, its pitfalls, an indicator sheet
ready to hand off to a SOC, and an exportable JSON report.

Progress — best score and number of attempts per case — is kept in the browser's
`localStorage`. No written answers are stored there.

---

## Background traffic

A real log isn't a list of evidence. The useful lines in each case are hand-written;
everything else is generated by fifteen normal-traffic generators (`js/data/bruit.js`):
Windows authentication, process telemetry, security agent, firewall, web proxy, DNS
resolution, identity federation, email, Unix logs, web server, remote access,
collaboration platform, database, CI pipeline, hypervisor.

This noise is **deterministic**: the seed is derived from the case ID and the exhibit ID.
Opening the same case twice produces exactly the same log, line for line, which lets an
instructor prepare an answer key and lets two students compare their approaches on
identical exhibits.

---

## Security posture

* **No dependencies.** Zero third-party libraries, zero remote resources, zero external
  fonts.
* **No network.** `connect-src 'none'`: the page cannot issue a request. It works in an
  isolated environment.
* **Strict Content Security Policy**, declared in `index.html`: `default-src 'none'`,
  scripts and styles restricted to the origin, no inline script or style,
  `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`.
* **No injection possible.** The DOM is built exclusively with `createElement` and
  `textContent` — including search-result highlighting. There is not a single occurrence
  of `innerHTML`, `eval`, or `new Function` in the code.
* **Locked-down element factory.** `util.el()` refuses by construction any `on*`
  attribute, as well as `style`, `href`, `src`, `srcdoc`, `action`, `formaction`, `ping`,
  and `background`.
* **Local storage validated on read**, bounded in size and entry count; unavailable
  storage does not prevent the app from working.
* **Compatibility.** Strict ES5 JavaScript, no modern syntax or promises. `Math.imul` has
  a fallback, `crypto` and `localStorage` are wrapped, `:focus-visible` is preceded by a
  fallback rule. Firefox, Chrome, Edge, Safari, on desktop as well as over `file://`.

### Everything is fictional

No organization, person, machine, address, or hash in this repository exists. IP addresses
belong to the ranges reserved for documentation (RFC 5737: `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), and domains use the reserved TLDs `.test`,
`.invalid`, and `.example` (RFC 2606). No indicator from this simulator can therefore
point to a real resource, and the exercise logs won't pollute a threat intelligence
platform if a student accidentally copies them out.

---

## Structure

```
index.html               Single page, Content Security Policy
css/openforensics.css    Single stylesheet, dark theme
js/util.js               Safe DOM, deterministic randomness, formatting
js/data/referentiel.js   ATT&CK tactics and techniques, scoring, exhibit types
js/data/bruit.js         Fifteen background-traffic generators
js/data/cas-01..10.js    The ten cases and their ground truth (SPOILERS)
js/engine.js             Logs, search, findings, scoring (no DOM)
js/ui.js                 Rendering and interactions
js/app.js                Bootstrapping and safety net
tests/run.html           Test suite runnable in the browser
tests/tests.js           59 assertions: normalization, integrity, volume, scoring
```

The engine never touches the DOM: that's what lets the tests replay complete
investigations — perfect, abandoned, partial, fully hint-assisted — and verify that
scoring separates them correctly.

---

## Adding a case

Create `js/data/cas-11.js` following the pattern of the others and declare it in
`index.html` and `tests/run.html`. The contract is checked automatically by the test
suite:

* each exhibit is a log, with `{ t, m }` lines timestamped `YYYY-MM-DD HH:MM:SS` and one
  or more noise specifications pointing to an existing family;
* each finding carries a `hint`, a `where`, and a `why`, and its answer must validate
  itself after normalization — as must each of its accepted variants;
* the chain covers all twelve tactics, with no duplicates, each technique belonging to
  the tactic of its line, with between two and nine unobserved tactics;
* the key indicators cited in `keyIndicators` must actually appear in the generated
  logs;
* the volume of logs and the number of findings must match the declared difficulty, and
  the useful lines must stay under 12% of the total.

Open `tests/run.html`: any discrepancy is flagged by name.

---

## License

MIT — see [LICENSE](LICENSE). Free to use in training centers, schools, or internally.
