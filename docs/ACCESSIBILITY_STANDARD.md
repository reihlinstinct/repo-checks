# Accessibility engineering standard

Accessibility (a11y) is part of every change, like internationalization and security.
This standard applies to new code and maintenance. Use free tooling only.
Track existing gaps as issues and fix them in small, tested PRs.

## Target and evidence

- SI 5568 is the Israeli reference, with AA as our baseline. The published
  September 2023 SI 5568-1 is based on WCAG 2.0 with national changes. It is
  not identical to WCAG 2.2. Review the national changes, including section
  headings (2.4.10), manually. Digital documents have a separate Part 2.
- Our web engineering target also includes WCAG 2.1 and 2.2 A/AA automated
  rules. This is additional coverage, not a statement of legal equivalence.
- A green axe run means only that the selected rules found no violations on
  the tested routes and states. It is not SI 5568 certification, a full audit,
  a legal opinion, or evidence of a legal exemption.
- For native apps, apply the relevant SI 5568 criteria and platform accessibility
  APIs. Record tests on at least two common operating systems (Android and iOS).
  Chromium and WebKit on Linux do NOT meet that two-OS requirement. A missing
  OS implementation or evidence is an open gap, never a passing result.

## Required implementation

Use semantic HTML/native controls, meaningful headings, names and labels;
image alternatives; text error messages tied to inputs; visible keyboard focus;
logical tab order; no keyboard traps; accessible dialog focus; adequate contrast;
zoom/reflow; reduced-motion support; captions and alternatives where needed.
Set document language and language direction from the selected translation.
Announce dynamic results without moving focus unexpectedly. Do not replace real
fixes with an overlay or an accessibility toolbar.

Every repository has root ACCESSIBILITY.md stating its UI scope, automated and
manual evidence, limitations, and a real reporting route. Web/app interfaces
also expose an easy-to-find accessibility statement describing the adjustments,
known gaps, date and reporting/contact route. Do not invent a named coordinator,
contact details, completed audit, or conformance claim. Check regulation 35ה and
applicable obligations before making legal statements. Internal repository docs
are not a substitute for a statement in the interface.

## Free automated gate

The shared `actions/a11y` action uses locked axe-core and Playwright packages.
Consumers pin the action to a reviewed full commit, run a local synthetic preview,
and provide a reviewed JSON route manifest. Keep any existing browser checks
until the pilot proves the new gate. Do not test an authenticated production
service or expose personal data to public CI.

The fixed matrix is Chromium + WebKit at 1280x900 and 390x844. All WCAG A/AA
violations fail, irrespective of impact tier. No rule exclusions or baselines are
accepted. Invalid input, missing browsers, blocked external HTTP requests,
navigation failures and axe failures return error, not pass. Consumer jobs must
have a timeout and must not use continue-on-error. Reports contain only engine,
width, page ordinal, counts and rule IDs, never DOM, selectors, text or URLs.

`incomplete` counts mean axe could not decide; review those checks manually and
record the outcome in the consumer's evidence. They are not proof of success.
The manifest must cover all pages, languages (including RTL) and supported URL
states in scope. The shared action scans page-load states only. Projects must
add their own axe tests after opening menus/dialogs, validating forms, loading
results, or other interactions. A homepage-only scan is not full UI coverage.
Remote dependencies should be bundled locally for deterministic tests. The test
browser bypasses Content Security Policy solely to inject axe; production CSP
is not changed or audited by this action. This bypass can enable inline code
that production CSP would block, so test results must be compared with the
production-CSP browser smoke tests. HTTP redirects are inspected before each
fetch and WebSockets are blocked; this remains a browser test, not a network
sandbox (DNS-prefetch and other browser side channels are not certified).

Example reviewed route manifest:

```json
{"version":1,"paths":["/","/?lang=en","/?lang=he"]}
```

Run a local preview first, then use the shared composite action with `base-url`
set to its HTTP loopback origin and `config` to the manifest's absolute path.
Pin `reihlinstinct/repo-checks/actions/a11y` to the full reviewed commit when
rolling out. It installs its own lockfile and browser dependencies on Ubuntu;
no commercial service, credit card or API key is used.

Local runner (Node 22 or newer):

```sh
cd actions/a11y
npm ci --ignore-scripts
npx --no-install playwright install --with-deps chromium webkit
A11Y_BASE_URL=http://127.0.0.1:8765/ A11Y_CONFIG=/tmp/routes.json node scan.mjs
```

Exit 0: no automated violations. Exit 1: violations. Exit 2: tool/config error.
The runner is not an OS network sandbox; use a synthetic, no-secret CI job.
No production screenshots or raw axe artifacts are published by this action.

## Manual release checklist

Record tester, date, build, devices/browser/OS, routes, languages and outcomes:

- Keyboard-only complete primary tasks, tab order, focus visibility, modal focus
  return, Escape behavior and skip navigation.
- Screen-reader names, roles, state, reading order, headings and live updates
  (for example VoiceOver and TalkBack on native devices).
- 200% text zoom and reflow at 320 CSS pixels; no lost text, controls or content.
- RTL/LTR language switching, mixed-direction text and labels; long translations.
- Contrast including focus/error/disabled states; touch targets and orientation.
- Captions/alternatives and document accessibility when those formats are used.
- Review every axe incomplete result. Keep untested items and failures visible
  as issues; a missing manual test is not a green conformance result.

New UI PRs state the a11y impact, routes/states tested and remaining manual gaps.
Existing requirements remain: issue first, docs, small signed commits, green CI,
independent review at the exact head and normal protected merge.

## Sources

- [SI 5568-1, September 2023, published by gov.il](https://www.gov.il/BlobFolder/legalinfo/israeli_accessibility_standards_pdf/he/sitedocs_si-5568-1-september-2023.pdf)
- [Israeli Internet Association: accessibility rules, apps and statements](https://www.isoc.org.il/freedom-of-internet/accessibility/all-about-accessibility)
- [W3C WAI evaluation guidance: tools alone cannot determine conformance](https://www.w3.org/WAI/test-evaluate/)

Sources checked 2026-11-11. The association's overview includes historical
rules; recheck official current regulations before relying on an exemption.
This project standard does not assume any exemption.
