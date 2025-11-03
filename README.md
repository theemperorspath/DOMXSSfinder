# DOMXSSfinder 🕵️‍♂️✨

Automated DOM XSS detection tool — run directly inside the browser DevTools console.

A small, copy-pasteable script that injects a large set of DOM XSS payloads and hooks risky DOM APIs to detect unsafe rendering/execution. Built for manual security testing and quick reconnaissance only on pages you own or are explicitly authorized to test.
The original script for this repo is provided as script.js.

🔍 Features

Runs in the browser console — no installation required.

Hooks risky APIs (e.g. innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, and setTimeout/setInterval when passed strings) and logs when they're used with injected payloads.

Injects a large payload set across multiple injection contexts (attribute, tag content, script block, URL/href).

Supports simple payload encodings/obfuscations: Base64, URL-encode, Unicode, whitespace/casing tricks.

Saves a detailed JSON report and can automatically download it when issues are found.

⚡ Quickstart — run in Chrome / Chromium / Edge

⚠️ Only test on systems you own or have explicit permission to test.

Open the target page in your browser.

Open DevTools → Console (F12 or Ctrl+Shift+I).

Open script.js, copy the entire file.

Paste into the Console and press Enter.

What the script does:

📸 Snapshot localStorage / sessionStorage.

🪝 Hook risky DOM & global APIs.

🔁 Iterate payloads and injection contexts.

📝 Log findings to the console and trigger a JSON report download if results exist.

Example report filename:

xss_report_2025-11-03T14-33-12.json

🧾 Example output

Console warnings telling you which API was triggered and by which payload.

Final summary, e.g.:

Tried: N payloads
Potential issues found: M


When findings exist: automatic download of xss_report_<timestamp>.json and a temporary Download XSS Report link injected into the page.

🛠️ Usage notes & recommended workflow

✅ Prefer running this in a controlled environment (staging or local replica) to avoid unintended side effects.

⚠️ The script does mutate the DOM during tests, but it attempts to restore original state where possible.

🔌 Disable extensions that may interfere with results (adblockers, script injectors, etc.).

🛡️ Sites with a strict Content-Security-Policy (CSP) may block payload execution (e.g., blocking eval or inline scripts). That is still useful — it indicates protections are in place.

🔒 Safety & legal (read this)

Do not use this tool against websites you do not own or are not explicitly authorized to test.
Unauthorized scanning, exploitation, or testing may be illegal and unethical. Use this tool only for:

defensive testing,

penetration tests with written permission, or

on your own lab/staging environments.

All credit for original version to: https://github.com/TRacer236
