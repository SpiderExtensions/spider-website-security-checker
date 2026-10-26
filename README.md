# Spider Website Security Checker

**Copyright © Spider Human AI. All rights reserved.**

A Chromium Manifest V3 extension with a neon cosmic / cyber-gothic interface inspired by the supplied Spider Human emblem.

## Install in Chrome, Edge, Brave or another Chromium browser
1. Extract `Spider-Website-Security-Checker.zip` to a folder.
2. Open `chrome://extensions` (Edge: `edge://extensions`).
3. Enable **Developer mode**.
4. Choose **Load unpacked** and select the extracted `spider-website-security-checker` folder.
5. Pin the Spider icon and open a regular website tab. Click the extension and choose **Scan this website**.

## What it checks
- HTTP vs HTTPS connection
- Some suspicious URL patterns
- Forms posting to HTTP or external hosts
- Mixed HTTP resource references on HTTPS pages
- Third-party iframes
- Public URLScan search results, when the service responds

## Important limitations
This is a heuristic checker, not a full antivirus, malware sandbox, certificate audit, or guarantee of safety. The percentage is a **heuristic safety score**, not a measured probability. URLScan public search can be unavailable, rate-limited, incomplete, or have no record for a site. A clean result does not prove a site is safe. Do not use this score alone to decide whether to download files or share sensitive information.

No API key is bundled. The optional public URLScan lookup is read-only and uses the hostname to query public scan records.
