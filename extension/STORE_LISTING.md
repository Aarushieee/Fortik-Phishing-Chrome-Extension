# SafeGuard - Malicious Site Detector

Protect yourself from phishing and unsafe links. SafeGuard analyzes pages and links in real time, highlighting potential risks and warning before you navigate.

## Key features
- Real-time page analysis with toolbar badge and high‑risk notifications
- Intercepts clicks and warns on suspicious links before navigation
- Clean popup with risk level, reasons, stats, and recent detections
- Adjustable sensitivity (Low/Medium/High), quick enable/disable
- Optional integration with a security API (configurable)

## How it works
SafeGuard uses lightweight heuristics (IP-only hosts, excessive subdomains, suspicious keywords, unusually long URLs). If you opt in, it can also query a configurable security API you provide. By default, analysis is fully local on your device.

## Required permissions (minimal and justified)
- activeTab: Analyze the current tab when you interact with the extension
- storage: Save your preferences and recent detection history
- notifications: Show alerts for high-risk pages
- host_permissions (<all_urls>): Inspect URLs on pages you visit to detect risk

No personal data is sold or shared.

## Privacy
- Local-only by default; no data leaves your device.
- If you enable API checks, the page URL is sent to your configured API.
- See the included Privacy Policy for details.

## Support
- Website: https://example.com/safeguard
- Email: support@example.com

## Screenshots guidance
Please capture: popup (status + history), warning banner on a high-risk page, and options (sensitivity + protection toggle).


