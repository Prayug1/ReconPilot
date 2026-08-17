# Executive Summary

`pixelpay.test` is a deliberately vulnerable lab-style banking target: it uses a `.test` domain, private IP `192.168.198.131`, fake-bank branding (`PixelPay Bank`), and a small exposed service set: `22/tcp` OpenSSH, `80/tcp` nginx, and `443/tcp` nginx. The posture is weak because the report shows public JS secrets, sensitive API routes, `.git` exposure, missing browser security headers, no WAF, and host-based routing across multiple banking/admin vhosts. The single most promising first avenue is client-side JS secret triage into API testing, especially around `/assets/js/payments.js`, `/assets/js/openbanking.js`, `/static/js/runtime.bundle.js`, `/static/js/vendor.bundle.js`, and harvested `/api/*` endpoints.

# Top Priorities

## 1. Exposed client-side secrets

**Why this matters:** The report shows `JS SECRETS (28 findings)` with high-risk material in public JavaScript, including Google API keys, a PEM private key marker, a Stripe live secret key, a GitHub personal access token, AWS key material, JWTs, and hardcoded API/secret assignments. The strongest source paths are `/assets/js/config.js`, `/assets/js/mobile.js`, `/assets/js/openbanking.js`, `/assets/js/payments.js`, `/assets/js/telemetry.js`, `/assets/js/transfers.js`, `/static/js/runtime.bundle.js`, and `/static/js/vendor.bundle.js`.

**Next step:**
```bash
mkdir -p evidence/js

for u in \
  https://pixelpay.test/assets/js/config.js \
  https://pixelpay.test/assets/js/mobile.js \
  https://pixelpay.test/assets/js/openbanking.js \
  https://pixelpay.test/assets/js/payments.js \
  https://pixelpay.test/assets/js/telemetry.js \
  https://pixelpay.test/assets/js/transfers.js \
  https://pixelpay.test/static/js/runtime.bundle.js \
  https://pixelpay.test/static/js/vendor.bundle.js
 do
  curl -sk "$u" -o "evidence/js/$(basename "$u")"
done

gitleaks detect --source evidence/js --no-git --report-format json --report-path evidence/js-secrets.json
```

**Expected outcome:** Success means confirmed, deduplicated secrets from served JS, with evidence ready for immediate revocation. Watch for secrets embedded in config objects, payment code, Open Banking code, telemetry clients, runtime bundles, and vendor bundles.

## 2. Validate sensitive API endpoints

**Why this matters:** The URL harvest contains banking-style API routes: `/api/v1/accounts.json`, `/api/v1/dashboard.json`, `/api/v1/profile.json`, `/api/v2/beneficiaries/verify.json`, `/api/v2/cards/controls.json`, `/api/v2/device-risk.json`, `/api/v2/feature-flags.json`, `/api/v2/investments/pricing.json`, and `/api/internal/risk-score.json`. These are more promising than generic paths because they imply account, profile, card, beneficiary, device-risk, feature-flag, investment, and internal risk-score functions.

**Next step:**
```bash
BASE="https://pixelpay.test"

for p in \
  /api/v1/accounts.json \
  /api/v1/dashboard.json \
  /api/v1/profile.json \
  /api/v2/beneficiaries/verify.json \
  /api/v2/cards/controls.json \
  /api/v2/device-risk.json \
  /api/v2/feature-flags.json \
  /api/v2/investments/pricing.json \
  /api/internal/risk-score.json
 do
  echo "### $p"
  curl -sk -i "$BASE$p" | sed -n '1,80p'
done
```

**Expected outcome:** Secure behavior is `401`, `403`, or sanitized empty JSON with no sensitive data. A serious finding is unauthenticated `200` output containing account data, dashboard data, profile fields, risk scores, card controls, feature flags, or authorization decisions.

## 3. Confirm `.git` exposure

**Why this matters:** Nuclei reports `git-config` against `https://pixelpay.test/.git/config` and `git-logs-exposure` against `https://pixelpay.test/.git/logs/HEAD`. If Git metadata is actually retrievable, source disclosure may expose hidden routes, deployment metadata, old secrets, API logic, and commit history.

**Next step:**
```bash
mkdir -p evidence/git

curl -sk -i https://pixelpay.test/.git/config -o evidence/git/config.response
curl -sk -i https://pixelpay.test/.git/logs/HEAD -o evidence/git/logs-head.response

sed -n '1,80p' evidence/git/config.response
sed -n '1,80p' evidence/git/logs-head.response
```

**Expected outcome:** If either response contains real Git content instead of `403` or `404`, attempt controlled lab recovery and review recovered source for credentials, hidden endpoints, auth bypasses, and admin/dev functionality.

## 4. Compare host-based routes and vhosts

**Why this matters:** Subdomain/vhost fuzzing found `13` hosts returning `200`: `www.pixelpay.test`, `dev.pixelpay.test`, `mobile.pixelpay.test`, `admin.pixelpay.test`, `secure.pixelpay.test`, `support.pixelpay.test`, `api.pixelpay.test`, `portal.pixelpay.test`, `cdn.pixelpay.test`, `billing.pixelpay.test`, `auth.pixelpay.test`, `status.pixelpay.test`, and `cards.pixelpay.test`. The response sizes differ slightly, so these may not all be identical aliases.

**Next step:**
```bash
mkdir -p evidence/vhosts
IP="192.168.198.131"

for h in www dev mobile admin secure support api portal cdn billing auth status cards
 do
  host="$h.pixelpay.test"
  echo "### $host"
  curl -sk --resolve "$host:443:$IP" "https://$host/" \
    -D "evidence/vhosts/$h.headers" \
    -o "evidence/vhosts/$h.body"
  wc -c "evidence/vhosts/$h.body"
  sha256sum "evidence/vhosts/$h.body"
done
```

**Expected outcome:** Success is separating true aliases from distinct applications. Prioritize `admin`, `dev`, `api`, `auth`, `secure`, `portal`, `billing`, and `cards`, then compare cookies, redirects, headers, forms, JavaScript includes, and API calls.

## 5. Fix missing security headers after exploit-path testing

**Why this matters:** The header analysis marks missing `Strict-Transport-Security`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`, `Cache-Control`, `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy` as high risk. `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN` are present, but missing CSP and cache controls are especially relevant for a banking-themed app.

**Next step:**
```bash
curl -skI https://pixelpay.test | egrep -i \
'HTTP/|server:|strict-transport-security|content-security-policy|referrer-policy|permissions-policy|x-xss-protection|cache-control|cross-origin-opener-policy|cross-origin-resource-policy|x-frame-options|x-content-type-options'
```

**Expected outcome:** Remediation should add HSTS, a restrictive CSP, safe referrer policy, feature restrictions, sensitive-page cache controls, and COOP/CORP where appropriate. From an operator perspective, missing CSP raises the value of any later XSS or HTML injection finding.

# Attack Path

Start with public JavaScript because `JS SECRETS (28 findings)` gives the highest-confidence lead. Confirm the exposed secrets in `/assets/js/*` and `/static/js/*`, then use the same JS files to map client API behavior and authentication assumptions. Next, test harvested API routes such as `/api/v1/accounts.json`, `/api/v2/cards/controls.json`, `/api/v2/device-risk.json`, and `/api/internal/risk-score.json` for unauthenticated access, weak token checks, or environment-only assumptions. In parallel, validate `.git/config` and `.git/logs/HEAD`; recovered source would accelerate route discovery and secret validation. Finally, pivot through the `admin`, `dev`, `api`, `auth`, `portal`, `billing`, and `cards` vhosts to find host-specific functionality that the root site hides.

# Don't waste time on

- Broad port hunting first: the open service set is only `22/tcp`, `80/tcp`, and `443/tcp`; the web/API/JS evidence is much richer.
- WAF bypass work: WAF detection says `No WAF detected (generic detection ran, no fingerprint)`.
- TLS downgrade work as the first priority: TLS is `TLSv1.3` with `TLS_AES_256_GCM_SHA384`; the main TLS issue is `Self-Signed: yes`, not an obvious weak protocol.
- Generic directory enumeration before validation: the report already has `51` directory paths, and the highest-value paths are clearly API, Git, admin/dev, backup/log/config/internal, and JS files.
- Treating `SNMPv3` as confirmed exposure: Nuclei mentions `pixelpay.test:161`, but the open-port table lists only `22/tcp`, `80/tcp`, and `443/tcp`, so validate UDP/161 before spending time there.
