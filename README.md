# CyberIntel — Astro starter

Responsive, static cybersecurity research website covering threat intelligence, ethical pentesting, Shodan aggregate exposure, detection engineering, projects and an about page.

## Run locally

Requires Node.js 20.3+ or 22+ (choose a recent Node LTS release), npm and Python 3.10+.

```bash
npm install
python3 scripts/fetch_intel.py   # optional first-time public feed sync
npm run dev
```

Open the local URL printed by Astro. The included initial JSON datasets are intentionally empty: no live data or fictional CVEs are presented until successful retrieval.

## Shodan integration (optional)

Run from your terminal without placing secrets in source files:

```bash
export SHODAN_API_KEY='YOUR_PRIVATE_KEY'
export SHODAN_QUERY='product:nginx'
python3 scripts/fetch_shodan.py
```

Or configure GitHub repository **Settings → Secrets and variables → Actions**:
- Secret `SHODAN_API_KEY`
- Variable `SHODAN_QUERY`

The updater uses Shodan's `/shodan/host/count` API to publish a single aggregate count, not host identifiers. Account entitlement, query limits and redistribution requirements must be confirmed with Shodan. For production, remove unrestricted public queries and design private scoped-asset checks as a separate authenticated service.

## GitHub Actions

The included workflow attempts a feed update every six hours (GitHub schedules can run late). It commits a JSON snapshot only if changed. Repository Settings → Actions → General may need **Read and write permissions** enabled for `GITHUB_TOKEN`. Make sure workflow updates cannot overwrite your editorial content. For hardened deployments pin third-party actions to full commit SHAs, use branch protections and keep dependency lockfiles committed.

## Deploy on Cloudflare Pages

1. Create a GitHub repository, commit this source and push to `main`.
2. In Cloudflare, create a **Pages** project linked to that repository.
3. Build command: `npm run build`; output directory: `dist`.
4. The static site needs no server-side Astro adapter.
5. Replace `site` in `astro.config.mjs` with the real production URL.

Cloudflare now generally recommends Workers for **new full-stack Astro projects**, but Pages is a valid static hosting option. If you later add server-side authenticated features, evaluate Workers with appropriate auth and private storage.

## Next production work

- Add NVD + EPSS enrichment with source-specific timestamps, provenance and throttling.
- Add real Markdown content collections, RSS, Pagefind and independent editorial review.
- Introduce tests, pinned GitHub Action commits, npm lockfile, dependency updates and security headers.
- Add authenticated workspace for authorised exposure monitoring, never in this static public app.
- Add disclosure policy, privacy notice, asset authorisation workflow and monitoring.

## Security limitations

Static sites still have supply-chain, deployment, content-injection and configuration risks. Only publish non-sensitive, licensed/redistributable intelligence. Do not upload live malware, credentials, client information or unredacted pentest reports. Shodan observations are not proof of exploitation.
