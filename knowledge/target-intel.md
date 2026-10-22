# Target Intel: Finding and Mapping Apps and Systems Worth Hunting

We do not hunt crowded leaderboards. We hunt apps and systems whose security attention is thin: government service apps, regional financial and insurance apps, logistics and operations systems, small-to-mid startup products, vendor backends behind popular apps, state-owned enterprises' digital services, B2B portals. Many have no visible security program at all - the disclosure path is discovered, not assumed.

## Where targets come from

1. App stores by region and category: finance, health, government, education, logistics categories in regional stores. Sort by installs (large userbase = impact scale) and last-updated (active = live surface). The apkpure MCP gives downloads, update dates, version histories per package; apkpure_target_score ranks engagement fit (freshness, install scale, mirror-vs-store drift).
2. The app itself is a map: every acquired APK reveals its org, its API estate, its vendors, its analytics and push stacks, its sibling apps (same signing cert = same org family - enumerate via the cert, not the name). One APK routinely expands into a target list of five.
3. Org OSINT: the company behind an app has a website estate, a careers page leaking their stack, GitHub orgs (public repos, org members, CI configs), press releases naming vendors, job posts naming internal systems. The web estate around the app is discovered from the app's own endpoints (mobile.md hosts.txt) and the org's DNS.
4. Referral chains: an app's backend references vendor dashboards, status pages, staging hosts, admin panels - each a new surface. A vendor serving many apps multiplies the finding surface across all of them.
5. Wayback/archives: dead-looking endpoints and forgotten subdomains that still resolve; old app versions still served by CDNs.

## Choosing what to hunt (effort allocation)

Rank by: userbase size (impact scale), freshness (active development = new code = new bugs), thinness of security attention (no visible security page, no public disclosures, small team), and attack-surface richness (payments, KYC, health data, push, deep links). A mid-size regional finance app with monthly releases and no security page beats a famous target with a thousand hunters and a disclosure graveyard.

Duplicate risk is different here: without public disclosure flows, the same bug may sit unfixed and unreported for years. Version history is the dup-check: the mirror's version timeline plus release notes tell whether the surface you found is new code (fresh) or ancient code (maybe found by someone, probably not, and unrotated secrets prove nobody acted anyway).

## Mapping the estate (before any dynamic probe)

1. Acquire the app artifact with provenance (mobile.md section 1). Decode, sweep, extract hosts/endpoints/secrets.
2. Expand: every discovered hostname -> DNS -> live probe; every org domain -> subdomain enum (crt.sh, subfinder, wayback); every IP -> port map where in scope (rh_scope first, always).
3. Fingerprint: tech stack per host (headers, cookies, generator tags, favicon hashes), app version + signing cert, API gateway shapes, push and analytics vendors.
4. Find the disclosure channel (for later, the operator uses it): /.well-known/security.txt on the main domains, the org's security/contact page, a CSIRT mailbox, the vendor's responsible-disclosure page. Record in target.json disclosure_contact. No contact found: the operator decides what happens to the material pack; nothing is sent automatically, ever.
5. Ingest every output line through rh_leadboard. The board is the estate map.

## The org-side signals worth a round

- Careers page: job posts naming the stack (a posting for "DevOps (Jenkins, Kubernetes)" is a recon result; a posting for "Application Security Engineer" is a warning that attention exists).
- Public GitHub orgs: repos, members, leaked CI configs, secrets scanning hits in old commits (note: acting on those is out of our scope law unless the org is the target and the repo is theirs; scope check still applies).
- Press/product pages: new feature launches = fresh code = fresh surface. Acquisitions = merged estates with mismatched controls.
- Certificate transparency on their domains: new subdomains weekly = active infrastructure growth.

## Anti-patterns

- Hunting famous targets because they are famous: the competition ate the surface years ago.
- Skipping "boring" categories: government service apps hold the most sensitive data classes and get the least security attention.
- Trusting the app-store listing over the artifact: the APK's own strings tell the truth about the estate.
- Forgetting the desktop client: vendor blogs link direct downloads; the asar is a first-class surface (mobile.md section 12).
- Hunting without provenance: if you cannot answer "how did I obtain this artifact", the evidence chain is broken before it starts.
