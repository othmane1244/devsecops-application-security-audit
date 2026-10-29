# Application Security Audit with Trivy and Jit

Academic security audit of OWASP Juice Shop.

## Status
Planning and laboratory preparation. No scans completed yet.

## Objectives
- Scan dependencies, container images, secrets and configurations.
- Generate a Software Bill of Materials (SBOM).
- Evaluate the security controls available through Jit.
- Analyze selected findings and apply targeted fixes.
- Compare results before and after remediation.
- Explore automation with GitHub Actions.

## Target application
https://github.com/juice-shop/juice-shop

Juice Shop is a third-party application.
Our work covers audit methodology, analysis, targeted fixes and automation.
The audited version will be recorded during laboratory preparation.

## Methodology
1. Prepare a reproducible local laboratory.
2. Run initial scans.
3. Investigate and prioritize findings.
4. Apply selected fixes.
5. Test functionality and repeat scans.
6. Document results and limitations.

## Limitations
Automated scans cannot detect every vulnerability.
Findings require contextual analysis and manual verification.

## Team
- Othmane Aliouali
- Youssef AIT KARROUM

## Laboratory setup completed

The following steps have been completed:
- Verified Git and Docker CLI availability.
- Started Docker Desktop with its Linux engine on WSL 2.
- Successfully executed the hello-world container.
- Downloaded OWASP Juice Shop v20.3.0.
- Started the audit container using the image digest.
- Confirmed startup through container status and application logs.

### Target image

Image tag: `bkimminich/juice-shop:v20.3.0`

Recorded digest:
`sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`

The digest fixes the image reference for reproducibility.
The laboratory currently uses Linux containers on x86_64.

### Reproduce the laboratory

With Docker running, execute:

```powershell
docker pull bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27
docker run -d --name juice-shop-audit -p 127.0.0.1:3000:3000 bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27
```

Open http://localhost:3000 once the application has started.
The published port is bound to localhost.

### Verify and manage the container

```powershell
docker ps --filter name=juice-shop-audit
docker logs --tail 50 juice-shop-audit
docker stop juice-shop-audit
docker start juice-shop-audit
```

Run the creation command only once.
For an existing stopped container, use `docker start`.

### Known laboratory limitations

Startup logs report unavailable Alchemy and LLM services.
Related blockchain and chatbot challenges are outside our initial scope.
Successful startup checks do not demonstrate application security.
The initial Trivy image scan has been completed and its original JSON is
preserved on this branch. The HIGH/CRITICAL JSON is a separate filtered
report and does not replace the original.

### Dependency analysis progress

The reports contain 98 initial detections (11 CRITICAL, 27 HIGH,
49 MEDIUM and 11 LOW) and 38 HIGH/CRITICAL detections. These are detection
counts, not counts of distinct advisories or confirmed exploitable issues.
Static analysis documents cover authentication, lodash, sanitize-html,
crypto-js, decompress/tar, Handlebars and MarsDB. Other installations and
some lower-severity alerts remain to be reviewed.

See the [detection tracking document](docs/analysis/00-suivi-des-detections.md)
for every reported installation, severity counts, analysis status, confirmed
aliases, open questions and suggested next checks. “Analyzed” describes
documentary progress and does not mean exploitability has been confirmed.

The initial CycloneDX SBOM is available at
[reports/sbom/juice-shop-initial.cdx.json](reports/sbom/juice-shop-initial.cdx.json).
Its scope, image identity, generation command, verification results and limits
are documented in the [SBOM guide](docs/sbom/README.md).

The Trivy secret checks have been completed for the audit worktree and the
`/juice-shop` files from the local image. Their scope and sanitized findings
are documented in the [secret audit method](docs/secrets/README.md) and
[shareable report](docs/secrets/rapport-partageable.md). Raw outputs remain
outside the repository.

No application changes, dependency updates, vulnerability scans or exploitation
tests were performed in this stage. The secret-only checks are summarized in
the linked report above.

### Next steps

- Study the application architecture.
- Prepare Trivy and record its version.
- Perform and document the initial security scans.
