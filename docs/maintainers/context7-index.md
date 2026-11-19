# Context7 consumer index

The root README, consumer docs, and runnable hostsession/nethttp documentation
are selected. Migration, recovery, session, security and transaction contracts
remain included. Historical implementation plans, review reports, release
procedures and maintainer evaluation notes are not consumer recipes.

The exclusion arrays preserve the Context7 documented defaults as checked on
2026-11-18: custom arrays replace, rather than extend, those defaults. No extra
source extensions or ownership keys are configured. Including example folders
does not make Go source into indexed documentation.

Run `python3 scripts/check-context7-config.py`. It checks this selection policy
and the documented transaction declarations against source, not the hosted
crawler, compilation or runtime behavior.

Configuration reference: <https://context7.com/docs/library-owners> and
<https://context7.com/schema/context7.json>.

After an approved merge, verify which configuration source is active before
claiming this file controls indexing. Do not assume repository/dashboard
precedence. Activation, ownership claims and refresh are separate actions.
Confirm the indexed revision and repeat queries for PostgreSQL initialization,
notification delivery, transaction callbacks and host authorization snapshots.
Do not turn a successful refresh into an assumed benchmark improvement.
