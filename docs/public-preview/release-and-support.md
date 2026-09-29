# Release and support contract

The current stage produces a locally verified unpublished candidate. It does
not change repository visibility, move a tag or deploy a host. Goauth v0.4.1 is
the released baseline; v0.5.0 is a candidate with deliberately changed store and
transaction assembly contracts. Consult the v0.5 migration before adoption.

## Distribution

Finish the combined candidate gates and focused independent review first.
Publish dependencies in order: canonical goauth, goadmin, then site. Pin exact
released versions; remove temporary development replacements before published
consumer verification. Never rewrite a published tag. A checkout-local probe
proves compatibility only; a clean no-replace consumer of the exact public tag
is a separate mandatory distribution check. OPS-03/04 remain not_run until that
stage actually executes. PR numbers or earlier successful tags are not evidence
for a new candidate.

Record base SHA, dirty source fingerprint, dependency selection, toolchain,
commands, service versions, failures and review snapshot. Keep sensitive raw
artifacts outside the repository and publish sanitized results. Review supported
import closure, all intended history/refs, release assets, permissions and the
private vulnerability reporting channel before public release. A vulnerability
scan does not replace that review or prove application security.

## Host cutover and recovery

Coordinate frontend/backend cookie and route changes; users log in again.
Do not exchange legacy browser tokens, reset canonical production tables or
reinterpret projection IDs. The admin journal migration is additive. Retain
old encrypted notification handlers until existing jobs drain or expire.
Rollback matching frontend/backend binaries together and require login again.
Do not downgrade canonical transaction/audit invariants or make an old refresh
secret reusable to preserve a browser session.

Retain JWT read keys through access expiry, HMAC read keys through the lifetime
of affected one-time/refresh records and AEAD read keys through queue/journal
and backup retention. Supervise delivery, cleanup and safe blocked-event
signals. Restore a backup only with its corresponding schema and key versions;
explicitly revoke restored sessions when policy requires it. Use separate
migration authority and least-privilege application credentials in deployment.
The disposable local restore gate does not prove production DB grants.

## Support and vulnerability handling

The supported-package manifest defines import support; export visibility alone
does not. Security changes may invalidate browser state deliberately and must
state that compatibility effect. Keep reproduction, affected/fixed versions and
private disclosure separate from public release notes. Follow SECURITY.md;
verify the real reporting channel before advertising public support. Neither a
local gate nor the ZITADEL subset pilot is a certification or generic provider
conformance claim. Deployments and physical mobile applications need their own
acceptance outside this repository.
