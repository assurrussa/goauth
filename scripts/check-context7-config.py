#!/usr/bin/env python3
"""Offline regression checks for this repo's Context7 selection policy.

Not an implementation or validation of Context7's remote parser.
"""
import fnmatch
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
config = json.loads((ROOT / "context7.json").read_text())


def included(path):
    parts = Path(path).parts
    if parts[-1] in config["excludeFiles"]:
        return False
    ancestors = ["/".join(parts[:i]) for i in range(1, len(parts))]
    for pattern in config["excludeFolders"]:
        if "/" in pattern:
            if any(fnmatch.fnmatchcase("/".join(a.split("/")[i:]), pattern)
                   for a in ancestors for i in range(len(a.split("/")))):
                return False
        elif any(fnmatch.fnmatchcase(p, pattern) for p in parts[:-1]):
            return False
    return path == "README.md" or any(
        path.startswith(folder + "/") for folder in config["folders"]
    )


# Snapshot of documented service defaults, checked 2026-11-18. Custom lists replace them.
DEFAULT_FOLDERS = ['archive', 'archived', 'old', 'docs/old', 'deprecated', 'legacy', 'previous', 'outdated', 'superseded', '_snaps', 'benchmark', 'benchmarks', 'benches', 'i18n/zh*', 'i18n/es*', 'i18n/fr*', 'i18n/de*', 'i18n/ja*', 'i18n/ko*', 'i18n/ru*', 'i18n/pt*', 'i18n/it*', 'i18n/ar*', 'i18n/hi*', 'i18n/tr*', 'i18n/nl*', 'i18n/pl*', 'i18n/sv*', 'i18n/vi*', 'i18n/th*', 'zh-cn', 'zh-tw', 'zh-hk', 'zh-mo', 'zh-sg']
DEFAULT_FILES = ['CHANGELOG.md', 'changelog.md', 'CHANGELOG.mdx', 'changelog.mdx', 'LICENSE.md', 'license.md', 'CODE_OF_CONDUCT.md', 'code_of_conduct.md', 'NEWS.md']
assert set(DEFAULT_FOLDERS) <= set(config["excludeFolders"]), "Default folder exclusions lost"
assert set(DEFAULT_FILES) <= set(config["excludeFiles"]), "Default file exclusions lost"

assert config["folders"], "Empty folders would index the entire repository"
assert all("/" not in p and "\\" not in p for p in config["excludeFiles"])
assert len(config["excludeFolders"]) <= 50
assert len(config["excludeFiles"]) <= 100
for key in ("folders", "excludeFolders", "excludeFiles"):
    assert len(config[key]) == len(set(config[key])), f"Duplicate {key}"
for folder in config["folders"]:
    assert (ROOT / folder).is_dir(), f"Missing included directory: {folder}"

required = [
    "README.md", "docs/owned-auth-transactions.md", "docs/local-identities.md",
    "docs/host-authorization-snapshots.md", "docs/notification-delivery.md",
    "docs/notification-lifecycle.md", "docs/password-reset-recipients.md",
    "docs/v0.5-migration.md", "docs/v0.6-migration.md", "docs/project-contract.md",
    "examples/hostsession/README.md", "examples/nethttp/README.md",
]
blocked = [
    "docs/public-preview/implementation-plan.md", "docs/review-corrections.md",
    "docs/maintainers/context7-index.md", "implementation-notes.md",
    "AGENTS.md", "docs/browser-acceptance-fixture.md", "docs/release-verification.md",
    "docs/archive/README.md", "docs/i18n/ru/guide.md", "docs/CHANGELOG.md",
]
for path in required:
    assert (ROOT / path).is_file(), f"Missing consumer page: {path}"
    assert included(path), f"Consumer page excluded: {path}"
for path in blocked:
    assert not included(path), f"Internal/default-excluded page included: {path}"
assert included("docs/future-consumer-guide.md")
source = (ROOT / "postgres/host_transaction.go").read_text()
doc = (ROOT / "docs/owned-auth-transactions.md").read_text()
for signature in (
    "func (r *Runtime) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error",
    "func (r *Runtime) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error",
    "func (r *Runtime) SQLExecutor(ctx context.Context) (SQLExecutor, error)",
):
    assert signature + " {" in source, f"Source signature changed: {signature}"
    assert signature in doc, f"Documentation signature missing: {signature}"

paths = subprocess.check_output(
    ["git", "ls-files", "-z"], cwd=ROOT
).decode().split("\0")
pages = sorted(p for p in paths if p.endswith(".md") and included(p))
print(f"PASS: selection policy; {len(pages)} tracked Markdown pages selected")
print("\n".join(pages))
