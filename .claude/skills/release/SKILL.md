---
name: release
description: Cut a release of pyhubblenetwork — bumps version, generates release notes from commits, commits, tags, and pushes to trigger the PyPI release workflow. Use this skill when the user wants to release, publish, cut a release, bump version, or push a new version to PyPI. Invoke via /release.
user_invocable: true
---

# Release pyhubblenetwork

Automates the full release flow: version bump, release notes generation, commit, tag, and push. The tag push triggers the GitHub Actions workflow that runs tests, builds, creates a GitHub Release, and publishes to PyPI.

## Step 1: Pre-flight checks

Before anything else, verify the repo is in a clean, releasable state.

```bash
# All three checks in one go
git status --porcelain
git branch --show-current
git fetch origin main && git rev-list --left-right --count origin/main...HEAD
```

**Abort if:**
- Working tree has uncommitted changes (dirty status)
- Not on the `main` branch
- Local is behind remote (left count > 0 means remote has commits you don't have)

Tell the user what's wrong and how to fix it. Don't proceed.

## Step 2: Determine the new version

Read the current version from `pyproject.toml`:

```bash
python3 -c "
import tomllib
with open('pyproject.toml', 'rb') as f:
    data = tomllib.load(f)
print(data['project']['version'])
"
```

Parse into major.minor.patch and compute the three bump options. Present them to the user using AskUserQuestion with these options:

- **Patch** (X.Y.Z+1) — bug fixes, backwards compatible
- **Minor** (X.Y+1.0) — new features, backwards compatible
- **Major** (X+1.0.0) — breaking changes

Wait for the user to choose before continuing.

## Step 3: Generate release notes

Get commits since the last release tag:

```bash
git describe --tags --abbrev=0   # gets the last tag, e.g. v0.5.0
git log <last-tag>..HEAD --oneline
```

Categorize each commit by its conventional commit prefix:

| Prefix | Category heading |
|--------|-----------------|
| `feat` | `### Added` |
| `fix` | `### Fixed` |
| `docs` | `### Documentation` |
| `test` | `### Tests` |
| `chore`, `ci`, `build`, `refactor`, `perf`, `style` | `### Maintenance` |

**Skip** commits whose message starts with `chore: release` or `release: bump` — these are previous release commits.

Format each entry as a bullet matching the existing style in `release-notes.md`:
```
- feat(cli): add org delete-device command with confirmation prompt
```

Use the full commit subject line (the oneline message) as the bullet text. Only include category headings that have entries. Order categories: Added, Fixed, Documentation, Tests, Maintenance.

## Step 4: Present draft for review

Show the user the complete release notes entry that will be added:

```
## [X.Y.Z] - YYYY-MM-DD

### Added
- feat(...): ...

### Fixed
- fix(...): ...
```

Use AskUserQuestion with options:
- **Approve** — proceed with this draft as-is
- **Abort** — cancel the release

If the user picks "Other" to provide edits, apply their requested changes and show the updated draft again for confirmation.

## Step 5: Apply changes

Once approved:

1. **Update `pyproject.toml`**: Change the `version = "..."` line to the new version using the Edit tool.

2. **Update `release-notes.md`**: Insert the new release notes section immediately after the `# Release Notes` header (before the first `## [` entry) using the Edit tool.

3. **Commit**:
```bash
git add pyproject.toml release-notes.md
git commit -m "chore: release X.Y.Z"
```

## Step 6: Tag and push

```bash
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

After pushing, tell the user:
- The release workflow has been triggered
- Link them to check progress: `https://github.com/HubbleNetwork/pyhubblenetwork/actions`
- Remind them to approve the publish step in GitHub Actions (the `pypi` environment gate)
