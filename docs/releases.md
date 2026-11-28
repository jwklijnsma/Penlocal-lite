# Releases

Releases are automatic, the same way as in ansreview:

| When | What |
|---|---|
| One of your pull requests is merged into `main` | a release right away (bot PRs such as Renovate don't start one) |
| Every Monday at 05:23 UTC | a release of whatever was merged since the last one, e.g. dependency updates |

Nothing happens when `main` has no commits since the last tag. The bump comes from
the labels on the PRs merged since the last release: `release:major` → major,
`release:minor` → minor, otherwise patch. Label a PR `no-release` to keep its
merge from starting one (it goes out with the next release).

The `release` workflow then runs the tests, bumps `__version__` in
`penlocal/__init__.py` (the only place the version lives), commits
`release: vX.Y.Z` to `main` with an annotated tag, builds the wheel (with the web
UI) and sdist, and creates the GitHub release with install lines and notes
generated from the merged PRs. Install a release with:

```bash
pip install https://github.com/jwklijnsma/penlocal-lite/releases/download/vX.Y.Z/penlocal_lite-X.Y.Z-py3-none-any.whl
```

By hand: **Actions › release › Run workflow**, or with the GitHub CLI:

```bash
make release                    # patch
make release BUMP=minor         # or BUMP=major, or VERSION=1.0.0
make release-dry-run            # test and build everything, publish nothing
```

---
