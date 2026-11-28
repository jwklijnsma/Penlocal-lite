# Why repetition matters

The blog's sharpest practical point: an LLM is non-deterministic, and runs
disagree *a lot* — one run found 16% of an app's vulns, another 95%. One run
counts the rest as missed. Because a local run is cheap, you repeat and merge.
Here that's `runs: 3` (config) or `--runs 3` (CLI): the whole task set runs N
times, candidate findings are pooled, *then* verified and assessed together.

---
