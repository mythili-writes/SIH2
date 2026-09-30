# Contributing

This describes how the team works, as reflected in the repository history:
one branch per component, integrated on `integration` with a linear history.
Amend it if the team agrees on something different.

## Branches

| Branch | Purpose |
|---|---|
| `integration` | The combined, working pipeline. Every commit here should pass CI. |
| component branches, e.g. `ai-engine` | Work on one component (`backend`, `ai_engine`, `frontend`) by its owner. |
| `main` | Not on the remote yet. When created, it holds demo-ready snapshots cut from `integration`. |

## Workflow

1. Branch from the latest `integration`:
   ```bash
   git fetch origin
   git switch -c <component>/<short-topic> origin/integration
   ```
2. Keep the branch focused on one change. Rebase on `integration` rather than
   merging it in, to keep history linear:
   ```bash
   git fetch origin && git rebase origin/integration
   ```
3. Before pushing, run what CI runs:
   ```bash
   pip install -r requirements-dev.txt
   ruff check . && black --check . && python -m pytest
   ```
4. Open a pull request into `integration`. CI (lint, contract checks, tests
   on Python 3.10 and 3.12) must be green.
5. Ask for review from the owner of any component your change touches. A
   change to a data contract needs a review from the owners on both sides of
   it.
6. Merge with **rebase** or **squash** so `integration` stays linear.

## Commit messages

Short imperative subject, then a body explaining *why* when it is not obvious.
Either prefix style seen in the history is fine:

```
ai_engine: traffic classifier (Random Forest) + synthetic dataset
fix(backend): emit the canonical Contract A session shape
```

## Rules that protect the pipeline

**Data contracts.** `docs/CONTRACTS.md` defines what flows between the
stages. Changes are additive only: never rename, retype or remove a key. A
contract change updates the doc, the checker in `ai_engine/test_data/`, the
canonical example next to it, and the tests, all in the same pull request.

**Verified scores.** `tests/test_pipeline.py` pins the risk scores of the
bundled samples (80 / 46 / 5). If your change moves them, that is a change to
what the tool tells users: say so in the pull request and update the test
deliberately, never just to make CI pass.

**The traffic model.** `ai_engine/models/traffic_model.joblib` must be loaded
by the scikit-learn version pinned in `requirements.txt`. If you retrain it:
- use the pinned version (`python ai_engine/traffic_model.py train`)
- commit the model, `synthetic_dataset.csv` and `training_report.json`
  together
- update the accuracy figures in `ai_engine/README.md` from
  `training_report.json`
- regenerate `ai_engine/test_data/test_report.json` and the sample reports

**Dependencies.** Pin exact versions. Keep the component requirement files
in step with the root `requirements.txt`; a test fails if they drift.

**Settings.** New tunable values go in `config.py`, not inline. A new
environment variable must be documented in `.env.example`; a test fails if
it is not.

**Secrets.** Never commit an API key or a `.env` file. Logs must not contain
payloads, IP addresses or keys.

**Honesty in docs.** The README's Status section says what is validated on
real data and what is synthetic. Keep it true when you change behaviour.
