# Contributing to llm-tripwire

Thanks for your interest in improving llm-tripwire. Bug reports, missed-leak reports, new canary kinds, decoy
templates and documentation fixes are all welcome.

## Getting set up

```bash
git clone https://github.com/OsamaWehbi/llm-tripwire.git
cd llm-tripwire
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Before you open a pull request

```bash
ruff check .
ruff format --check .
pytest
```

CI runs the same checks on Python 3.11, 3.12 and 3.13 on Linux and on Windows, plus Bandit, pip-audit and Gitleaks.

## Adding a detection transform

Transforms live in `src/llm_tripwire/detect.py`. Add a test in `tests/test_detect.py` that leaks a canary through the
new transform, and check that random text and near-miss IDs still produce no hits. False positives make canaries
useless, because the whole point is that every alert is real.

## Guidelines

- Open an issue first for larger changes so we can agree on the approach.
- Keep pull requests focused. One topic per PR is easier to review.
- Use conventional commit messages such as `feat`, `fix`, `docs`, `test` and `chore`.
- Never commit a real registry or real hit logs. Tests create canaries on the fly.
