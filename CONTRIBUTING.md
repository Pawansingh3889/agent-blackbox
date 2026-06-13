# Contributing

Thanks for taking a look. This is a small, focused tool and the aim is to keep it that way: record agent actions to a tamper-evident log, on-prem, with no dependencies.

## Getting set up

```bash
git clone https://github.com/Pawansingh3889/agent-blackbox
cd agent-blackbox
pip install -e ".[dev]"
python -m pytest -q
```

## Ground rules

- Standard library only in the core package. The zero-dependency, runs-anywhere property is the point; please don't add runtime deps.
- Anything that changes how a row is hashed or chained must keep `verify()` honest. Add a test that tampers with the data and proves `verify()` catches it.
- Keep the surface small. One clear job done well beats more options.

## Good first issues

Check the issues tab for ones tagged `good first issue`. Open a draft PR early if you want feedback before it's finished.

## Tests

Every change needs a test. The existing ones in `tests/test_ledger.py` are a good template, especially the tamper-detection cases.
