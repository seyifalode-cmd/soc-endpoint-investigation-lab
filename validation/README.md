# Local validation scope

Install the pinned dependency in a virtual environment, then run:

```bash
python -m pip install -r requirements-validation.txt
python validation/check_project.py
```

The suite checks three YAML files for parsing, core sections, UUID uniqueness and experimental status; verifies the XML schema attribute and four broad collection categories; checks original PDF/figure hashes and local Markdown file links; and runs 24 synthetic cases against a deliberately limited interpreter of the selectors present in these files.

`synthetic-cases.json` is invented test data. It is not exported Sysmon telemetry and has no historical event timestamps. Its EventID mapping is a harness assumption for the three Sigma logsource categories. Each rule has eight cases, including positives, negatives and known scope boundaries.

The evaluator supports only literal exact-string values, endswith, contains, OR within a value list and AND between selections. Comparisons are case-insensitive. Missing fields and unexpected non-string values do not match. Unsupported operators and wildcards raise errors. This is not a general Sigma parser, semantic validator, conversion backend or SIEM engine.

The test covers the documented `Initiated: 'true'` string. A boolean fixture is deliberately rejected to make backend type conversion an explicit deployment requirement.

The saved [local report](../evidence/local-validation.txt) records the environment and actual pass results. Windows activity, PowerShell runtime/syntax validation, installed Sysmon schema acceptance, full Sigma semantics, backend translation, live alert generation and production quality measurement were not performed by these checks.
