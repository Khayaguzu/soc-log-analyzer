# SOC Log Analyzer

A defensive Python command-line tool that converts authentication logs into prioritized security alerts. It demonstrates the work of a junior SOC analyst by validating telemetry, correlating events, assigning risk scores, mapping activity to MITRE ATT&CK, and producing investigation-ready reports.

> This project uses synthetic sample data and reserved documentation IP addresses. It does not attack systems or collect credentials.

## Detection capabilities

| Rule | Detection | Severity | MITRE ATT&CK |
|---|---|---:|---|
| SOC-001 | Five or more failures against one account from one IP within 10 minutes | High | T1110.001 Password Guessing |
| SOC-002 | One IP fails against five or more accounts within 15 minutes | High | T1110.003 Password Spraying |
| SOC-003 | A login succeeds after three or more recent failures | Critical | T1078 Valid Accounts |
| SOC-004 | One user logs in successfully from two countries within 60 minutes | High | T1078 Valid Accounts |

## Skills demonstrated

- Security log parsing and normalization
- Event correlation and rule-based threat detection
- Alert severity and risk scoring
- MITRE ATT&CK mapping
- Incident response recommendations
- Defensive input validation and error handling
- JSON and CSV report generation
- Python unit testing and modular design

## Quick start

### Requirements

- Python 3.10 or later
- No third-party runtime dependencies

### Run from source

```bash
git clone https://github.com/Khayaguzu/soc-log-analyzer.git
cd soc-log-analyzer
python -m venv .venv
```

Activate the environment on Windows:

```powershell
.venv\Scripts\activate
```

Install the project and run the sample investigation:

```bash
python -m pip install -e .
soc-log-analyzer data/sample_auth_logs.csv --json reports/alerts.json --csv reports/alerts.csv
```

Expected summary:

```text
Detected 4 alert(s)

SEVERITY   RISK   RULE      USER             SOURCE IP        TITLE
CRITICAL   95     SOC-003   analyst          203.0.113.50     Successful login after repeated failures
HIGH       88     SOC-004   manager          198.51.100.80    Potential impossible travel
HIGH       85     SOC-002   multiple         198.51.100.77    Possible password-spraying attack
HIGH       80     SOC-001   analyst          203.0.113.50     Possible brute-force attack
```

## Input format

The tool accepts normalized CSV logs with these columns:

```csv
timestamp,source_ip,username,outcome,country,event_id
2026-08-01T08:00:00,192.0.2.10,khaya,SUCCESS,ZA,EVT-001
```

- `timestamp` must use ISO 8601 format.
- `source_ip` must be a valid IPv4 or IPv6 address.
- `outcome` must be `SUCCESS` or `FAILURE`.
- `country` should be a two-letter country code.

## Testing

Run all automated tests:

```bash
python -m unittest discover -s tests -v
```

The test suite covers malicious patterns, normal activity, valid input, and malformed IP addresses.

## Project structure

```text
soc-log-analyzer/
├── data/
│   └── sample_auth_logs.csv
├── src/soc_log_analyzer/
│   ├── analyzer.py
│   ├── cli.py
│   ├── models.py
│   ├── parser.py
│   └── reporting.py
├── tests/
│   ├── test_analyzer.py
│   └── test_parser.py
├── LICENSE
├── pyproject.toml
└── README.md
```

## Analyst workflow

1. Collect and normalize authentication events.
2. Validate the log schema and values.
3. Correlate failures and successful logins by user, source, location, and time.
4. Prioritize alerts by severity and risk score.
5. Review the supporting event count and time range.
6. Follow the recommended containment and investigation actions.
7. Export the findings for reporting or further analysis.

## Limitations and roadmap

This educational version expects normalized CSV input. Country changes are treated as a teaching approximation of impossible travel and are not proof of compromise.

Planned improvements:

- Parse Windows Event and Linux authentication logs
- Add configurable YAML detection rules
- Enrich public IP addresses with threat-intelligence data
- Add a Streamlit investigation dashboard
- Add baseline-based anomaly detection
- Package the tool in a Docker container

## Responsible use

Use this project only with logs that you are authorized to access. Detection results should be validated by an analyst before response actions are taken.

## License

Licensed under the MIT License.
