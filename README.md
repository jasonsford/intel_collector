# intel_collector 

A consolidated threat intelligence aggregator that queries multiple public and enterprise APIs for domains, IP addresses, and file hashes.

## Key Features (v3.0)
- **Single-File Architecture**: All sources consolidated into one modular script using a registry pattern
- **Dynamic `.env` Routing**: Sources automatically enable/disable based on API key presence. Leave a key empty to skip that provider
- **Request Caching**: Built-in `requests-cache` deduplicates identical queries, saves API calls, and speeds up repeated recon runs
- **Web-Ready API**: Drop-in `get_intel_results()` function for FastAPI/Flask/Starlette backends
- **Verbose Logging**: Replaced `print()` statements with structured logging. Enable `--verbose` for `DEBUG`-level troubleshooting
- **Rate Limiting**: Configurable delay between API calls to respect provider limits and avoid throttling
- **Auto-Validation**: Strict IP, domain, and hash validation using Python's `ipaddress` stdlib and regex
- **Removed Sources**: BinaryEdge (decommissioned), EchoTrail (decommissioned), Onyphe (paid-only)

---

## Installation & Setup

### Install dependencies
pip install -r requirements.txt

### Configuration (`.env`)

All API keys are managed via a single `.env` file. Sources without configured keys are automatically skipped at runtime.

| Source | Required `.env` Variables |
|--------|---------------------------|
| **Circl.lu** | `CIRCL_API_KEY` |
| **CrowdStrike** | `CRWD_CLIENT_ID`, `CRWD_CLIENT_SECRET` |
| **Emerging Threats** | `ETINTEL_API_KEY` |
| **Filescan.io** | `FILESCAN_API_KEY` |
| **GreyNoise** | `GREYNOISE_API_KEY` |
| **Hybrid Analysis** | `HYBRID_API_KEY` |
| **LeakIX** | `LEAKIX_API_KEY` |
| **Microsoft Defender** | `MSDE_TENANT_ID`, `MSDE_CLIENT_ID`, `MSDE_CLIENT_SECRET` |
| **Netlas** | `NETLAS_API_KEY` |
| **Pulsedive** | `PULSEDIVE_API_KEY` |
| **Shodan** | `SHODAN_API_KEY` |
| **Stalkphish** | `STALKPHISH_API_KEY` |
| **Stratosphere IPS** | *(No key required)* |
| **Triage** | `TRIAGE_API_KEY` |
| **URLhaus** | `URLHAUS_API_KEY` |
| **URLScan** | `URLSCAN_API_KEY` |
| **VirusTotal** | `VIRUSTOTAL_API_KEY` |

---

## Usage

### Command Line Interface

```bash
# Query an IP address
python intel_collector.py 103.161.17.242 -t ip

# Query a domain (JSON output, limit to specific sources)
python intel_collector.py example.com -t domain --source Shodan VirusTotal

# CSV output with custom delay and verbose logging
python intel_collector.py 870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9 \
  -t hash --format csv --delay 1.0 --verbose --output-dir ./reports

# Disable file saving (stdout only)
python intel_collector.py malware.com -t domain --no-save
```

**CLI Arguments:**
| Flag | Description |
|------|-------------|
| `indicator` | Domain, IP, or SHA256/MD5/SHA1 hash |
| `-t, --type` | Force `domain`, `ip`, or `hash` |
| `-f, --format` | Output format: `json` (default) or `csv` |
| `-s, --source` | Limit to specific providers (space-separated) |
| `-o, --output-dir` | Directory for saved reports |
| `--no-save` | Skip file output, print to stdout only |
| `-d, --delay` | Rate limit delay between sources (seconds) |
| `-v, --verbose` | Enable DEBUG-level logging |

---

### Python API

```python
from intel_collector import IntelCollector

# Initialize collector with custom settings
collector = IntelCollector(
    output_dir="./reports",
    rate_limit_delay=0.5,
    verbose=False
)

# Run query (auto-detects indicator type)
result = collector.find("103.161.17.242", sources=["GreyNoise", "Shodan"], save_file=True)

# Access structured data
print(f"Queried: {result.sources_queried}")
print(f"Found in: {list(result.results.keys())}")
```

---

### Web Integration (FastAPI Example)

The built-in `get_intel_results()` function returns a strictly JSON-serializable dictionary, making it trivial to integrate with any web framework:

```python
from fastapi import FastAPI
from intel_collector import get_intel_results

app = FastAPI()

@app.get("/intel/{indicator}")
def lookup_indicator(indicator: str, indicator_type: str = None, source: str = None):
    sources = source.split(",") if source else None
    return get_intel_results(indicator, indicator_type=indicator_type, sources=sources, save=False)
```

**Response Format:**
```json
{
  "query_type": "ip",
  "query_value": "103.161.17.242",
  "timestamp": "2026-05-13T17:22:59.123456+00:00",
  "sources_queried": ["GreyNoise", "Shodan", "VirusTotal"],
  "results": {
    "GreyNoise": { "ip": "...", "noise": false },
    "VirusTotal": { "data": { "attributes": { ... } } }
  },
  "output_path": "./reports/103_161_17_242_20260513_172259.json"
}
```

---

## 📊 Supported Sources & Capabilities

| Source | Domains | IPs | Hashes | Auth Required |
|--------|---------|-----|--------|---------------|
| **Circl.lu** | ❌ | ❌ | ✅ | None |
| **CrowdStrike** | ❌ | ✅ | ✅ | `CRWD_*` |
| **Emerging Threats** | ✅ | ✅ | ✅ | `ETINTEL_API_KEY` |
| **Filescan.io** | ❌ | ❌ | ✅ | `FILESCAN_API_KEY` |
| **GreyNoise** | ❌ | ✅ | ❌ | `GREYNOISE_API_KEY` |
| **Hybrid Analysis** | ❌ | ❌ | ✅ | `HYBRID_API_KEY` |
| **LeakIX** | ❌ | ✅ | ❌ | `LEAKIX_API_KEY` |
| **Microsoft Defender** | ✅ | ✅ | ✅ | `MSDE_*` |
| **Netlas** | ✅ | ✅ | ❌ | `NETLAS_API_KEY` |
| **Pulsedive** | ✅ | ✅ | ✅ | `PULSEDIVE_API_KEY` |
| **Shodan** | ✅ | ✅ | ❌ | `SHODAN_API_KEY` |
| **Stalkphish** | ❌ | ✅ | ❌ | `STALKPHISH_API_KEY` |
| **Stratosphere IPS** | ❌ | ✅ | ❌ | None |
| **Triage** | ✅ | ✅ | ✅ | `TRIAGE_API_KEY` |
| **URLhaus** | ✅ | ❌ | ❌ | `URLHAUS_API_KEY` |
| **URLScan** | ✅ | ✅ | ✅ | `URLSCAN_API_KEY` |
| **VirusTotal** | ✅ | ✅ | ✅ | `VIRUSTOTAL_API_KEY` |

---

## Output & Logging

- **File Output**: Timestamped `.json` or `.csv` files saved to `output_dir/`
- **Console Output**: Structured logging with timestamps and severity levels
  ```
  2026-05-13 17:22:59 [INFO] intel_collector: → GreyNoise
  2026-05-13 17:22:59 [INFO] intel_collector: Warning: GreyNoise returned no data
  2026-05-13 17:22:59 [ERROR] intel_collector: Shodan unexpected error: ConnectionError
  2026-05-13 17:22:59 [INFO] intel_collector: Results saved to ./reports/103_161_17_242_20260513_172259.json
  ```
- **Caching**: `requests-cache` stores successful responses for 1 hour. Identical queries hit the cache instead of the network.

---

## Configuration & Modularity

- **Dynamic Source Routing**: The `SOURCES_REGISTRY` dict drives execution. Add new providers by defining a query function and appending to the registry.
- **Selective Execution**: Use `--source Shodan VirusTotal` or pass `sources=["Shodan", "VirusTotal"]` to limit scope.
- **Graceful Degradation**: Network failures, API rate limits, or missing keys are caught per-source. Other providers continue executing.
- **Extensible**: Designed for easy addition of new intelligence feeds following the established pattern.

---

## Contributing

Contributions are welcome! Please ensure:
1. New sources follow the existing function signature: `def <source>_query(indicator: str, indicator_type: str = None) -> Optional[Dict]`
2. All requests use `requests.Session()` with `timeout=10`
3. Add entries to `SOURCES_REGISTRY` with correct `env_keys` and `types`

---

## License

This project is licensed under the [GPLv3 License](https://choosealicense.com/licenses/gpl-3.0/).

---

## Author

**Jason Ford**  
GitHub: [github.com/jasonsford](https://github.com/jasonsford)  
LinkedIn: [JasonSFord](https://www.linkedin.com/in/jasonsford/)
