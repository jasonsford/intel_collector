#!/usr/bin/env python3

"""
intel_collector.py
v3.0

intel_collector is a Python library to query various sources of
threat intelligence for data on domains, file hashes, and IP addresses.

github.com/jasonsford
13 May 2026
"""

import os
import re
import csv
import json
import logging
import tempfile
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path

import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv
import requests_cache

# Configuration & Caching

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("intel_collector")

requests_cache.install_cache(
    cache_name="intel_cache",
    backend="sqlite",
    expire_after=3600,
    allowable_methods=["GET", "POST"],
    filter_fn=lambda response: response.status_code < 500
)

# Validation Helper Methods

def validate_domain(domain: str) -> bool:
    return bool(re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$", domain, re.IGNORECASE))

def validate_ip(ip: str) -> bool:
    try:
        addr = IPv4Address(ip)
        return not addr.is_private and not addr.is_reserved and not addr.is_loopback
    except ValueError:
        return False

def validate_hash(h: str) -> bool:
    return len(h) in (32, 40, 64, 128)

# Intel Sources

def circl_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    htype = {"32": "md5", "40": "sha1", "64": "sha256"}.get(str(len(indicator)))
    if not htype: return None
    with requests.Session() as s:
        s.headers.update({"accept": "application/json"})
        try:
            r = s.get(f"https://hashlookup.circl.lu/lookup/{htype}/{indicator}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                return {"prefixes": data if isinstance(data, list) else data.get("prefixes", [])}
            else: logger.error(f"Circl.lu API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Circl.lu Network Error: {e}"); return None

def crwd_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    cid, csecret = os.getenv("CRWD_CLIENT_ID"), os.getenv("CRWD_CLIENT_SECRET")
    if not cid or not csecret: return None
    htype = {"32": "md5", "64": "sha256", "128": "sha512"}.get(str(len(indicator)), "sha256")
    try:
        auth = requests.post("https://api.crowdstrike.com/oauth2/token", 
                             data={"client_id": cid, "client_secret": csecret}, timeout=10)
        if auth.status_code != 200: logger.error(f"CrowdStrike Auth Error ({auth.status_code}): {auth.text}"); return None
        token = auth.json()["access_token"]
    except RequestException as e: logger.error(f"CrowdStrike Network Error: {e}"); return None

    with requests.Session() as s:
        s.headers.update({"Authorization": f"Bearer {token}"})
        try:
            r = s.get("https://api.crowdstrike.com/indicators/entities/iocs/v1", 
                      params={"type": htype, "value": indicator}, timeout=10)
            if r.status_code == 200: return r.json().get("resources", [])
            else: logger.error(f"CrowdStrike API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"CrowdStrike Network Error: {e}"); return None

def etintel_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("ETINTEL_API_KEY")
    if not key: return None
    base = "https://api.emergingthreats.net/v1/"
    
    if indicator_type == "domain":
        endpoint = f"domains/{indicator}/reputation"
    elif indicator_type == "ip":
        endpoint = f"ips/{indicator}/reputation"
    elif indicator_type == "hash":
        endpoint = f"samples/{indicator}"
    else:
        return None
        
    with requests.Session() as s:
        s.headers.update({"Authorization": key})
        try:
            r = s.get(base + endpoint, timeout=10)
            if r.status_code == 200:
                res = r.json()
                return res.get("response", []) if res.get("response") else None
            else: logger.error(f"Emerging Threats API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Emerging Threats Network Error: {e}"); return None

def filescan_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("FILESCAN_API_KEY")
    if not key: return None
    htype = {"32": "md5", "40": "sha1", "64": "sha256"}.get(str(len(indicator)))
    if not htype: return None
    with requests.Session() as s:
        s.headers.update({"X-Api-Key": key})
        try:
            r = s.get(f"https://filescan.io/api/reports/search?{htype}={indicator}", timeout=10)
            if r.status_code == 200: return r.json()
            else: logger.error(f"Filescan API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Filescan Network Error: {e}"); return None

def greynoise_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("GREYNOISE_API_KEY")
    if not key: return None
    with requests.Session() as s:
        s.headers.update({"key": key})
        try:
            r = s.get(f"https://api.greynoise.io/v3/community/{indicator}", timeout=10)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                return None  # Valid "not found" response
            else:
                logger.error(f"GreyNoise API Error ({r.status_code}): {r.text}")
                return None
        except RequestException as e:
            logger.error(f"GreyNoise Network Error: {e}")
            return None

def hybrid_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("HYBRID_API_KEY")
    if not key: return None
    # Official API: GET /api/v2/search/hash?hash={indicator}
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    with requests.Session() as s:
        s.headers.update({"api-key": key, "accept": "application/json"})
        try:
            r = s.get(url, params={"hash": indicator}, timeout=10)
            if r.status_code == 200: return r.json()
            else: logger.error(f"Hybrid Analysis API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Hybrid Analysis Network Error: {e}"); return None

def leakix_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("LEAKIX_API_KEY")
    if not key: return None
    with requests.Session() as s:
        s.headers.update({"api-key": key, "Accept": "application/json"})
        try:
            r = s.get(f"https://leakix.net/host/{indicator}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                return data if data.get("hosts") else None
            else: logger.error(f"LeakIX API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"LeakIX Network Error: {e}"); return None

def msde_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    tid, cid, csec = os.getenv("MSDE_TENANT_ID"), os.getenv("MSDE_CLIENT_ID"), os.getenv("MSDE_CLIENT_SECRET")
    if not all([tid, cid, csec]): return None
    try:
        auth = requests.post(f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token",
                             data={"client_id": cid, "client_secret": csec, "grant_type": "client_credentials", 
                                   "scope": "https://api.securitycenter.windows.com/.default"}, timeout=10)
        if auth.status_code != 200: logger.error(f"Microsoft Defender Auth Error ({auth.status_code}): {auth.text}"); return None
        token = auth.json()["access_token"]
    except RequestException as e: logger.error(f"Microsoft Defender Network Error: {e}"); return None

    base = "https://api.securitycenter.windows.com"
    endpoint = f"/api/{indicator_type}s/{indicator}/stats" if indicator_type in ("domain", "ip") else f"/api/files/{indicator}"
    with requests.Session() as s:
        s.headers.update({"Authorization": f"Bearer {token}"})
        try:
            r = s.get(base + endpoint, timeout=10)
            if r.status_code == 200: return r.json()
            else: logger.error(f"Microsoft Defender API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Microsoft Defender Network Error: {e}"); return None

def netlas_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("NETLAS_API_KEY")
    if not key: return None
    with requests.Session() as s:
        s.headers.update({"X-API-Key": key})
        try:
            r = s.get(f"https://app.netlas.io/api/responses/?q=host%3A{indicator}", timeout=10)
            if r.status_code == 200: return r.json().get("items", [])
            else: logger.error(f"Netlas API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Netlas Network Error: {e}"); return None

def pulsedive_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("PULSEDIVE_API_KEY")
    if not key: return None
    # Official API: GET /api/indicator.php?indicator={ind}&key={key}
    url = "https://pulsedive.com/api/indicator.php"
    with requests.Session() as s:
        try:
            r = s.get(url, params={"indicator": indicator, "key": key, "pretty": 1}, timeout=10)
            if r.status_code == 200: return r.json()
            elif r.status_code == 404: return None  # Valid "not found" response
            else: logger.error(f"Pulsedive API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Pulsedive Network Error: {e}"); return None

def shodan_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("SHODAN_API_KEY")
    if not key: return None
    with requests.Session() as s:
        try:
            r = s.get(f"https://api.shodan.io/shodan/host/{indicator}", params={"key": key}, timeout=10)
            if r.status_code == 200: return r.json()
            elif r.status_code == 404: return None
            else: logger.error(f"Shodan API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Shodan Network Error: {e}"); return None

def stalkphish_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("STALKPHISH_API_KEY")
    if not key: return None
    with requests.Session() as s:
        s.headers.update({"Authorization": f"Token {key}"})
        try:
            r = s.get(f"https://www.stalkphish.io/api/v1/search/ipv4/{indicator}", timeout=10)
            if r.status_code == 200: return r.json()
            else: logger.error(f"Stalkphish API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"Stalkphish Network Error: {e}"); return None

def strato_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200: logger.error(f"Stratosphere Download Error ({r.status_code})"); return None
        with tempfile.NamedTemporaryFile(mode="w+", delete=True, suffix=".csv") as tmp:
            tmp.write(r.text); tmp.seek(0)
            if indicator in tmp.read(): return {"source": "Stratosphere IPS", "match": indicator, "list": "last_24h"}
    except RequestException as e: logger.error(f"Stratosphere Network Error: {e}")
    return None

def triage_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("TRIAGE_API_KEY")
    if not key:
        return None

    hash_len = len(indicator.strip())
    operator_map = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    operator = operator_map.get(hash_len)

    if not operator:
        logger.error(f"Triage API Error: Invalid hash length ({hash_len}). Expected 32, 40, 64, or 128.")
        return None

    query_str = f"{operator}:{indicator.strip().lower()}"
    url = "https://tria.ge/api/v0/search"

    with requests.Session() as s:
        s.headers.update({"Authorization": f"Bearer {key}"})
        try:
            r = s.get(url, params={"query": query_str}, timeout=10)
            if r.status_code == 200:
                return r.json().get("results") or []
            else:
                logger.error(f"Triage API Error ({r.status_code}): {r.text}")
                return None
        except RequestException as e:
            logger.error(f"Triage Network Error: {e}")
            return None

def urlhaus_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    if indicator_type != "domain":
        return None
        
    key = os.getenv("URLHAUS_API_KEY")
    if not key:
        logger.warning("URLHAUS_API_KEY not set. Domain lookup skipped.")
        return None
    
    with requests.Session() as s:
        file_url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/hostfile.txt"
        try:
            r = s.get(file_url, timeout=30)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 2 and (indicator.strip() == parts[0].strip() or indicator.strip() == parts[1].strip()):
                        return {"source": "URLhaus", "match_type": "hostfile", "indicator": indicator}
                return None
            else:
                logger.error(f"URLHaus v2 File Download Error ({r.status_code}): {r.text}")
                return None
        except RequestException as e:
            logger.error(f"URLHaus v2 Network Error: {e}")
            return None


def urlscan_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("URLSCAN_API_KEY")
    if not key: return None
    with requests.Session() as s:
        s.headers.update({"API-Key": key})
        try:
            r = s.get("https://urlscan.io/api/v1/search/", params={"q": f"{indicator_type}:{indicator}"}, timeout=10)
            if r.status_code == 200: return r.json()
            else: logger.error(f"URLScan API Error ({r.status_code}): {r.text}"); return None
        except RequestException as e: logger.error(f"URLScan Network Error: {e}"); return None

def virustotal_query(indicator: str, indicator_type: str = None) -> Optional[Dict]:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key: return None

    vt_resources = {
        "ip": "ip_addresses",
        "domain": "domains",
        "hash": "files"
    }
    resource = vt_resources.get(indicator_type)
    if not resource: return None

    with requests.Session() as s:
        s.headers.update({"x-apikey": key, "accept": "application/json"})
        try:
            r = s.get(f"https://www.virustotal.com/api/v3/{resource}/{indicator}", timeout=10)
            
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                return None  # Valid state: IOC not yet indexed by VT
            else:
                logger.error(f"VirusTotal API Error ({r.status_code}): {r.text}")
                return None
        except RequestException as e:
            logger.error(f"VirusTotal Network Error: {e}")
            return None

# Intel Source Routing

SOURCES_REGISTRY = [
    {"name": "Circl.lu", "env_keys": [], "types": {"hash"}, "func": circl_query},
    {"name": "CrowdStrike", "env_keys": ["CRWD_CLIENT_ID", "CRWD_CLIENT_SECRET"], "types": {"ip", "hash"}, "func": crwd_query},
    {"name": "Emerging Threats", "env_keys": ["ETINTEL_API_KEY"], "types": {"domain", "ip", "hash"}, "func": etintel_query},
    {"name": "Filescan.io", "env_keys": ["FILESCAN_API_KEY"], "types": {"hash"}, "func": filescan_query},
    {"name": "GreyNoise", "env_keys": ["GREYNOISE_API_KEY"], "types": {"ip"}, "func": greynoise_query},
    {"name": "Hybrid Analysis", "env_keys": ["HYBRID_API_KEY"], "types": {"hash"}, "func": hybrid_query},
    {"name": "LeakIX", "env_keys": ["LEAKIX_API_KEY"], "types": {"ip"}, "func": leakix_query},
    {"name": "Microsoft Defender", "env_keys": ["MSDE_TENANT_ID", "MSDE_CLIENT_ID", "MSDE_CLIENT_SECRET"], "types": {"domain", "ip", "hash"}, "func": msde_query},
    {"name": "Netlas", "env_keys": ["NETLAS_API_KEY"], "types": {"domain", "ip"}, "func": netlas_query},
    {"name": "Pulsedive", "env_keys": ["PULSEDIVE_API_KEY"], "types": {"domain", "ip", "hash"}, "func": pulsedive_query},
    {"name": "Shodan", "env_keys": ["SHODAN_API_KEY"], "types": {"domain", "ip"}, "func": shodan_query},
    {"name": "Stalkphish", "env_keys": ["STALKPHISH_API_KEY"], "types": {"ip"}, "func": stalkphish_query},
    {"name": "Stratosphere IPS", "env_keys": [], "types": {"ip"}, "func": strato_query},
    {"name": "Triage", "env_keys": ["TRIAGE_API_KEY"], "types": {"hash"}, "func": triage_query},
    {"name": "URLhaus", "env_keys": ["URLHAUS_API_KEY"], "types": {"domain"}, "func": urlhaus_query},
    {"name": "URLScan", "env_keys": ["URLSCAN_API_KEY"], "types": {"domain", "ip", "hash"}, "func": urlscan_query},
    {"name": "VirusTotal", "env_keys": ["VIRUSTOTAL_API_KEY"], "types": {"domain", "ip", "hash"}, "func": virustotal_query},
]

def get_enabled_sources(indicator_type: str, force_sources: Optional[List[str]] = None) -> List[Dict]:
    enabled = []
    for src in SOURCES_REGISTRY:
        if indicator_type not in src["types"]: continue
        if force_sources and src["name"] not in force_sources: continue
        if all(os.getenv(k) for k in src["env_keys"]): enabled.append(src)
    return enabled

# Orchestration

@dataclass
class QueryResult:
    query_type: str
    query_value: str
    timestamp: str
    sources_queried: List[str]
    results: Dict[str, Any]
    output_path: Optional[str] = None

class IntelCollector:
    def __init__(self, output_dir: str = ".", rate_limit_delay: float = 0.5, verbose: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.delay = rate_limit_delay
        if verbose: logging.getLogger().setLevel(logging.DEBUG)

    def _validate_and_route(self, indicator: str, forced_type: Optional[str] = None) -> str:
        auto_detected = None
        if validate_domain(indicator): auto_detected = "domain"
        elif validate_ip(indicator): auto_detected = "ip"
        elif validate_hash(indicator): auto_detected = "hash"

        if forced_type:
            if auto_detected and forced_type != auto_detected:
                logger.warning(f"Forced type '{forced_type}' does not match auto-detected type '{auto_detected}'. Proceeding with forced type.")
            return forced_type
        elif auto_detected:
            return auto_detected
        else:
            raise ValueError(f"Unrecognized indicator format: {indicator}")

    def find(self, indicator: str, indicator_type: Optional[str] = None, sources: Optional[List[str]] = None, save_file: bool = True) -> QueryResult:
        indicator_type = self._validate_and_route(indicator, forced_type=indicator_type)
        
        if indicator_type:
            is_valid = False
            if indicator_type == "domain": is_valid = validate_domain(indicator)
            elif indicator_type == "ip": is_valid = validate_ip(indicator)
            elif indicator_type == "hash": is_valid = validate_hash(indicator)
            
            if not is_valid:
                logger.warning(f"Indicator '{indicator}' does not match forced type '{indicator_type}'. Skipping queries.")
                return QueryResult(indicator_type, indicator, datetime.now(timezone.utc).isoformat(), [], {})
        
        enabled = get_enabled_sources(indicator_type, force_sources=sources)
        
        if not enabled:
            logger.warning("No enabled sources configured for this indicator type.")
            return QueryResult(indicator_type, indicator, datetime.now(timezone.utc).isoformat(), [], {})
    
        results = {}
        logger.info(f"Polling {len(enabled)} source(s) for {indicator_type}: {indicator}")

        for src in enabled:
            logger.info(f"→ {src['name']}")
            try:
                data = src["func"](indicator, indicator_type)
                if data:
                    results[src["name"]] = data
                else:
                    logger.info(f"Warning: {src['name']} returned no data")
                time.sleep(self.delay)
            except Exception as e:
                logger.error(f"{src['name']} unexpected error: {e}")

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^\w\-_]", "_", indicator)
        output_path = None

        if results and save_file:
            json_path = self.output_dir / f"{safe_name}_{ts}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            output_path = str(json_path)
            logger.info(f"Results saved to {json_path}")

        return QueryResult(indicator_type, indicator, datetime.now(timezone.utc).isoformat(), 
                           [s["name"] for s in enabled], results, output_path)

    def to_dict(self, result: QueryResult) -> Dict[str, Any]:
        return {
            "query_type": result.query_type,
            "query_value": result.query_value,
            "timestamp": result.timestamp,
            "sources_queried": result.sources_queried,
            "results": result.results,
            "output_path": result.output_path
        }

# Web Helper Method

def get_intel_results(indicator: str, indicator_type: Optional[str] = None, 
                      sources: Optional[List[str]] = None, save: bool = True, verbose: bool = False) -> Dict[str, Any]:
    if indicator_type and not any([validate_domain(indicator), validate_ip(indicator), validate_hash(indicator)]):
        return {"error": "Invalid indicator format", "status": 400}
        
    collector = IntelCollector(verbose=verbose)
    try:
        result = collector.find(indicator, indicator_type=indicator_type, sources=sources, save_file=save)
        return collector.to_dict(result)
    except ValueError as e:
        return {"error": str(e), "status": 400}
    except Exception as e:
        logger.exception("Unhandled error in get_intel_results")
        return {"error": "Internal server error", "status": 500}

# Command Line Entry Point

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Intel Collector")
    parser.add_argument("indicator", help="Domain, IP address, or file hash")
    parser.add_argument("--type", "-t", choices=["domain", "ip", "hash"], help="Force indicator type")
    parser.add_argument("--format", "-f", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--source", "-s", nargs="+", help="Limit to specific sources by name")
    parser.add_argument("--output-dir", "-o", default=".", help="Directory to save results")
    parser.add_argument("--no-save", action="store_true", help="Disable file output")
    parser.add_argument("--delay", "-d", type=float, default=0.5, help="Rate limit delay between sources (seconds)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debugging logs")
    args = parser.parse_args()

    collector = IntelCollector(output_dir=args.output_dir, rate_limit_delay=args.delay, verbose=args.verbose)
    result = collector.find(args.indicator, indicator_type=args.type, sources=args.source, save_file=not args.no_save)
    
    # Only print results if actual intelligence data was returned
    if result.results:
        print("\n--- Collection Results ---")
        print(json.dumps(collector.to_dict(result), indent=2, default=str))
        
        if args.format == "csv" and result.results:
            csv_path = result.output_path.replace(".json", ".csv") if result.output_path else "output.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Source", "Data"])
                for src, data in result.results.items():
                    writer.writerow([src, json.dumps(data, default=str)])
            print(f"CSV saved to: {csv_path}")
