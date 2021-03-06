# intel_collector

intel_collector is a Python library to query various sources of threat intelligence
for data on domains, file  hashes, and IP addresses. Responses that do not return
empty results are reformatted as comma separated values and written to CSV.

CrowdStrike Falcon Intel and Microsoft Defender for Endpoint customers can also query
their tenant for the presence of indicators within their own environment.

## Supported APIs

Circl.lu (hashlookup.circl.lu)
<br>CrowdStrike Falcon Intel (api.crowdstrike.com)
<br>Emerging Threats Intelligence (api.emergingthreats.net)
<br>Filescan.io (filescan.io)
<br>GreyNoise Community API (api.greynoise.io)
<br>Hybrid Analysis (hybrid-analysis.com)
<br>Microsoft Defender for Endpoint (api.securitycenter.windows.com)
<br>Onyphe Free Tier (onyphe.io)
<br>Shodan (shodan.io)
<br>Sorbs (sorbs.net)
<br>Spamhaus Zen (spamhaus.org)
<br>Stalkphish (stalkphish.io)
<br>Triage (tria.ge)
<br>Urlhaus (urlhaus-api.abuse.ch)
<br>Urlscan.io (urlscan.io)
<br>VirusTotal Free Tier (virustotal.com)

## Setting API keys

```python
# CrowdStrike
self.crwd_client_id = 'your crowdstrike api client id'
self.crwd_client_secret = 'your crowdstrike api client secret'

# Echotrail.io
self.echotrail_api_key = 'your echotrail api key'

# Emerging Threats Intelligence (Proofpoint)
self.etintel_api_key = 'your emerging threats intelligence api key'

# Filescan.io
self.filescan_api_key = 'your filescan.io api key'

# GreyNoise
self.greynoise_api_key = 'your greynoise community api key'

# Hybrid Analysis
self.hybrid_api_key = 'your hybrid analysis api key'

# Microsoft Defender for Endpoint
self.msft_tenant_id = 'your M365 tenant id'
self.msft_client_id = 'your M365 client id'
self.msft_client_secret = 'your M365 client secret'

# Onyphe
self.onyphe_api_key = 'apikey your onyphe api key'

# Shodan
self.shodan_api_key = 'your shodan api key'

# Stalkphish
self.stalkphish_api_key = 'your stalkphish api key'

# Tria.ge
self.triage_api_key = 'your tria.ge api key'

# Urlscan.io
self.urlscan_api_key = 'your urlscan.io api key'

# VirusTotal
self.virustotal_api_key = 'your virustotal api key'
```

## Disabling Modules

All modules are enabled by default. Modules within each function can be disabled if you don't have an API key or don't wish to utilize them. Add # to beginning of these lines as needed:     

```python
find_domain

    self.etintel_domain(domain)                 # Emerging Threats
    self.msft_domain(domain)                    # Microsoft Defender for Endpoint
    self.onyphe_domain(domain)                  # Onyphe
    self.shodan_domain(domain)                  # Shodan
    self.triage_iocs(domain,indicator_type)     # Tria.ge
    self.urlhaus_iocs(domain,indicator_type)    # Urlhaus
    self.urlscan_domain(domain)                 # Urlscan.io
    self.virustotal_domain(domain)              # VirusTotal

find_hash

    self.circl_hash(hash,indicator_type)        # Circl.lu
    self.crwd_iocs(hash,indicator_type)         # CrowdStrike Falcon
    self.echotrail_hash(hash,indicator_type)    # Echotrail.io
    self.etintel_hash(hash)                     # Emerging Threats
    self.filescan_hash(hash,indicator_type)     # Filescan.io
    self.hybrid_hash(hash)                      # Hybrid Analysis
    self.msft_hash(hash)                        # Microsoft Defender for Endpoint
    self.triage_iocs(hash,indicator_type)       # Tria.ge
    self.urlhaus_iocs(hash,indicator_type)      # Urlhaus
    self.urlscan_hash(hash)                     # Urlscan.io
    self.virustotal_hash(hash)                  # VirusTotal

find_ip

    self.crwd_iocs(ip,indicator_type)           # CrowdStrike Falcon
    self.etintel_ip(ip)                         # Emerging Threats
    self.greynoise(ip)                          # GreyNoise
    self.msft_ip(ip)                            # Microsoft Defender for Endpoint
    self.onyphe_ip(ip)                          # Onyphe
    self.shodan_ip(ip)                          # Shodan
    self.sorbs_ip(ip)                           # Sorbs
    self.spamhaus_ip(ip)                        # Spamhaus Zen
    self.stalkphish_ip(ip)                      # Stalkphish
    self.triage_iocs(ip,indicator_type)         # Tria.ge
    self.urlhaus_iocs(ip,indicator_type)        # Urlhaus
    self.urlscan_ip(ip)                         # Urlscan.io
    self.virustotal_ip(ip)                      # VirusTotal
```

## Usage
    
```python
# Import the library
from intel_collector import intel_collector

# Initialize client API keys and base URLs  
go = intel_collector()

# Get information on a domain
go.find_domain('bkdata.vn')

# Get information on an IP address
go.find_ip('103.161.17.242')

# Get information on a file hash
go.find_hash('870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9')
go.find_hash('1e5bc9d7e413ddd7902c2932e418702b84d0cc07')
go.find_hash('177f3c8a2623d4efb41b0020d680be83')
```
### Helpful hints for searching file hashes:

- The Circl.lu API supports the following indicator types (md5, sha1, sha256)
- The Crowdstrike Falcon API for custom IOCs supports the following indicator types (md5, sha256)
- The Echotrail API supports the following indicator types (md5, sha256)
- The ET Intel API supports the (md5) indicator type
- The Filescan.io API supports the following indicator types (md5, sha1, sha256)
- The Hybrid Analysis API supports the following indicator types (md5, sha1, sha256)
- The Microsoft Defender for Endpoint API supports the following indicator types (sha1, sha256)
- The Tria.ge API supports the following indicator types (md5, sha1, sha256, sha512)
- The Urlhaus API supports the following indicator types (md5, sha256)
- The Urlscan.io API supports the (sha256) indicator type
- The VirusTotal API supports the following indicator types (md5, sha1, shad256)

## Sample Output
 ```python   
go.find_domain('bkdata.vn')
```
```bash
    bkdata.vn found in Onyphe - Summary
    bkdata.vn found in Shodan
    bkdata.vn found in VirusTotal - Resolutions
    Results written to bkdata.vn_20220425_124237.csv
```
```python
go.find_hash('870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9')
```
```bash
    870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9 response from Microsoft Defender - Global File Info
    870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9 response from VirusTotal - File Report
    870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9 response from VirusTotal - File Behavior Reports
    Results written to 870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9_20220426_123337.csv
```
```python
go.find_ip('103.161.17.242')
```
```bash
    103.161.17.242 found in ET Intel - Events
    103.161.17.242 response from GreyNoise
    103.161.17.242 found in Onyphe - Summary
    103.161.17.242 found in Shodan
    Results written to 103.161.17.242_20220425_124237.csv
```
## Contributing
Pull requests are welcome. For major changes, please open an issue to discuss what you would like to change.

## Authors
[Jason Ford](https://twitter.com/JasonFord)

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)