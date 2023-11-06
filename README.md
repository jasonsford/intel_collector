# intel_collector

intel collector is a Python library to query various sources of threat intelligence
for data on domains, file hashes, and IP addresses. Responses are returned in JSON
format and written to CSV.

CrowdStrike Falcon and Microsoft Defender for Endpoint customers can also query
their tenant for the presence of indicators within their own environment.

## Supported APIs
### Free Resources
BinaryEdge (binaryedge.io)
<br>Circl.lu (hashlookup.circl.lu)
<br>Echotrail (echotrail.io)
<br>Filescan.io (filescan.io)
<br>GreyNoise Community API (api.greynoise.io)
<br>Hybrid Analysis (hybrid-analysis.com)
<br>LeakIX (leakix.net)
<br>Netlas (app.netlas.io)
<br>Onyphe Free Tier (onyphe.io)
<br>PulseDive (pulsedive.com)
<br>Shodan (shodan.io)
<br>Stalkphish (stalkphish.io)
<br>Stratosphere IPS (stratosphereips.org)
<br>Triage (tria.ge)
<br>Urlhaus (urlhaus-api.abuse.ch)
<br>Urlscan.io (urlscan.io)
<br>VirusTotal (virustotal.com)

### Paid Resources
CrowdStrike Falcon Intel (api.crowdstrike.com)
<br>Emerging Threats Intelligence (api.emergingthreats.net)
<br>Microsoft Defender for Endpoint (api.securitycenter.windows.com)

## Setting API keys

API keys are set from within the library for each intel source.

```python
# binaryedge.py (BinaryEdge)
binaryedge_api_key = 'your binary edge api key'

# crwd.py (CrowdStrike)
crwd_client_id = 'your crowdstrike api client id'
crwd_client_secret = 'your crowdstrike api client secret'

# echotrail.py (Echotrail.io)
echotrail_api_key = 'your echotrail api key'

# etintel.py (Emerging Threats Intelligence)
etintel_api_key = 'your emerging threats intelligence api key'

# filescan.py (Filescan.io)
filescan_api_key = 'your filescan.io api key'

# greynoise.py (GreyNoise.io)
greynoise_api_key = 'your greynoise community api key'

# hybrid.py (Hybrid Analysis)
hybrid_api_key = 'your hybrid analysis api key'

# leakix.py (LeakIX)
leakix_api_key = 'your leakix api key'

# msde.py (Microsoft Defender for Endpoint)
msft_tenant_id = 'your M365 tenant id'
msft_client_id = 'your M365 client id'
msft_client_secret = 'your M365 client secret'

# netlas.py (Netlas.io)
netlas_api_key 'your netlas api key'

# onyphe.py (Onyphe)
onyphe_api_key = 'your onyphe api key'

# pulsedive.py (Pulsedive)
pulsedive_api_key = 'your pulsedive api key'

# shodanpy.py (Shodan)
shodan_api_key = 'your shodan api key'

# stalkphish.py (Stalkphish)
stalkphish_api_key = 'Token your stalkphish api key'

# triage.py (Tria.ge)
triage_api_key = 'your tria.ge api key'

# urlscan.py (Urlscan.io)
urlscan_api_key = 'your urlscan.io api key'

# virustotal.py (VirusTotal)
virustotal_api_key = 'your virustotal api key'
```

## Disabling Modules

All modules are enabled by default. Modules within each function can be disabled if you don't have an API key or don't wish to utilize them. Add # to the beginning of these lines as needed:     

```python

# Free Resources 
import binaryedge
import circl
import echotrail
import filescan
import greynoise
import hybrid
import leakix
import netlas
import onyphe
import pulsedive
import shodanpy
import stalkphish
import strato
import triage
import urlhaus
import urlscan
import virustotal

# Paid Resources
import crwd
import msde
import etintel

find_domain

    results["Emerging Threats"] = etintel.domain(domain)        # Emerging Threats
    results["Microsoft"] = msde.domain(domain)                  # Microsoft Defender for Endpoint
    results["Netlas"] = netlas.iocs(domain)                     # Netlas.io
    results["Onyphe"] = onyphe.domain(domain)                   # Onyphe
    results["Pulsedive"] = pulsedive.iocs(domain)               # Pulsedive
    results["Shodan"] = shodanpy.domain(domain)                 # Shodan
    results["Tria.ge"] = triage.iocs(domain,'domain')           # Tria.ge
    results["URLhaus"] = urlhaus.iocs(domain,'host')            # Urlhaus
    results["URLScan"] = urlscan.domain(domain)                 # Urlscan.io
    results["VirusTotal"] = virustotal.domain(domain)           # VirusTotal

find_hash

    results["Circl.lu"] = circl.hash(hash,'md5')         # Circl.lu
    results["CrowdStrike"] = crwd.iocs(hash,'md5')       # CrowdStrike Falcon
    results["Echotrail"] = echotrail.hash(hash)          # Echotrail.io
    results["Emerging Threats"] = etintel.hash(hash)     # Emerging Threats
    results["FileScan.io"] = filescan.hash(hash,'md5')   # Filescan.io
    results["Hybrid Analysis"] = hybrid.hash(hash)       # Hybrid Analysis
    results["Microsoft"] = msde.hash(hash)               # Microsoft Defender for Endpoint            
    results["Tria.ge"] = triage.iocs(hash,'sha1')        # Tria.ge
    results["URLhaus"] = urlhaus.iocs(hash,'sha256')     # Urlhaus
    results["URLScan"] = urlscan.hash(hash)              # Urlscan.io
    results["VirusTotal"] = virustotal.hash(hash)        # VirusTotal

find_ip

    results["BinaryEdge"] = binaryedge.ip(ip)            # BinaryEdge.io
    results["CrowdStrike"] = crwd.iocs(ip,'ipv4')        # CrowdStrike Falcon
    results["Emerging Threats"] = etintel.ip(ip)         # Emerging Threats
    results["GreyNoise"] = greynoise.ip(ip)              # GreyNoise
    results["LeakIX"] = leakix.ip(ip)                    # LeakIX
    results["Microsoft"] = msde.ip(ip)                   # Microsoft Defender for Endpoint
    results["Netlas"] = netlas.iocs(ip)                  # Netlas.io
    results["Onyphe"] = onyphe.ip(ip)                    # Onyphe
    results["Pulsedive"] = pulsedive.iocs(ip)            # Pulsedive
    results["Shodan"] = shodanpy.ip(ip)                  # Shodan
    results["Stalkphish"] = stalkphish.ip(ip)            # Stalkphish
    results["Stratosphere IPS"] = strato.ip(ip)          # Stratosphere IPS
    results["Tria.ge"] = triage.iocs(ip,'ip')            # Tria.ge
    results["URLhaus"] = urlhaus.iocs(ip,'host')         # Urlhaus
    results["URLScan"] = urlscan.ip(ip)                  # Urlscan.io
    results["VirusTotal"] = virustotal.ip(ip)            # VirusTotal
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
    Found in Microsoft Defender for Endpoint - Domains
    Found in Netlas.io
    Found in Onyphe
    Found in Shodan

```
```python
go.find_hash('870c31aa344b2950d0ea4849a472dafed312ecee8aa212c47bf543668bbee8e9')
```
```bash
    Response from Echotrail.io
    Found in Filescan.io
    Found in Hybrid Analysis
    Found in Microsoft Defender for Endpoint - Global File Stats
    Found in Tria.ge
    Found in VirusTotal - Files
```
```python
go.find_ip('103.161.17.242')
```
```bash
    Found in Emerging Threats - Events
    Response from GreyNoise
    Found in Microsoft Defender for Endpoint - IP Stats
    Found in Onyphe
    Found in Shodan
    Found in Stalkphish
    Response from URLscan.io
```
## Contributing
Pull requests are welcome. For major changes, please open an issue to discuss what you would like to change.

## Authors
[Jason Ford](http://jasonsford.com)

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
