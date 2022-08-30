# Changelog
All notable changes to intel_collector will be documented here.

## [1.0.4] - 30 August 2022
### Added
- Input validation to check whether input is a properly formatted domain name, IP address, or file hash of appropriate length (validate.py)
Support for:
- Netlas.io (Domains, IPs)

### Changed
- Updated README to reflect Free vs Paid API resources

### Removed
- List of APIs from within the script comments to leverage markdown in the README
- Excessive variables within functions. More code cleanup to come in 1.0.5 :-)

## [1.0.3] - 13 July 2022
### Added
Support for:
- Filescan.io (File Hashes)
- Tria.ge (Domains, File Hashes, IPs)

Support for:
- SHA512 file hashes (currently limited to Tria.ge)

### Removed
- Onyphe Simple Base URL

## [1.0.2] - 12 May 2022
### Added
Support for:
- Circl.lu (File Hashes)
- Echotrail.io (File Hashes)
- Urlhaus (Domains, File Hashes, IPs)

### Added
requirements.txt

## [1.0.1] - 4 May 2022
### Added
Support for:
- Hybrid Analysis
- Sorbs
- Spamhaus Zen
- Stalkphish
- Urlscan.io
### Fixed
- Updated logic for find_hash to properly identify indicator_type by hash length

## [1.0.0] - 26 April 2022
### Initial Release
Support for:
- CrowdStrike Falcon Intel
- Emerging Threats Intelligence
- GreyNoise Community API
- Microsoft Defender for Endpoint
- Onyphe Free Tier
- Shodan
- VirusTotal Free Tier