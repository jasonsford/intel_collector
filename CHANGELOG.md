# Changelog
All notable changes to intel_collector will be documented here.

## [2.0.1] - 22 September 2022
### Added
Support for:
- BinaryEdge (IPs)
- LeakIX (IPs)
- Pulsedive (Domains, IPs)

## [2.0.0] - 7 September 2022
### Added
Support for:
- Stratosphere IPS | Czech Technical University (IPs) - Thank you to @bry_campbell for the suggestion :)

### Changed
- Intel sources now have their own libraries. API keys are set within each individual library.
- Individual libraries no longer parse JSON data to remove characters and format strings. Everything is returned as JSON
- Intel Collector will store results of each API call into a dictionary (results) with a key that corresponds to the API
- CLI output has been condensed. API calls that return a response will provide one of two outputs:
    - 'Found in <source>'
    - 'Response from <source>'
- validate.py library updated with new regex to check domain name submissions to ensure only top level domains (TLDs) are accepted

### Removed
Support for:
- Sorbs
- Spamhaus Zen

## [1.0.4] - 30 August 2022
### Added
Support for:
- Netlas.io (Domains, IPs)
- Input validation! The validate.py library allows intel_collector to check whether user input is a properly formatted domain name, IP address, or file hash of appropriate length

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