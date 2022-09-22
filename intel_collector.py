# intel_collector.py
#
# intel_collector is a Python library to query various sources of threat intelligence
# for data on domains, file hashes, and IP addresses. Responses are returned in JSON
# format and written to CSV.
#
# CrowdStrike Falcon and Microsoft Defender for Endpoint customers can also query
# their tenant for the presence of indicators within their own environment.
#
# github.com/jasonsford
# 22 September 2022

# Dependencies for file output
from datetime import datetime
import json

# Library to determine if user query is a valid domain, hash, or ip
from validate import isValidDomain, isValidFileHash, isValidIpAddress

# Free Resources 
import binaryedge   # BinaryEdge.io
import circl        # Circl.lu
import echotrail    # Echotrail.io
import filescan     # Filescan.io
import greynoise    # GreyNoise.io
import hybrid       # Hybrid Analysis
import leakix       # LeakIX
import netlas       # Netlas.io
import onyphe       # Onyphe
import pulsedive    # Pulsedive
import shodanpy     # Shodan
import stalkphish   # Stalkphish
import strato       # Stratosphere IPS
import triage       # Tria.ge
import urlhaus      # URLhaus
import urlscan      # URLscan.io
import virustotal   # VirusTotal

# Paid Resources
import crwd         # CrowdStrike
import etintel      # Emerging Threats Intelligence
import msde         # Microsoft Defender for Endpoint

class intel_collector:
    
    def find_domain(self, domain: str):

        validDomain = False
        # Check the input to determine if it is a valid TLD
        try:
            validDomain = isValidDomain(domain)
        except:
            pass

        if validDomain is True:
            # Store the current date and time so it can be appended to the name of the output file
            now = datetime.now()
            output_file = domain + "_" + now.strftime("%Y%m%d_%H%M%S") + ".csv"
            # Empty dictionary to store results from API calls
            results = {}
            
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

            # If the results dictionary is not empty, iterate through each key and write it to the output file
            if results != {}:
                with open(output_file, 'w') as output:
                    for key in results.keys():
                        output.write("%s, %s\n" % (key, json.dumps(results[key])))
                # Uncomment this line to return responses as JSON. Useful if you're passing output to another script.
                #return results
            else:
                print('No results for ' + domain)
        else:
            print(domain + ' is not a valid top level domain name.')

    def find_hash(self, hash: str):

        validFileHash = False
        # Check the input to determine if it is a valid file hash
        try:
            validFileHash = isValidFileHash(hash)
        except:
            pass

        if validFileHash is True:
            # Store the current date and time so it can be appended to the name of the output file
            now = datetime.now()
            output_file = hash + "_" + now.strftime("%Y%m%d_%H%M%S") + ".csv"
            # Empty dictionary to store results from API calls
            results = {}

            # Query the appropriate API based on the number of characters in the hash
            if(len(hash) == 32):
                results["Circl.lu"] = circl.hash(hash,'md5')             # Circl.lu
                results["CrowdStrike"] = crwd.iocs(hash,'md5')           # CrowdStrike Falcon
                results["Echotrail"] = echotrail.hash(hash)              # Echotrail.io
                results["Emerging Threats"] = etintel.hash(hash)         # Emerging Threats
                results["FileScan.io"] = filescan.hash(hash,'md5')       # Filescan.io
                results["Hybrid Analysis"] = hybrid.hash(hash)           # Hybrid Analysis
                results["Tria.ge"] = triage.iocs(hash,'md5')             # Tria.ge
                results["URLhaus"] = urlhaus.iocs(hash,'md5')            # Urlhaus
                results["VirusTotal"] = virustotal.hash(hash)            # VirusTotal
            if(len(hash) == 40):
                results["Circl.lu"] = circl.hash(hash,'sha1')            # Circl.lu
                results["FileScan.io"] = filescan.hash(hash,'sha1')      # Filescan.io
                results["Hybrid Analysis"] = hybrid.hash(hash)           # Hybrid Analysis
                results["Microsoft"] = msde.hash(hash)                   # Microsoft Defender for Endpoint            
                results["Tria.ge"] = triage.iocs(hash,'sha1')            # Tria.ge
                results["VirusTotal"] = virustotal.hash(hash)            # VirusTotal
            if(len(hash) == 64):
                results["Circl.lu"] = circl.hash(hash,'sha256')          # Circl.lu
                results["CrowdStrike"] = crwd.iocs(hash,'sha256')        # CrowdStrike Falcon
                results["Echotrail"] = echotrail.hash(hash)              # Echotrail.io
                results["FileScan.io"] = filescan.hash(hash,'sha256')    # Filescan.io
                results["Hybrid Analysis"] = hybrid.hash(hash)           # Hybrid Analysis
                results["Microsoft"] = msde.hash(hash)                   # Microsoft Defender for Endpoint
                results["Tria.ge"] = triage.iocs(hash,'sha256')          # Tria.ge
                results["URLhaus"] = urlhaus.iocs(hash,'sha256')         # Urlhaus
                results["URLScan"] = urlscan.hash(hash)                  # Urlscan.io
                results["VirusTotal"] = virustotal.hash(hash)            # VirusTotal
            if(len(hash) == 128):
                results["Tria.ge"] = triage.iocs(hash,'sha512')          # Tria.ge

            # If the results dictionary is not empty, iterate through each key and write it to the output file
            if results != {}:
                with open(output_file, 'w') as output:
                    for key in results.keys():
                        output.write("%s, %s\n" % (key, json.dumps(results[key])))
                # Uncomment this line to return responses as JSON. Useful if you're passing output to another script.
                #return results
            else:
                print('No results for ' + hash)

        else:
            print(hash + ' is not a valid file hash.')

    def find_ip(self, ip: str):
    
        validIpAddress = False
        # Check the input to determine if it is a valid IP address
        try:
            validIpAddress = isValidIpAddress(ip)
        except:
            pass

        if validIpAddress is True:
            # Store the current date and time so it can be appended to the name of the output file
            now = datetime.now()
            output_file = ip + "_" + now.strftime("%Y%m%d_%H%M%S") + ".csv"
            # Empty dictionary to store results from API calls
            results = {}

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

            # If the results dictionary is not empty, iterate through each key and write it to the output file
            if results != {}:
                with open(output_file, 'w') as output:
                    for key in results.keys():
                        output.write("%s, %s\n" % (key, json.dumps(results[key])))
                # Uncomment this line to return responses as JSON. Useful if you're passing output to another script.
                #return results
            else:
                print('No results for ' + ip)

        else:
            print(ip + ' is not a valid, publicly routable IPv4 address.')