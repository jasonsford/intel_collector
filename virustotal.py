# virustotal.py
#
# Python library to query the VirusTotal API for data on domains, file hashes, and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

virustotal_api_key = 'your virustotal api key'
virustotal_base_url = 'https://www.virustotal.com/api/v3/'

def domain(domain: str):

    virustotal_session = requests.session()
    virustotal_session.verify = True
    
    virustotal_commfiles_response = virustotal_session.get((virustotal_base_url + 'domains/' + domain + '/communicating_files'), headers={'x-apikey': virustotal_api_key})
    virustotal_resolutions_response = virustotal_session.get((virustotal_base_url + 'domains/' + domain + '/resolutions'), headers={'x-apikey': virustotal_api_key})
    virustotal_whois_response = virustotal_session.get((virustotal_base_url + 'domains/' + domain + '/historical_whois'), headers={'x-apikey': virustotal_api_key})

    if "[]" not in virustotal_commfiles_response.text:    
        print('Found in VirusTotal - Communicating Files')
        return json.loads(virustotal_commfiles_response.text)

    if "[]" not in virustotal_resolutions_response.text:    
        print('Found in VirusTotal - Resolutions')
        return json.loads(virustotal_resolutions_response.text)

    if "[]" not in virustotal_whois_response.text: 
        print('Found in VirusTotal - Historical WHOIS')
        return json.loads(virustotal_whois_response.text)

def ip(ip: str):

    virustotal_session = requests.session()
    virustotal_session.verify = True
    
    virustotal_whois_response = virustotal_session.get((virustotal_base_url + 'ip_addresses/' + ip + '/historical_whois'), headers={'x-apikey': virustotal_api_key})
    virustotal_commfiles_response = virustotal_session.get((virustotal_base_url + 'ip_addresses/' + ip + '/communicating_files'), headers={'x-apikey': virustotal_api_key})

    if "[]" not in virustotal_commfiles_response.text:    
        print('Found in VirusTotal - Communicating Files')
        return json.loads(virustotal_commfiles_response.text)

    if "[]" not in virustotal_whois_response.text: 
        print('Found in VirusTotal - Historical WHOIS')
        return json.loads(virustotal_whois_response.text)

def hash(hash: str):

    virustotal_session = requests.session()
    virustotal_session.verify = True

    virustotal_behavior_response = virustotal_session.get((virustotal_base_url + 'files/' + hash + '/behaviour_summary'), headers={'x-apikey': virustotal_api_key})
    virustotal_file_response = virustotal_session.get((virustotal_base_url + 'files/' + hash), headers={'x-apikey': virustotal_api_key})

    if "[]" not in virustotal_file_response.text:    
        print('Found in VirusTotal - Files')
        return json.loads(virustotal_file_response.text)
        
    if "[]" not in virustotal_behavior_response.text:    
        print('Found in VirusTotal - Behaviour Summary')
        return json.loads(virustotal_behavior_response.text)