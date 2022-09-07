# etintel.py
#
# Python library to query the Emerging Threats Intelligence API for data on domains, file hashes, and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import requests
import json

etintel_api_key = 'your emerging threats intelligence api key'
etintel_base_url = 'https://api.emergingthreats.net/v1/'   

def domain(domain: str):
 
    etintel_session = requests.session()
    etintel_session.verify = True
    
    etintel_ips_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/ips'), headers={'Authorization': etintel_api_key})
    etintel_events_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/events'), headers={'Authorization': etintel_api_key})
    etintel_geoloc_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/geoloc'), headers={'Authorization': etintel_api_key})
    etintel_nameservers_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/nameservers'), headers={'Authorization': etintel_api_key})
    etintel_reputation_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/reputation'), headers={'Authorization': etintel_api_key})
    etintel_samples_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/samples'), headers={'Authorization': etintel_api_key})
    etintel_urls_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/urls'), headers={'Authorization': etintel_api_key})
    etintel_whois_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/whois'), headers={'Authorization': etintel_api_key})

    if "[]" not in etintel_ips_response.text:
        print('Found in Emerging Threats - IPs')
        return json.loads(etintel_ips_response.text)['response']

    if "[]" not in etintel_events_response.text:
        print('Found in Emerging Threats - Events')
        return json.loads(etintel_events_response.text)['response']

    if "[]" not in etintel_geoloc_response.text:
        print('Found in Emerging Threats - Geolocation')
        return json.loads(etintel_geoloc_response.text)['response']

    if "[]" not in etintel_nameservers_response.text:
        print('Found in Emerging Threats - Name Servers')
        return json.loads(etintel_nameservers_response.text)['response']

    if "[]" not in etintel_reputation_response.text:
        print('Found in Emerging Threats - Reputation')
        return json.loads(etintel_reputation_response.text)['response']

    if "[]" not in etintel_samples_response.text:
        print('Found in Emerging Threats - Samples')
        return json.loads(etintel_samples_response.text)['response']

    if "[]" not in etintel_urls_response.text:
        print('Found in Emerging Threats - URLs')
        return json.loads(etintel_urls_response.text)['response']

    if "[]" not in etintel_whois_response.text:
        print('Found in Emerging Threats - WHOIS')
        return json.loads(etintel_whois_response.text)['response']

def ip(ip: str):
    
    etintel_session = requests.session()
    etintel_session.verify = True
    
    etintel_domains_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/domains'), headers={'Authorization': etintel_api_key})
    etintel_events_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/events'), headers={'Authorization': etintel_api_key})
    etintel_geoloc_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/geoloc'), headers={'Authorization': etintel_api_key})
    etintel_reputation_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/reputation'), headers={'Authorization': etintel_api_key})
    etintel_samples_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/samples'), headers={'Authorization': etintel_api_key})
    etintel_urls_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/urls'), headers={'Authorization': etintel_api_key})

    if "[]" not in etintel_domains_response.text:
        print('Found in Emerging Threats - Domains')
        return json.loads(etintel_domains_response.text)['response']

    if "[]" not in etintel_events_response.text:
        print('Found in Emerging Threats - Events')
        return json.loads(etintel_events_response.text)['response']

    if "[]" not in etintel_geoloc_response.text:
        print('Found in Emerging Threats - Geolocation')
        return json.loads(etintel_geoloc_response.text)['response']

    if "[]" not in etintel_reputation_response.text:
        print('Found in Emerging Threats - Reputation')
        return json.loads(etintel_reputation_response.text)['response']
        
    if "[]" not in etintel_samples_response.text:
        print('Found in Emerging Threats - Samples')
        return json.loads(etintel_samples_response.text)['response']
        
    if "[]" not in etintel_urls_response.text:
        print('Found in Emerging Threats - URLs')
        return json.loads(etintel_urls_response.text)['response']

def hash(hash: str):
    
    etintel_session = requests.session()
    etintel_session.verify = True
    
    etintel_samples_response = etintel_session.get((etintel_base_url + 'samples/' + hash), headers={'Authorization': etintel_api_key})
    etintel_connections_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/connections'), headers={'Authorization': etintel_api_key})
    etintel_dnslookups_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/dns'), headers={'Authorization': etintel_api_key})
    etintel_httpreqs_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/http'), headers={'Authorization': etintel_api_key})
    etintel_events_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/events'), headers={'Authorization': etintel_api_key})

    if "[]" not in etintel_samples_response.text:
        print('Found in Emerging Threats - Samples')
        return json.loads(etintel_samples_response.text)['response']

    if "[]" not in etintel_connections_response.text:
        print('Found in Emerging Threats - Connections')
        return json.loads(etintel_connections_response.text)['response']

    if "[]" not in etintel_dnslookups_response.text:
        print('Found in Emerging Threats - DNS Lookups')
        return json.loads(etintel_dnslookups_response.text)['response']

    if "[]" not in etintel_httpreqs_response.text:
        print('Found in Emerging Threats - HTTP Requests')
        return json.loads(etintel_httpreqs_response.text)['response']

    if "[]" not in etintel_events_response.text:
        print('Found in Emerging Threats - Events')
        return json.loads(etintel_events_response.text)['response']