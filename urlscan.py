# urlscan.py
#
# Python library to query the URLscan.io API for data on domains, file hashes, and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

urlscan_api_key = 'your urlscan.io api key'
urlscan_base_url = 'https://urlscan.io/api/v1/'

def domain(domain: str):

    urlscan_session = requests.session()
    urlscan_session.verify = True
    urlscan_session.headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}
    urlscan_api_response = urlscan_session.get(urlscan_base_url + 'search/?q=domain:' + domain,headers=urlscan_session.headers)

    if(urlscan_api_response.status_code == 200):
        print(domain + ' found in URLscan')
        return json.loads(urlscan_api_response.text)

def hash(hash: str):

    urlscan_session = requests.session()
    urlscan_session.verify = True
    urlscan_session.headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}

    urlscan_api_response = urlscan_session.get(urlscan_base_url + 'search/?q=hash:' + hash,headers=urlscan_session.headers)

    if((urlscan_api_response.status_code == 200) and ("0" not in urlscan_api_response.text)):
        print('Response from URLscan.io')
        return json.loads(urlscan_api_response.text)

def ip(ip: str):

    urlscan_session = requests.session()
    urlscan_session.verify = True
    urlscan_session.headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}

    urlscan_api_response = urlscan_session.get(urlscan_base_url + 'search/?q=ip:' + ip,headers=urlscan_session.headers)

    if(urlscan_api_response.status_code == 200):
        print('Response from URLscan.io')
        return json.loads(urlscan_api_response.text)