# onyphe.py
#
# Python library to query the Onyphe Summary API for data on domains and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

onyphe_api_key = 'your onyphe api key'
onyphe_summary_base_url = 'https://www.onyphe.io/api/v2/summary/'

def domain(domain: str):

    onyphe_session = requests.session()
    onyphe_session.verify = True

    onyphe_summary_response = onyphe_session.get((onyphe_summary_base_url + 'domain/' + domain), headers={'Authorization':'apikey ' + onyphe_api_key})

    if "[]" not in onyphe_summary_response.text:
        print('Found in Onyphe')
        return json.loads(onyphe_summary_response.text)['results']

def ip(ip: str):

    onyphe_session = requests.session()
    onyphe_session.verify = True

    onyphe_summary_response = onyphe_session.get((onyphe_summary_base_url + 'ip/' + ip), headers={'Authorization': onyphe_api_key})

    if "[]" not in onyphe_summary_response.text:
        print('Found in Onyphe')
        return json.loads(onyphe_summary_response.text)['results']