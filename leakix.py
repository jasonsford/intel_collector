# leakix.py
#
# Python library to query the leakix.io API for data on IP addresses.
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 22 September 2022

import json
import requests

leakix_api_key = 'your leakix api key'
leakix_base_url = 'https://leakix.net/host/'

def ip(ip:str):

    leakix_request = leakix_base_url + ip
    leakix_response = requests.get(leakix_request, headers={'api-key':leakix_api_key,'Accept':'application/json'})

    if "[]" not in leakix_response.text:
        print('Response from leakix.com')
        return json.loads(leakix_response.text)