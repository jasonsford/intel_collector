# netlas.py
#
# Python library to query the Netlas.io API for data on domains and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

netlas_api_key = 'your netlas api key'
netlas_base_url = 'https://app.netlas.io'

def iocs(indicator: str):

        netlas_request = netlas_base_url + '/api/responses/?q=host%3A' + indicator
        netlas_response = requests.get(netlas_request, headers={'X-API-Key':netlas_api_key})
        
        if "[]" not in netlas_response.text:     
            print('Found in Netlas.io')
            return json.loads(netlas_response.text)['items']