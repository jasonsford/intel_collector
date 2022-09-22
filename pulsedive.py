# pulsedive.py
#
# Python library to query the pulsedive.io API for data on IP addresses.
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 22 September 2022

import json
import requests

pulsedive_api_key = 'your pulsedive api key'
pulsedive_base_url = 'https://pulsedive.com/api/info.php?indicator='

def iocs(indicator:str):

    pulsedive_session = requests.session()
    pulsedive_session.verify = True
    pulsedive_session.headers = {'X-Api-Key':pulsedive_api_key,'Content-Type':'application/json'}
    pulsedive_api_response = pulsedive_session.get(pulsedive_base_url + indicator,headers=pulsedive_session.headers)

    if(pulsedive_api_response.status_code == 200):
        print('Response from pulsedive.com')
        return json.loads(pulsedive_api_response.text)