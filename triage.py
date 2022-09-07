# triage.py
#
# Python library to query the Tria.ge API for data on domains, file hashes, and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

triage_api_key = 'your tria.ge api key'
triage_base_url = 'https://api.tria.ge/v0/'

def iocs(indicator: str, indicator_type: str):

        triage_session = requests.session()
        triage_session.verify = True
        triage_session.headers = {'Authorization':'Bearer ' + triage_api_key,'Content-Type':'application/json'}
        triage_api_response = triage_session.get(triage_base_url + 'search?query=' + indicator_type + ':' + indicator,headers=triage_session.headers)

        if((triage_api_response.status_code == 200) and ("null" not in triage_api_response.text)):
            print('Found in Tria.ge')
            return json.loads(triage_api_response.text)