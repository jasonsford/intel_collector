# hybrid.py
#
# Python library to query the Hybrid Analyis API for data on file hashes.
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

hybrid_api_key = 'your hybrid analysis api key'
hybrid_base_url = 'https://www.hybrid-analysis.com/api/v2/'
        
def hash(hash: str):

    hybrid_session = requests.session()
    hybrid_session.verify = True
    hybrid_session.headers = {'api-key':hybrid_api_key,'user-agent':'Falcon Sandbox','accept':'application/json','Content-Type':'application/x-www-form-urlencoded'}

    hybrid_api_response = hybrid_session.post(hybrid_base_url + 'search/hash','hash=' + hash)

    if(hybrid_api_response.status_code == 200):
        print('Found in Hybrid Analysis')
        return json.loads(hybrid_api_response.text)