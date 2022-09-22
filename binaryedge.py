# binaryedge.py
#
# Python library to query the binaryedge.io API for data on IP addresses.
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 22 September 2022

import json
import requests

binaryedge_api_key = 'your binaryedge api key'
binaryedge_base_url = 'https://api.binaryedge.io/v2/'

def ip(ip:str):

    binaryedge_session = requests.session()
    binaryedge_session.verify = True
    binaryedge_session.headers = {'X-Key':binaryedge_api_key,'Content-Type':'application/json'}
    binaryedge_api_response = binaryedge_session.get(binaryedge_base_url + 'query/ip/' + ip,headers=binaryedge_session.headers)

    if(binaryedge_api_response.status_code == 200):
        print('Response from binaryedge.io')
        return json.loads(binaryedge_api_response.text)