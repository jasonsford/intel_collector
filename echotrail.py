# echotrail.py
#
# Python library to query the Echotrail.io API for data on file hashes.
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

echotrail_api_key = 'your echotrail api key'
echotrail_base_url = 'https://api.echotrail.io/v1/private/insights/'

def hash(hash:str):

    echotrail_session = requests.session()
    echotrail_session.verify = True
    echotrail_session.headers = {'X-Api-Key':echotrail_api_key,'Content-Type':'application/json'}
    echotrail_api_response = echotrail_session.get(echotrail_base_url + hash,headers=echotrail_session.headers)

    if(echotrail_api_response.status_code == 200):
        print('Response from Echotrail.io')
        return json.loads(echotrail_api_response.text)