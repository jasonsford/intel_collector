# crwd.py
#
# Python library to query the CrowdStrike Falcon Custom Indicator API for data on file hashes and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

crwd_client_id = 'your crowdstrike api client id'
crwd_client_secret = 'your crowdstrike api client secret'

crwd_base_url = 'https://api.crowdstrike.com'

def iocs(indicator: str, indicator_type: str):

    crwd_session = requests.session()
    crwd_session.verify = True
    
    crwd_payload = {'client_id': crwd_client_id, 'client_secret': crwd_client_secret}

    crwd_api_response = crwd_session.post(crwd_base_url + '/oauth2/token', data=crwd_payload)

    if(crwd_api_response.status_code == 201):

        headers =  {'Authorization': f'Bearer {crwd_api_response.json()["access_token"]}',
                    'token_type': 'bearer',
                    'Content-Type': 'application/json'}

        crwd_session.headers = headers

        crwd_params = {'type': indicator_type, 'value': indicator}

        crwd_getdetailedinfo = crwd_session.get(crwd_base_url + '/indicators/entities/iocs/v1', params=crwd_params)

        if(crwd_getdetailedinfo.status_code == 200):
            print('Response from CrowdStrike - Custom IOCs')
            return json.loads(crwd_getdetailedinfo.text)['resources']
            
    crwd_session.close()