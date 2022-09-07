# filescan.py
#
# Python library to query the Filescan.io API for data on file hashes.
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

filescan_api_key = 'your filescan.io api key'
filescan_base_url = 'https://filescan.io/api/'

def hash(hash: str, indicator_type: str):

        filescan_session = requests.session()
        filescan_session.verify = True
        filescan_session.headers = {'X-Api-Key':filescan_api_key,'Content-Type':'application/json'}
        
        filescan_api_response = filescan_session.get(filescan_base_url + 'reports/search?' + indicator_type + '=' + hash,headers=filescan_session.headers)

        if(filescan_api_response.status_code == 200):
            print('Found in Filescan.io')
            return json.loads(filescan_api_response.text)