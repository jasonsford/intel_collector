# circl.py
#
# Python library to query the Circl.lu API for data on file hashes. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

circl_base_url = 'https://hashlookup.circl.lu/lookup/'

def hash(indicator: str, indicator_type: str):

        circl_session = requests.session()
        circl_session.verify = True
        circl_session.headers = {'accept':'application/json'}

        circl_api_response = circl_session.get(circl_base_url + indicator_type + '/' + indicator,headers=circl_session.headers)
        
        if(circl_api_response.status_code == 200):
            print('Response from Circl.lu')
            return json.loads(circl_api_response.text)