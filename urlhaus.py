# urlhaus.py
#
# Python library to query the URLhaus API for data on domains, file hashes, and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

urlhaus_base_url = 'https://urlhaus-api.abuse.ch/v1'

def iocs(indicator: str, indicator_type: str):

        urlhaus_session = requests.session()
        urlhaus_session.verify = True

        urlhaus_data = {indicator_type:indicator}
        
        if(indicator_type == 'host'):
            urlhaus_api_response = urlhaus_session.post(urlhaus_base_url + 'host/', urlhaus_data, headers=urlhaus_session.headers)
        else:
            urlhaus_api_response = urlhaus_session.post(urlhaus_base_url + 'payload/', urlhaus_data, headers=urlhaus_session.headers)

        if((urlhaus_api_response.status_code == 200) and ("no_results" not in urlhaus_api_response.text)):
            print('Response from URLhaus')
            return json.loads(urlhaus_api_response.text)