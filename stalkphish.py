# stalkphish.py
#
# Python library to query the Stalkphish.io API for data on IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

stalkphish_api_key = 'your stalkphish api key'
stalkphish_base_url = 'https://www.stalkphish.io/api/v1/'

def ip(ip:str):

        stalkphish_session = requests.session()
        stalkphish_session.verify = True
        stalkphish_session.headers = {'Authorization':'Token ' + stalkphish_api_key}

        stalkphish_api_response = stalkphish_session.get(stalkphish_base_url + 'search/ipv4/' + ip)

        if(stalkphish_api_response.status_code == 200):
            print('Response from Stalkphish')
            return json.loads(stalkphish_api_response.text)