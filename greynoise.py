# greynoise.py
#
# Python library to query the GreyNoise.io API for data on IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests

greynoise_api_key = 'your greynoise community api key'
greynoise_base_url = 'https://api.greynoise.io/v3/community/'

def ip(ip: str):

    greynoise_session = requests.session()
    greynoise_session.verify = True

    greynoise_response = greynoise_session.get((greynoise_base_url + ip), headers={'key': greynoise_api_key})

    print('Response from GreyNoise.io')
    return json.loads(greynoise_response.text)