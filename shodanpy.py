# shodanpy.py
#
# Python library to query the Shodan API for data on domains and IP addresses. 
# Responses are returned in JSON format. This library can be used independently or as part 
# of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import shodan

shodan_api_key = 'your shodan api key'

def domain(domain: str):

    shodan_api = shodan.Shodan(shodan_api_key)       

    try:
        print('Found in Shodan')
        return shodan_api.dns.domain_info(domain)

    except shodan.APIError as error:
        pass

def ip(ip: str):

    shodan_api = shodan.Shodan(shodan_api_key)       

    try:
        print('Found in Shodan')
        return shodan_api.host(ip)

    except shodan.APIError as error:
        pass