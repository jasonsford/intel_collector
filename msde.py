# msde.py
#
# Python library to query Microssoft Defender for Endpoint via the Graph API for data on domains, 
# file hashes, and IP addresses. Responses are returned in JSON format. This library can be used 
# independently or as part of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import json
import requests
import urllib.parse
import urllib.request

msft_base_url = 'https://login.windows.net/%s/oauth2/token'
msft_app_url = 'https://api.securitycenter.windows.com'

msft_tenant_id = 'your M365 tenant id'
msft_client_id = 'your M365 client id'
msft_client_secret = 'your M365 client secret'

def domain(domain: str):

        msft_session = requests.session()
        
        msft_payload = {'resource': msft_app_url,
                   'client_id': msft_client_id,
                   'client_secret': msft_client_secret,
                   'grant_type': 'client_credentials'}

        msft_data = urllib.parse.urlencode(msft_payload).encode("utf-8")

        msft_url = msft_base_url % msft_tenant_id

        msft_request = urllib.request.Request(msft_url, msft_data)
        msft_response = urllib.request.urlopen(msft_request)

        msft_auth_json = json.loads(msft_response.read())

        if('access_token' in msft_auth_json):

            msft_session_headers = {'Authorization': f'Bearer {msft_auth_json["access_token"]}',
                        'token_type': 'bearer',
                        'Content-Type': 'application/json'}

            msft_session.headers = msft_session_headers

            msft_domain_stats = msft_session.get(msft_app_url + '/api/domains/' + domain + '/stats')

            if(msft_domain_stats.status_code == 200):
                print('Found in Microsoft Defender for Endpoint - Domains')
                return json.loads(msft_domain_stats.text) 

            msft_session.close()

def hash(hash: str):

    msft_session = requests.session()
    
    msft_payload = {'resource': msft_app_url,
                'client_id': msft_client_id,
                'client_secret': msft_client_secret,
                'grant_type': 'client_credentials'}

    msft_data = urllib.parse.urlencode(msft_payload).encode("utf-8")

    msft_url = msft_base_url % msft_tenant_id

    msft_request = urllib.request.Request(msft_url, msft_data)
    msft_response = urllib.request.urlopen(msft_request)

    msft_auth_json = json.loads(msft_response.read())

    if('access_token' in msft_auth_json):

        msft_session_headers = {'Authorization': f'Bearer {msft_auth_json["access_token"]}',
                    'token_type': 'bearer',
                    'Content-Type': 'application/json'}

        msft_session.headers = msft_session_headers

        msft_globalfile_stats = msft_session.get(msft_app_url + '/api/files/' + hash)
        msft_orgfile_stats = msft_session.get(msft_app_url + '/api/files/' + hash + '/stats')

        if(msft_globalfile_stats.status_code == 200):
            print('Found in Microsoft Defender for Endpoint - Global File Stats')
            return json.loads(msft_globalfile_stats.text) 

        if(msft_orgfile_stats.status_code == 200):
            print('Found in Microsoft Defender for Endpoint - Organizational File Stats')
            return json.loads(msft_orgfile_stats.text) 

        msft_session.close()

def ip(ip: str):

    msft_session = requests.session()
    
    msft_payload = {'resource': msft_app_url,
                'client_id': msft_client_id,
                'client_secret': msft_client_secret,
                'grant_type': 'client_credentials'}

    msft_data = urllib.parse.urlencode(msft_payload).encode("utf-8")

    msft_url = msft_base_url % msft_tenant_id

    msft_request = urllib.request.Request(msft_url, msft_data)
    msft_response = urllib.request.urlopen(msft_request)

    msft_auth_json = json.loads(msft_response.read())

    if('access_token' in msft_auth_json):

        msft_session_headers = {'Authorization': f'Bearer {msft_auth_json["access_token"]}',
                    'token_type': 'bearer',
                    'Content-Type': 'application/json'}

        msft_session.headers = msft_session_headers

        msft_ip_stats = msft_session.get(msft_app_url + '/api/ips/' + ip + '/stats')

        if(msft_ip_stats.status_code == 200):
            print('Found in Microsoft Defender for Endpoint - IP Stats')
            return json.loads(msft_ip_stats.text)  

        msft_session.close()