# intel_collector.py
#
# intel_collector is a Python library to query various sources of threat intelligence
# for data on domains, files hashes, and IP addresses. Responses that do not return 
# empty results are reformatted as comma separated values and written to CSV.
#
# CrowdStrike Falcon and Microsoft Defender for Endpoint customers can also query
# their tenant for the presence of indicators within their own environment.
# 
# APIs Currently supported:
#
#   CrowdStrike (falcon.crowdstrike.com)
#   Emerging Threats Intelligence (emergingthreats.net)
#   GreyNoise Community API (greynoise.io)
#   Microsoft Defender for Endpoint (api.securitycenter.windows.com)
#   Onyphe Free Tier (onyphe.io)
#   Shodan (shodan.io)
#   VirusTotal Free Tier (virustotal.com)
#
# github.com/jasonsford
# 26 April 2022

import json
import requests
import shodan
import urllib.request
import urllib.parse
from datetime import datetime
from os.path import exists

class intel_collector:
    
    def __init__(self):
    
        # CrowdStrike
        self.crwd_base_url = 'https://api.crowdstrike.com'
        self.crwd_client_id = 'your crowdstrike api client id'
        self.crwd_client_secret = 'your crowdstrike api client secret'
        
        # Emerging Threats Intelligence (Proofpoint)
        self.etintel_base_url = 'https://api.emergingthreats.net/v1/'
        self.etintel_api_key = 'your emerging threats intelligence api key'
        
        # GreyNoise
        self.greynoise_base_url = 'https://api.greynoise.io/v3/community/'
        self.greynoise_api_key = 'your greynoise community api key'
        
        # Microsoft
        self.msft_base_url = 'https://login.windows.net/%s/oauth2/token'
        self.msft_app_url = 'https://api.securitycenter.windows.com'
        self.msft_tenant_id = 'your M365 tenant id'
        self.msft_client_id = 'your M365 client id'
        self.msft_client_secret = 'your M365 client secret'
        
        # Onyphe
        self.onyphe_simple_base_url = 'https://www.onyphe.io/api/v2/simple/'
        self.onyphe_summary_base_url = 'https://www.onyphe.io/api/v2/summary/'
        self.onyphe_api_key = 'apikey your onyphe api key'
        
        # Shodan
        self.shodan_api_key = 'your shodan api key'
        
        # VirusTotal
        self.virustotal_base_url = 'https://www.virustotal.com/api/v3/'
        self.virustotal_api_key = 'your virustotal api key'

    def find_domain(self, domain: str):

        now = datetime.now()
        self.flat_output_file = domain + "_" + now.strftime("%Y%m%d_%H%M%S") + ".csv"

        self.etintel_domain(domain)     # Proofpoint Emerging Threats
        self.msft_domain(domain)        # Microsoft Defender for Endpoint
        self.onyphe_domain(domain)      # Onyphe
        self.shodan_domain(domain)      # Shodan
        self.virustotal_domain(domain)  # VirusTotal

        if(exists(self.flat_output_file) == True):
            print('Results written to ' + self.flat_output_file)

    def find_hash(self, hash: str):

        now = datetime.now()
        self.flat_output_file = hash + "_" + now.strftime("%Y%m%d_%H%M%S") + ".csv"

        if(len(hash) == 32):
            self.crwd_iocs(hash,'md5')      # CrowdStrike Falcon
        if(len(hash) == 64):
            self.crwd_iocs(hash,'sha256')   # CrowdStrike Falcon
        if(len(hash) == 32):
            self.etintel_hash(hash)         # Proofpoint Emerging Threats
        if((len(hash) == 40) or (len(hash) == 64)):
            self.msft_hash(hash)            # Microsoft Defender for Endpoint            
        self.virustotal_hash(hash)          # VirusTotal

        if(exists(self.flat_output_file) == True):
            print('Results written to ' + self.flat_output_file)

    def find_ip(self, ip: str):
    
        now = datetime.now()
        self.flat_output_file = ip + "_" + now.strftime("%Y%m%d_%H%M%S") + ".csv"

        self.crwd_iocs(ip,'ipv4')       # CrowdStrike Falcon
        self.etintel_ip(ip)             # Proofpoint Emerging Threats
        self.greynoise(ip)              # GreyNoise
        self.msft_ip(ip)                # Microsoft Defender for Endpoint
        self.onyphe_ip(ip)              # Onyphe
        self.shodan_ip(ip)              # Shodan
        self.virustotal_ip(ip)          # VirusTotal   

        if(exists(self.flat_output_file) == True):        
            print('Results written to ' + self.flat_output_file)

    def crwd_iocs(self, indicator: str, indicator_type: str):

        crwd_base_url = self.crwd_base_url
        crwd_client_id = self.crwd_client_id
        crwd_client_secret = self.crwd_client_secret
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
                event_array = json.loads(crwd_getdetailedinfo.text)['resources']
                print(indicator + ' found in CrowdStrike - Custom IOCs')
                for e in event_array:
                    d = json.dumps(e)
                    d = 'CrowdStrike,' + d
                    print(d, file=open(self.flat_output_file, "a"))        

        crwd_session.close()

    def etintel_domain(self, domain: str):

        etintel_base_url = self.etintel_base_url
        etintel_api_key = self.etintel_api_key
        etintel_session = requests.session()
        etintel_session.verify = True
        
        etintel_ips_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/ips'), headers={'Authorization': etintel_api_key})
        etintel_events_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/events'), headers={'Authorization': etintel_api_key})
        etintel_geoloc_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/geoloc'), headers={'Authorization': etintel_api_key})
        etintel_nameservers_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/nameservers'), headers={'Authorization': etintel_api_key})
        etintel_reputation_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/reputation'), headers={'Authorization': etintel_api_key})
        etintel_samples_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/samples'), headers={'Authorization': etintel_api_key})
        etintel_urls_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/urls'), headers={'Authorization': etintel_api_key})
        etintel_whois_response = etintel_session.get((etintel_base_url + 'domains/' + domain + '/whois'), headers={'Authorization': etintel_api_key})
    
        if "[]" not in etintel_ips_response.text:
            event_array = json.loads(etintel_ips_response.text)['response']
            print(domain + ' found in ET Intel - IPs')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_events_response.text:
            event_array = json.loads(etintel_events_response.text)['response']
            print(domain + ' found in ET Intel - Events')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,events,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_geoloc_response.text:
            event_array = json.loads(etintel_geoloc_response.text)['response']
            print(domain + ' found in ET Intel - Geolocation')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,geoloc,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_nameservers_response.text:
            event_array = json.loads(etintel_nameservers_response.text)['response']
            print(domain + ' found in ET Intel - Nameservers')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,nameservers,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_reputation_response.text:
            event_array = json.loads(etintel_reputation_response.text)['response']
            print(domain + ' found in ET Intel - Reputation')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,reputation,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_samples_response.text:
            event_array = json.loads(etintel_samples_response.text)['response']
            print(domain + ' found in ET Intel - Samples')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,samples,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_urls_response.text:
            event_array = json.loads(etintel_urls_response.text)['response']
            print(domain + ' found in ET Intel - URLs')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,urls,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_whois_response.text:
            event_array = json.loads(etintel_whois_response.text)['response']
            print(domain + ' found in ET Intel - Whois')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,urls,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

    def etintel_ip(self, ip: str):
        
        etintel_base_url = self.etintel_base_url
        etintel_api_key = self.etintel_api_key
        etintel_session = requests.session()
        etintel_session.verify = True
        
        etintel_domains_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/domains'), headers={'Authorization': etintel_api_key})
        etintel_events_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/events'), headers={'Authorization': etintel_api_key})
        etintel_geoloc_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/geoloc'), headers={'Authorization': etintel_api_key})
        etintel_reputation_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/reputation'), headers={'Authorization': etintel_api_key})
        etintel_samples_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/samples'), headers={'Authorization': etintel_api_key})
        etintel_urls_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/urls'), headers={'Authorization': etintel_api_key})

        if "[]" not in etintel_domains_response.text:
            event_array = json.loads(etintel_domains_response.text)['response']
            print(ip + ' found in ET Intel - Domains')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_events_response.text:
            event_array = json.loads(etintel_events_response.text)['response']
            print(ip + ' found in ET Intel - Events')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,events,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_geoloc_response.text:
            event_array = json.loads(etintel_geoloc_response.text)['response']
            print(ip + ' found in ET Intel - Geolocation')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,geoloc,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_reputation_response.text:
            event_array = json.loads(etintel_reputation_response.text)['response']
            print(ip + ' found in ET Intel - Reputation')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,reputation,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_samples_response.text:
            event_array = json.loads(etintel_samples_response.text)['response']
            print(ip + ' found in ET Intel - Samples')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,samples,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_urls_response.text:
            event_array = json.loads(etintel_urls_response.text)['response']
            print(ip + ' found in ET Intel - URLs')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,urls,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))
    
    def etintel_hash(self, hash: str):
        
        etintel_base_url = self.etintel_base_url
        etintel_api_key = self.etintel_api_key
        etintel_session = requests.session()
        etintel_session.verify = True
        
        etintel_samples_response = etintel_session.get((etintel_base_url + 'samples/' + hash), headers={'Authorization': etintel_api_key})
        etintel_connections_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/connections'), headers={'Authorization': etintel_api_key})
        etintel_dnslookups_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/dns'), headers={'Authorization': etintel_api_key})
        etintel_httpreqs_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/http'), headers={'Authorization': etintel_api_key})
        etintel_events_response = etintel_session.get((etintel_base_url + 'samples/' + hash + '/events'), headers={'Authorization': etintel_api_key})

        if "[]" not in etintel_samples_response.text:
            event_array = json.loads(etintel_samples_response.text)['response']
            print(hash + ' found in ET Intel - Samples')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_connections_response.text:
            event_array = json.loads(etintel_connections_response.text)['response']
            print(hash + ' found in ET Intel - Sample Connections')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_dnslookups_response.text:
            event_array = json.loads(etintel_dnslookups_response.text)['response']
            print(hash + ' found in ET Intel - Sample DNS Lookups')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_httpreqs_response.text:
            event_array = json.loads(etintel_httpreqs_response.text)['response']
            print(hash + ' found in ET Intel - Sample HTTP Requests')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_events_response.text:
            event_array = json.loads(etintel_events_response.text)['response']
            print(hash + ' found in ET Intel - Sample IDS Events')
            for e in event_array:
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

    def greynoise(self, ip: str):

        greynoise_base_url = self.greynoise_base_url
        greynoise_api_key = self.greynoise_api_key
        greynoise_session = requests.session()
        greynoise_session.verify = True

        greynoise_response = greynoise_session.get((greynoise_base_url + ip), headers={'key': greynoise_api_key})

        grey_array = json.loads(greynoise_response.text)
        print(ip + ' response from GreyNoise')
        d = json.dumps(grey_array)
        d = 'GreyNoise,' + d
        d = d.replace('\'', '')
        d = d.replace('"', '')
        d = d.replace('{', '')
        d = d.replace('}', '')
        d = d.replace('ip:', 'ip,')
        d = d.replace('noise:', 'noise,')
        d = d.replace('riot:', 'riot,')
        d = d.replace('classification:', 'classification,')
        d = d.replace('name:', 'name,')
        d = d.replace('link:', 'link,')
        d = d.replace('last_seen:', 'last_seen,')
        d = d.replace('message:', 'message,')
        print(d, file=open(self.flat_output_file, "a"))
    
    def msft_domain(self, domain: str):

        msft_base_url = self.msft_base_url
        msft_app_url = self.msft_app_url
        msft_tenant_id = self.msft_tenant_id
        msft_client_id = self.msft_client_id
        msft_client_secret = self.msft_client_secret
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
                event_array = json.loads(msft_domain_stats.text)
                print(domain + ' response from Microsoft Defender - Domains Stats')
                d = json.dumps(event_array)
                d = 'Microsoft' + d
                d = d.replace('"@odata.context": "https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgIPStats"', '')
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))  

            msft_session.close()

    def msft_hash(self, hash: str):

        msft_base_url = self.msft_base_url
        msft_app_url = self.msft_app_url
        msft_tenant_id = self.msft_tenant_id
        msft_client_id = self.msft_client_id
        msft_client_secret = self.msft_client_secret
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
                event_array = json.loads(msft_globalfile_stats.text)
                print(hash + ' response from Microsoft Defender - Global File Info')
                d = json.dumps(event_array)
                d = 'Microsoft' + d
                d = d.replace('"@odata.context": "https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgIPStats"', '')
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))  

            if(msft_orgfile_stats.status_code == 200):
                event_array = json.loads(msft_orgfile_stats.text)
                print(hash + ' response from Microsoft Defender - Organiation File Info')
                d = json.dumps(event_array)
                d = 'Microsoft' + d
                d = d.replace('"@odata.context": "https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgIPStats"', '')
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))  

            msft_session.close()

    def msft_ip(self, ip: str):

        msft_base_url = self.msft_base_url
        msft_app_url = self.msft_app_url
        msft_tenant_id = self.msft_tenant_id
        msft_client_id = self.msft_client_id
        msft_client_secret = self.msft_client_secret
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
                event_array = json.loads(msft_ip_stats.text)
                print(ip + ' response from Microsoft Defender - IP Stats')
                d = json.dumps(event_array)
                d = 'Microsoft' + d
                d = d.replace('"@odata.context": "https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgIPStats"', '')
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))  

            msft_session.close()
    
    def onyphe_domain(self, domain: str):

        onyphe_summary_base_url = self.onyphe_summary_base_url
        onyphe_api_key = self.onyphe_api_key
        onyphe_session = requests.session()
        onyphe_session.verify = True

        onyphe_summary_response = onyphe_session.get((onyphe_summary_base_url + 'domain/' + domain), headers={'Authorization': onyphe_api_key})

        if "[]" not in onyphe_summary_response.text:
            event_array = json.loads(onyphe_summary_response.text)['results']
            print(domain + ' response from Onyphe - Summary')
            for e in event_array:
                d = json.dumps(e)
                d = 'Onyphe,summary,' + d
                d = d.replace('"', '')
                d = d.replace('@', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace('[', '')
                d = d.replace(']', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

    def onyphe_ip(self, ip: str):

        onyphe_summary_base_url = self.onyphe_summary_base_url
        onyphe_api_key = self.onyphe_api_key
        onyphe_session = requests.session()
        onyphe_session.verify = True

        onyphe_summary_response = onyphe_session.get((onyphe_summary_base_url + 'ip/' + ip), headers={'Authorization': onyphe_api_key})

        if "[]" not in onyphe_summary_response.text:
            event_array = json.loads(onyphe_summary_response.text)['results']
            print(ip + ' response from Onyphe - Summary')
            for e in event_array:
                d = json.dumps(e)
                d = 'Onyphe,summary,' + d
                d = d.replace('"', '')
                d = d.replace('@', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace('[', '')
                d = d.replace(']', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

    def shodan_domain(self, domain: str):

        shodan_api_key = self.shodan_api_key
        shodan_api = shodan.Shodan(shodan_api_key)       

        try:
            shodan_result = shodan_api.dns.domain_info(domain)
            print(domain + ' found in Shodan')
            d = json.dumps(shodan_result)
            d = 'Shodan,' + d
            d = d.replace('"', '')
            d = d.replace('\'', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

        except shodan.APIError as error:
            print('Shodan: {}'.format(error))

    def shodan_ip(self, ip: str):

        shodan_api_key = self.shodan_api_key
        shodan_api = shodan.Shodan(shodan_api_key)       

        try:
            shodan_result = shodan_api.host(ip)
            print(ip + ' found in Shodan')
            d = json.dumps(shodan_result)
            d = 'Shodan,' + d
            d = d.replace('"', '')
            d = d.replace('\'', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

        except shodan.APIError as error:
            print('Shodan: {}'.format(error))
    
    def virustotal_domain(self, domain: str):

        virustotal_base_url = self.virustotal_base_url
        virustotal_api_key = self.virustotal_api_key
        virustotal_session = requests.session()
        virustotal_session.verify = True
        
        virustotal_commfiles_response = virustotal_session.get((virustotal_base_url + 'domains/' + domain + '/communicating_files'), headers={'x-apikey': virustotal_api_key})
        virustotal_resolutions_response = virustotal_session.get((virustotal_base_url + 'domains/' + domain + '/resolutions'), headers={'x-apikey': virustotal_api_key})
        virustotal_whois_response = virustotal_session.get((virustotal_base_url + 'domains/' + domain + '/historical_whois'), headers={'x-apikey': virustotal_api_key})

        if "[]" not in virustotal_commfiles_response.text:    
            event_array = json.loads(virustotal_commfiles_response.text)
            print(domain + ' response from VirusTotal - Communicating Files')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in virustotal_resolutions_response.text:    
            event_array = json.loads(virustotal_resolutions_response.text)
            print(domain + ' response from VirusTotal - Resolutions')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in virustotal_whois_response.text: 
            event_array = json.loads(virustotal_whois_response.text)
            print(domain + ' found in VirusTotal - Historical Whois')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

    def virustotal_ip(self, ip: str):

        virustotal_base_url = self.virustotal_base_url
        virustotal_api_key = self.virustotal_api_key
        virustotal_session = requests.session()
        virustotal_session.verify = True
        
        virustotal_whois_response = virustotal_session.get((virustotal_base_url + 'ip_addresses/' + ip + '/historical_whois'), headers={'x-apikey': virustotal_api_key})
        virustotal_commfiles_response = virustotal_session.get((virustotal_base_url + 'ip_addresses/' + ip + '/communicating_files'), headers={'x-apikey': virustotal_api_key})

        if "[]" not in virustotal_commfiles_response.text:    
            event_array = json.loads(virustotal_commfiles_response.text)
            print(ip + ' response from VirusTotal - Communicating Files')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in virustotal_whois_response.text: 
            event_array = json.loads(virustotal_whois_response.text)
            print(ip + ' response from VirusTotal - Historical Whois')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

    def virustotal_hash(self, hash: str):

        virustotal_base_url = self.virustotal_base_url
        virustotal_api_key = self.virustotal_api_key
        virustotal_session = requests.session()
        virustotal_session.verify = True

        virustotal_behavior_response = virustotal_session.get((virustotal_base_url + 'files/' + hash + '/behaviour_summary'), headers={'x-apikey': virustotal_api_key})
        virustotal_file_response = virustotal_session.get((virustotal_base_url + 'files/' + hash), headers={'x-apikey': virustotal_api_key})

        if "[]" not in virustotal_file_response.text:    
            event_array = json.loads(virustotal_file_response.text)
            print(hash + ' response from VirusTotal - File Report')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))
        
        if "[]" not in virustotal_behavior_response.text:    
            event_array = json.loads(virustotal_behavior_response.text)
            print(hash + ' response from VirusTotal - File Behavior Reports')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))