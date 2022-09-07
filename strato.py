# strato.py
#
# Python library to query the Stratosphere Research Laboratory at Czech Technical University
# for information on IP addresses that have been blocklisted. Files are retrieved and checked 
# to see if they contain the queried IP.
#
# This library can be used independently or as part of the intel_collector threat intelligence aggregator project.
#
# github.com/jasonsford
# 7 September 2022

import urllib.request
import os

def ip(ip:str):

        location1 = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv'

        urllib.request.urlretrieve(location1, 'AIP_blacklist_for_IPs_seen_last_24_hours.csv')

        with open(r'AIP_blacklist_for_IPs_seen_last_24_hours.csv', 'r') as file:
                content = file.read()
                if ip in content:
                        print('Found in Stratosphere IPS Blocklist for IPs seen last 24 hours')
                        returnString = 'StratosphereIPS_Last24H,' + ip
                        return returnString

        location2 = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_newest_attackers.csv'

        urllib.request.urlretrieve(location2, 'AIP_historical_blacklist_prioritized_by_newest_attackers.csv')

        with open(r'AIP_historical_blacklist_prioritized_by_newest_attackers.csv', 'r') as file:
                content = file.read()
                if ip in content:
                        print('Found in Stratosphere IPS Historical Blocklist Prioritized by Newest Attackers')
                        returnString = 'StratosphereIPS_Historical_Newest,' + ip
                        return returnString

        location3 = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_repeated_attackers.csv'

        urllib.request.urlretrieve(location3, 'AIP_historical_blacklist_prioritized_by_repeated_attackers.csv')

        with open(r'AIP_historical_blacklist_prioritized_by_repeated_attackers.csv', 'r') as file:
                content = file.read()
                if ip in content:
                        print('Found in Stratosphere IPS Historical Blocklist Prioritized by Repeated Attackers')
                        returnString = 'StratosphereIPS_Historical_Repeated,' + ip
                        return returnString

        os.remove('AIP_blacklist_for_IPs_seen_last_24_hours.csv')
        os.remove('AIP_historical_blacklist_prioritized_by_newest_attackers.csv')
        os.remove('AIP_historical_blacklist_prioritized_by_repeated_attackers.csv')