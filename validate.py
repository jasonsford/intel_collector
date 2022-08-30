# validate.py
#
# Check a string to validate whether it is a properly formatted domain name, IP address, or file hash or appropriate length
#
# github.com/jasonsford
# 30 August 2022

import re

def isValidDomain(str):

    domainregex = "^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$"

    p = re.compile(domainregex)

    if(str == None):
        return False

    if(re.search(p, str)):
        return True
    else:
        return False

def isValidFileHash(str):

    if(str == None):
        return False
    
    if((len(str) == 32) or (len(str) == 40) or (len(str) == 64) or (len(str) == 128)):
        return True
    else:
        return False

def isValidIpAddress(str):

    ipaddressregex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    internalipregex = "(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)"
    p1 = re.compile(ipaddressregex)
    p2 = re.compile(internalipregex)

    if(str == None):
        return False

    if(re.search(p1, str)):
        if(re.search(p2, str)):
            return False
        else:
            return True
    else:
        return False