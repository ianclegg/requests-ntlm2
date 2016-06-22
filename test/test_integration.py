import requests
from requests_ntlm2 import HttpNtlm2Auth

# test for mragaei
session = requests.Session()

# un-authenticated
r1 = session.get("http://52.208.44.235/iisstart.htm", verify=False)
Referer = dict(Referer = "http://192.168.1.20/now")

# set auth handler for authenticted, use same connection
session.auth = HttpNtlm2Auth('WIN-QRD0D23AHH3', 'test', '6N%9rEpFqedKdjGw')
r2 = session.get("http://52.208.44.235/secure/iisstart.htm", verify=False, headers=Referer)
print(r2.status_code)
print(r2.content)
