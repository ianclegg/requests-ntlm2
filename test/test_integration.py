import requests
from requests_ntlm2 import HttpNtlm2Auth
import base64
import binascii

handler = HttpNtlm2Auth('DEVNUC', 'Administrator', '5iveM1nut3s')
result = requests.get(url="http://192.168.1.20/now", auth=handler)
print(result.status_code)
print(result.content)