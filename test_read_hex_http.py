# from bs4 import BeautifulSoup as bs
#
# soup = bs(open("D___GPT_ 的索引.html"),features="html.parser")
#
# out = open('__html.html','w')
# out.write(soup.decode(True))
# out.close()
from server import url_decoder
import base64

f = open("sampleHex", 'r')
req = bytes.fromhex(f.read()).decode()
NEWLINE = '\r\n'
# print(req)

header, body = req.split('\r\n\r\n', 1)
headers = header.split(NEWLINE)
request_line = headers[0].split()
req_method = request_line[0]
url = request_line[1]

decoded_url = url_decoder(url)
print("-------------------headers-------------------")
for h in headers:
    print(h)
print("-------------------body-------------------")
print(body)
