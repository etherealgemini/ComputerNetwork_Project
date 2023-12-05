# from bs4 import BeautifulSoup as bs
#
# soup = bs(open("D___GPT_ 的索引.html"),features="html.parser")
#
# out = open('__html.html','w')
# out.write(soup.decode(True))
# out.close()
import os
import time

from server import url_decoder
import base64

VIEW_PATH = ".\\\\.idea\\\\inspectionProfiles\\\\"


template_file = open("template.html",'r')
template = template_file.read()
temp = os.walk(VIEW_PATH)
cnt = 0
template += "\r\n"
template += f"<script>start(\"{VIEW_PATH}\");</script>"
for root,dirs,files in temp:
    cnt+=1
    for dir in dirs:
        ctime = int(os.path.getmtime(root + dir))
        formatted_ctime = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(ctime))
        template += "\r\n"
        template += f"<script>addRow(\"{dir}\", \"{dir}\", 1, 0, \"0 B\", {ctime}, \"{formatted_ctime}\");</script>"
    for file in files:
        siz = os.path.getsize(root+file)
        ctime = int(os.path.getmtime(root+file))
        formatted_ctime = time.strftime('%Y/%m/%d %H:%M:%S',time.localtime(ctime))
        template += "\r\n"
        template += f"<script>addRow(\"{file}\", \"{file}\", 0, {siz}, \"{siz} B\", {ctime}, \"{formatted_ctime}\");</script>"
    break

output_file = open("test.html",'w')
output_file.write(template)
output_file.close()
template_file.close()
