# -*- coding: UTF-8 -*-
import os
import time


def generate_view_html(local_root, root,port):
    template_file = open("template.html", 'r',encoding='utf-8')
    print(root)
    template = template_file.read()
    template += "\r\n"

    root = root.replace("/","\\")
    local_root = local_root.replace("/","\\")
    root = root.replace("\\", "\\\\")
    local_root = local_root.replace("\\", "\\\\")

    template += f"<script>start(\"{port}\\{root}\");</script>"
    template += "\r\n"
    template += f"<script>onHasParentDirectory();</script>"
    print("generate html")
    root:str
    _root = root.split("init\\\\",1)
    print(_root)
    if len(_root)>1:
        _root = root
    else:
        _root = ""
    print(_root)

    for _,dirs,files in os.walk(local_root):
        for dir in dirs:
            print(dir)
            ctime = int(os.path.getmtime(local_root +"\\"+ dir.replace("/","\\")))
            formatted_ctime = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(ctime))
            template += "\r\n"
            template += f"<script>addRow(\"{dir}\", \"{dir}\", 1, 0, \"0 B\", {ctime}, \"{formatted_ctime}\");</script>"
        for file in files:
            print(file)
            siz = os.path.getsize(local_root +"\\"+ file)
            ctime = int(os.path.getmtime(local_root +"\\"+ file.replace("/","\\")))
            formatted_ctime = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(ctime))
            template += "\r\n"
            template += f"<script>addRow(\"{file}\", \"{file}\", 0, {siz}, \"{siz} B\", {ctime}, \"{formatted_ctime}\");</script>"
        break
    print("finish path iter")
    template += "\r\n"
    template += "</html>"
    output_file = open("test.html", 'w')
    output_file.write(template)
    output_file.close()
    template_file.close()
    # print(template)

    return template

def walk(path):
    list_ = list()
    for _,dirs,files in os.walk(path):
        for dir in dirs:
            list_.append(dir)
        for file in files:
            list_.append(file)
        break
    return str(list_)

def url2str(url):
    import binascii

    if isinstance(url,str):
        url = url.encode()
    url:bytes
    bits = url.split(b'%')
    if len(bits) == 1:
        return bits[0]

    res = []
    i = 0
    for bit in bits:
        if i==0:
            res.append(bit)
            i += 1
        elif i!=0 and len(bit)>2 :
            res.append(binascii.unhexlify(bit[:2]))
            res.append(bit[2:])
        else:
            i+=1
            res.append(binascii.unhexlify(bit))

    return b''.join(res).decode('utf-8')

# def url2str(url) -> str:
#     if isinstance(url,bytes):
#         return url2bytes(url).decode()
#
#     bits = url.split('%')
#     if len(bits) == 1:
#         return bits[0]
#
#     res = []
#     for bit in bits:
#         res.append((bit[:2]))
#         res.append(bit[2:])
#     return b''.join(res)

