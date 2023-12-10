import os
import time


def generate_view_html(local_root, root,port):
    template_file = open("template.html", 'r')
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
