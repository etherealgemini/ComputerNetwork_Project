import base64
import copy
import mimetypes
import mimetypes as mime
import os
from pathlib import Path
import socket
import threading

import send2trash

from util import *

# 运行后，将在路径D:\\temp\pythonServer创建根目录文件夹，浏览器中运行http:\\localhost:8000\查看

NEWLINE = "\r\n"
DATA_ROOT = "D:\\\\temp\\pythonServer"
LOCATION = "http:\\\\localhost:8000\\"
SCHEME = "http/1.1"
MIME_TYPE = {
    "html": "text/html"
}


def url_decoder(url: str) -> dict[str]:
    """
    a decoder for url.

    example: https://bb.sustech.edu.cn/webapps/blackboard/content/listContent.jsp?course_id=123&content_id=456

    scheme: https

    net_location: bb.sustech.edu.cn

    path: /webapps/blackboard/content/listContent.jsp

    params: null

    query: course_id=123&content_id=456

    fragment: null

    target: listContent.jsp
    :return: a dict of decoded url
    """

    # split方法会去除指定分隔符（第一个参数）
    scheme, r = url.split("://", 1) if "://" in url else ("", url)
    net_location, r = r.split("/", 1) if "/" in r else (r, "")
    path, r = ("/" + r).split("?", 1) if "?" in r else (r, "")
    params, r = r.split("?", 1) if "?" in r else (r, "")
    query, fragment = r.split("#", 1) if "#" in r else (r, "")
    target = path.split("/")[-1]
    return {
        "scheme": scheme,
        "net_location": net_location,
        "path": path,
        "params": params,
        "query": query,
        "fragment": fragment,
        "target": target
    }


class server:
    def __init__(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = server_socket
        path = Path(DATA_ROOT)
        self.root = path
        if not path.exists():
            path.mkdir()

        server_socket.bind(("localhost", 8000))

        server_socket.listen()
        self.launch()

    def launch(self):
        server_socket = self.server_socket
        while True:
            client_socket, client_address = server_socket.accept()
            self.accept_conn(client_socket, client_address)

    def accept_conn(self, client_socket, client_address):
        t = threading.Thread(target=self.handle_conn,
                             args=(client_socket, client_address))
        print(t.name)
        t.start()

    """
    client_address: (host_address,port)
    """

    def handle_conn(self, client_socket: socket.socket, client_address: tuple):
        while True:
            data = client_socket.recv(4096)
            req = data.decode("utf-8")
            response = self.handle_request(req)
            if type(response).__name__ == "str":
                response = response.encode('utf-8')
            try:
                client_socket.send(response)
            except TypeError:
                if response is None:
                    continue
                else:
                    print(type(req))
                    print(len(req))
                    time.sleep(10)
            # finally:
                # client_socket.close()
                # break

    """
    method URL version CRLF <- request_line
    header_name:value CRLF
    header_name:value CRLF
    ...
    header_name:value CRLF
    CRLF
    payload
    """

    def handle_request(self, req):
        try:
            temp = req.split('\r\n\r\n', 1)
            header = temp[0]
            body = None
            if len(temp) > 1:
                body = temp[1]
            headers = header.split(NEWLINE)
            request_line = headers[0].split()
            req_method = request_line[0]
            url = request_line[1]

            decoded_url = url_decoder(url)
        except IndexError:
            a=1

        if len(request_line) == 0:
            return

        if req_method == "GET":
            return self.get_request(decoded_url)
        elif req_method == "POST":
            return self.post_request(decoded_url,body)
        return self.not_supported_request()

    def get_request(self, decoded_url):

        if "." in decoded_url["target"] and decoded_url["target"][-1] != ".":
            body = self.download(decoded_url)
        else:
            body = self.view(decoded_url)
        return body

    def post_request(self, decoded_url,body):

        if decoded_url["target"] == "upload":
            return self.upload(decoded_url,body)
        elif decoded_url["target"] == "delete":
            return self.delete(decoded_url)

    def download(self, decoded_url):
        path = decoded_url['path']
        path = DATA_ROOT + "\\\\" + path.replace("\\", "\\\\")
        path_ = Path(path)
        print(f"download: {decoded_url['path']}")
        ftype = mimetypes.guess_type(path_)[0]
        content = path_.open('rb').read()

        resp = Response()
        resp.set_status_line(SCHEME,200,"OK")
        print(mimetypes.guess_type(path_)[0])
        resp.set_content_type(ftype,"")
        resp.set_keep_alive()
        resp.body = content
        out = resp.build_byte()

        return out

    def view(self, decoded_url):
        # if decoded_url['target'].endswith("."):
        path = decoded_url['path']
        path = path.replace("\\", "\\\\")
        path = path.replace("/", "\\")
        print(f"view: {path}")
        html_file = generate_view_html(DATA_ROOT + "\\" + path, path, LOCATION)

        resp = Response()
        resp.set_status_line(SCHEME, 200, "OK")
        resp.set_content_type(MIME_TYPE["html"], "utf-8")
        resp.set_keep_alive()
        resp.body = html_file

        # print(f"view: {decoded_url['path']}")
        return resp.build()

    def upload(self, decoded_url, body):
        path = decoded_url['path']
        path = DATA_ROOT + path.replace("\\", "\\\\")
        path_ = Path(path)
        path_.open('wb').write(body)
        pass
        # if path_.exists():
        #     return
        # else:
        #
        # pass

    def delete(self, decoded_url):
        print(f"delete file at \"{decoded_url['params']}\"")
        pass

    def not_supported_request(self):
        print("request not supported")
        pass


class Response:
    def __init__(self):
        self.status_line = None
        self.headers = dict()
        self.body = None
        self.message = None

    def set_status_line(self, scheme, code, msg):
        self.status_line = str(scheme) + " " + code.__str__() + " " + str(msg)

    def add_header(self, header: str, value):
        self.headers[header] = value

    def set_content_type(self, type: str, charset: str):
        self.headers["Content-Type"] = type
        if charset != "":
            self.headers["Content-Type"] += "; charset="+charset

    def set_keep_alive(self):
        self.headers["Connection"] = "keep-alive"

    def remove_header(self, header: str):
        self.headers.pop(header)

    def build(self) -> str:
        st_line = self.status_line
        hds = self.headers
        bd = self.body

        msg = st_line
        msg += NEWLINE
        for hd in hds:
            msg += hd + ":" + str(hds[hd])
            msg += NEWLINE
        msg += NEWLINE
        msg += bd
        self.message = msg

        return msg

    def build_byte(self)->bytes:
        st_line = self.status_line
        hds = self.headers
        bd = self.body

        msg = st_line
        msg += NEWLINE
        for hd in hds:
            msg += hd + ":" + str(hds[hd])
            msg += NEWLINE
        msg += NEWLINE
        msg = msg.encode('utf-8')
        msg += bd
        self.message = msg
        return msg


if __name__ == "__main__":
    server()
