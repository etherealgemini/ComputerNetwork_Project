import base64
import chunk
import copy
import mimetypes
import mimetypes as mime
import os
from pathlib import Path
import socket
import threading
from util import *

# 运行后，将在路径D:\\temp\pythonServer创建根目录文件夹，浏览器中运行http:\\localhost:8000\查看

NEWLINE = "\r\n"
FILE_ROOT = os.getcwd()
DATA_ROOT = FILE_ROOT + "\\data"
LOCATION = "http:\\\\localhost:8000\\"
SCHEME = "http/1.1"
MIME_TYPE = {
    "html": "text/html"
}
CHUNK_SIZE = 1024 * 3
user_dict = {
    "test": "123456"
}


def url_decoder(url: str) -> dict[str]:
    """
    a decoder for url.

    example: https://bb.sustech.edu.cn/webapps/blackboard/content/listContent.jsp?course_id=123&content_id=456

    scheme: https

    net_location: bb.sustech.edu.cn

    path: /webappsackboard/contentstContent.jsp

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
    # params, r = r.split("?", 1) if "?" in r else (r, "")
    query, fragment = r.split("#", 1) if "#" in r else (r, "")
    target = path.split("/")[-1]
    queries = query.split("&") if "&" in query else [query]
    queries_dict = dict()
    for q in queries:
        key, value = q.split("=")
        queries_dict[key] = value
    return {
        "scheme": scheme,
        "net_location": net_location,
        "path": path,
        # "params": params,
        "query": query,
        "fragment": fragment,
        "target": target,
        "queries_dict": queries_dict
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
        data = client_socket.recv(4096)
        req = data.decode("utf-8")
        self.handle_first_req(client_socket, req)

        while True:
            data = client_socket.recv(4096)
            req = data.decode("utf-8")
            if len(data) < 1:
                continue
            response = self.handle_request(client_socket, req)
            self.send(client_socket, response)
            # finally:
            # client_socket.close()
            # break

    @staticmethod
    def send(client_socket: socket.socket, response):
        if type(response).__name__ == "str":
            print(1)
            response = response.encode('utf-8')
        print("send")
        client_socket.sendall(response)

    def handle_first_req(self, client_socket, req):

        auth_flag = self.check_auth(req)

        if auth_flag:
            self.send(client_socket, self.handle_request(client_socket, req))
            return

        response = self.authorization()
        self.send(client_socket, response)

        data = client_socket.recv(4096)
        req = data.decode("utf-8")
        auth_flag = self.check_auth(req)

        if not auth_flag:
            self.send(client_socket, self.unAuthorized())
            client_socket.close()
        self.send(client_socket, self.pass_auth())
        return

    @staticmethod
    def check_auth(req) -> bool:
        temp = req.split('\r\n\r\n', 1)
        headers_ = temp[0]
        headers = headers_.split(NEWLINE)
        auth_flag = False
        for header in headers:
            if not header.__contains__("Authorization"):
                continue
            auth_flag = True
            _, r = header.split(":")
            temp = r.split(" ")
            if len(temp) < 2:
                auth_flag = False
                break
            auth_method, code = temp[0], temp[len(temp) - 1]
            temp = base64.b64decode(code).decode("utf-8").split(":")
            print(temp)
            if len(temp) < 2:
                auth_flag = False
                break
            usr_name, pw = temp[0], temp[1]
            if user_dict[usr_name] != pw:
                auth_flag = False
            auth_flag = True
            break
        return auth_flag

    """
    method URL version CRLF <- request_line
    header_name:value CRLF
    header_name:value CRLF
    ...
    header_name:value CRLF
    CRLF
    payload
    """

    def handle_request(self, client_socket, req):
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
            print(decoded_url)
            # self.session_worker(decoded_url)
        except IndexError:
            a = 1

        if len(request_line) == 0:
            return

        if req_method == "GET":
            return self.get_request(client_socket, decoded_url)
        elif req_method == "POST":
            return self.post_request(client_socket, decoded_url, body)
        return self.not_supported_request()

    def get_request(self, client_socket, decoded_url):

        if "." in decoded_url["target"] and decoded_url["target"][-1] != ".":
            body = self.download(client_socket, decoded_url)
        else:
            body = self.view(client_socket, decoded_url)
        return body

    def post_request(self, client_socket, decoded_url, body):
        print(decoded_url["target"]+'是')

        if decoded_url["target"] == "upload":
            return self.upload(decoded_url, body)
        elif decoded_url["target"] == "delete":
            return self.delete(decoded_url)
        else:
            return self.not_supported_request()

    def download(self, client_socket, decoded_url):
        path = decoded_url["queries_dict"['path']]
        path = DATA_ROOT + "\\\\" + path.replace("\\", "\\\\")
        path_ = Path(path)
        print(f"download: {decoded_url['path']}")
        ftype = mimetypes.guess_type(path_)[0]
        content = path_.open('rb').read()
        # return self.download_regular(content, ftype)

        q_dict = decoded_url["queries_dict"]
        if q_dict is None or q_dict.get("chunk") is None or q_dict["chunked"] != 1:
            return self.download_regular(content, ftype)
        else:
            return self.send_chunked(client_socket, content, ftype)

    @staticmethod
    def download_regular(content, mime_type) -> bytes:
        resp = Response()
        resp.set_status_line(SCHEME, 200, "OK")
        # print(mimetypes.guess_type(path)[0])
        resp.set_content_type(mime_type, "")
        resp.set_keep_alive()
        resp.body = content
        out = resp.build_byte()


        return out

    def send_chunked(self, client_socket, content, mime_type):
        resp = Response()
        resp.set_status_line(SCHEME, 200, "OK")
        resp.set_content_type(mime_type, "")
        resp.set_keep_alive()
        resp.set_chunked()
        resp.body = None

        resp_chunk = Response()
        if type(content).__name__()=="str":
            content = content.encode()
        pointer = 0
        rest_len = len(content)
        while rest_len - CHUNK_SIZE > 0:
            chunk_data = str(CHUNK_SIZE)
            chunk_data += NEWLINE
            chunk_data += content[pointer:pointer + CHUNK_SIZE]
            chunk_data += NEWLINE
            pointer += CHUNK_SIZE
            rest_len -= CHUNK_SIZE

            resp_chunk.body = chunk_data
            self.send(client_socket, resp_chunk._build())

        chunk_data = str(rest_len)
        chunk_data += NEWLINE
        chunk_data += content[pointer:pointer + CHUNK_SIZE]
        chunk_data += NEWLINE
        resp_chunk.body = chunk_data
        self.send(client_socket, resp_chunk._build())

        chunk_data = str(0)
        chunk_data += NEWLINE
        resp_chunk.body = chunk_data.encode()
        self.send(client_socket, resp_chunk._build())

        return
        # return

    @staticmethod
    def view(client_socket, decoded_url):
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
        path_.open('wb').write(body.encode())
        file_size=len(body)
        response = Response()
        response.set_status_line(SCHEME, 200, "OK")
        response.set_content_type("text/plain", "")
        response.set_content_length(file_size)
        response.set_keep_alive()
        response.body = None
        return response.build()

    def delete(self, decoded_url):
        print(f"delete file at \"{decoded_url['params']}\"")
        pass

    def not_supported_request(self):
        print("request not supported")
        pass

    @staticmethod
    def authorization():
        resp = Response()
        resp.set_status_line(SCHEME, 401, "Unauthorized")
        resp.set_auth()
        resp.set_keep_alive()
        resp.body = open("401.html", "r").read()
        return resp.build()

    @staticmethod
    def unAuthorized():
        resp = Response()
        resp.set_status_line(SCHEME, 401, "Unauthorized")
        resp.set_keep_alive(False)
        resp.set_content_type(MIME_TYPE["html"], "utf-8")
        resp.body = open("401.html", "r").read()
        return resp.build()

    def session_worker(self, decoded_url):

        pass

    def pass_auth(self):
        resp = Response()
        resp.set_status_line(SCHEME, 200, "OK")
        resp.set_auth()
        resp.set_keep_alive()
        # resp.body = "http://localhost:8000/init"
        resp.body = ""
        return resp.build()


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
            self.headers["Content-Type"] += "; charset=" + charset

    def set_keep_alive(self, alive=True):
        if alive:
            self.headers["Connection"] = "keep-alive"
        else:
            self.headers["Connection"] = "close"

    def set_auth(self):
        self.headers["WWW-Authenticate"] = "Basic realm=\"Authorization Required\""

    def set_content_length(self, length):
        self.headers["Content-Length"] = str(length)

    def set_chunked(self):
        self.headers["Transfer-Encoding"] = "chunked"

    def remove_header(self, header: str):
        self.headers.pop(header)

    def build(self) -> str:
        if self.headers.get("Transfer-Encoding") is None and self.headers.get("Content-Length") is None:
            print("set content_length")
            self.set_content_length(len(self.body.encode()))
        return self._build()

    def _build(self) -> str:
        st_line = self.status_line
        hds = self.headers
        bd = self.body
        if bd is None: bd = ""

        msg = st_line
        msg += NEWLINE
        for hd in hds:
            msg += hd + ":" + str(hds[hd])
            msg += NEWLINE
        msg += NEWLINE
        msg += bd
        self.message = msg

        return msg

    def build_byte(self) -> bytes:
        st_line = self.status_line
        bd = self.body
        self.headers["Content-Length"] = len(bd)
        hds = self.headers

        msg = st_line
        msg += NEWLINE
        for hd in hds:
            msg += hd + ":" + str(hds[hd])
            msg += NEWLINE
        msg += NEWLINE
        msg = msg.encode()
        msg += bd
        self.message = msg

        return msg


if __name__ == "__main__":
    server()
