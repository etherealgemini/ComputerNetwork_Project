import base64
import chunk
import copy
import logging
import mimetypes
import mimetypes as mime
import os
from pathlib import Path
import re
import socket
import threading
from util import *
import numpy as np

# 运行后，将在路径D:\\temp\pythonServer创建根目录文件夹，浏览器中运行http:\\localhost:8000\查看

NEWLINE = "\r\n"
FILE_ROOT = os.getcwd()
DATA_ROOT = FILE_ROOT + "\\data"
LOCATION = "http:\\\\localhost:8080\\"
SCHEME = "http/1.1"
MIME_TYPE = {
    "html": "text/html"
}
CHUNK_SIZE = 1024
user_dict = {
    "test": "123456",
    "client1": "123",
    "client2": "123",
    "client3": "123"
}
session_dict = dict()
rng = np.random.default_rng()


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
    # params, r = r.split("?", 1) if "?" in r else (r, "")
    query, fragment = r.split("#", 1) if "#" in r else (r, "")
    target = path.split("/")[-1]
    queries = query.split("&") if "&" in query else [query]
    queries_dict = dict()
    for q in queries:
        key_value = q.split('=') if "=" in q else None
        if key_value is None:
            continue
        key, value = key_value[0], key_value[1]
        queries_dict[key] = value

    out_dict = {
        "scheme": scheme,
        "net_location": net_location,
        "path": path,
        # "params": params,
        "query": query,
        "fragment": fragment,
        'target': target,
        "queries_dict": queries_dict
    }
    print(out_dict)
    return out_dict


class server:
    def __init__(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = server_socket
        path = Path(DATA_ROOT)
        self.root = path
        if not path.exists():
            path.mkdir()

        server_socket.bind(("localhost", 8080))

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

    @staticmethod
    def decode_raw_data(data):
        headers_body = data.split(b'\r\n\r\n')
        if len(headers_body) == 2:
            headers = headers_body[0]
            body = headers_body[1]
        else:
            headers = headers_body[0]
            body = None
        headers = headers.decode("utf-8")
        req = {
            "headers": headers,
            "body": body
        }
        return req

    def handle_conn(self, client_socket: socket.socket, client_address: tuple):
        data = client_socket.recv(4096)
        req = self.decode_raw_data(data)
        self.handle_first_req(client_socket, req)

        while True:
            data = client_socket.recv(4096)
            req = self.decode_raw_data(data)
            if len(data) < 1:
                continue
            response,isClose = self.handle_request(client_socket, req)
            self.send(client_socket, response)
            if isClose:
                client_socket.close()

            # finally:
            # client_socket.close()
            # break

    @staticmethod
    def send(client_socket: socket.socket, response):
        if response is None:
            logging.exception(f"trying to send an empty response to: {client_socket}")
            return
        if type(response).__name__ == "str":
            print(1)
            response = response.encode('utf-8')
        print("send")
        client_socket.sendall(response)

    def handle_first_req(self, client_socket, req:dict):

        auth_flag, _ = self.check_auth(req)

        if auth_flag:
            response,isClose = self.handle_request(client_socket, req)
            self.send(client_socket, response)
            print("auth success")
            if isClose:client_socket.close()
            return

        response = self.authorization()
        self.send(client_socket, response)

        data = client_socket.recv(4096)
        req = self.decode_raw_data(data)
        auth_flag, username = self.check_auth(req)

        if not auth_flag:
            self.send(client_socket, self.unAuthorized())
            logging.info("auth failed")
            client_socket.close()

        response, isClose = self.handle_request(client_socket, req)
        self.send(client_socket, response)
        print("auth success")
        if isClose: client_socket.close()
        return

    @staticmethod
    def check_auth(req:dict) -> (bool, None | str):
        headers_ = req["headers"]
        headers = headers_.split(NEWLINE)
        auth_flag = False
        usr_name = None
        for header in headers:
            if header.__contains__("Authorization"):
                _, r = header.split(":")
                temp = r.split(" ")
                if len(temp) < 2:
                    break
                auth_method, code = temp[0], temp[len(temp) - 1]
                temp = base64.b64decode(code).decode("utf-8").split(":")
                print(temp)
                if len(temp) < 2:
                    break
                usr_name, pw = temp[0], temp[1]
                if user_dict[usr_name] != pw:
                    break
                auth_flag = True
                break

            elif header.__contains__("Cookie"):
                cookies = header.split(":")[1]
                cookies = cookies.split(";")
                print(cookies)
                for cookie in cookies:
                    cookie: str
                    cookie = cookie.strip()
                    session_name, session_id = cookie.split("=") if "=" in cookie else None, None
                    if session_name is None or session_id is None:
                        continue
                    if session_dict[session_name] != session_id:
                        continue
                    else:
                        usr_name = session_name
                        auth_flag = True
                break

        return auth_flag, usr_name

    """
    method URL version CRLF <- request_line
    header_name:value CRLF
    header_name:value CRLF
    ...
    header_name:value CRLF
    CRLF
    payload
    """

    def handle_request(self, client_socket, req, isHead=False):
        try:
            header = req["headers"]
            body:bytes
            body = req["body"]
            headers = header.split(NEWLINE)
            headers_dict = self.list2dict(headers)
            request_line = headers[0].split()
            req_method = request_line[0]
            url = request_line[1]

            decoded_url = url_decoder(url)
            isClose = headers_dict.get("Connection", "keep-alive") == "close"

        except IndexError:
            a = 1

        if len(request_line) == 0:
            return

        if req_method == "GET" or req_method == "HEAD":
            return self.get_request(client_socket, decoded_url, headers_dict, isHead=req_method == "HEAD"),isClose
        elif req_method == "POST":
            return self.post_request(client_socket, decoded_url, headers_dict, body),isClose
        return self.not_supported_request(),isClose

    @staticmethod
    def list2dict(list_):
        dict_ = dict()
        for l in list_:
            k_v = l.split(":") if ":" in l else None
            if k_v is None:
                continue
            k, v = k_v[0], k_v[1]
            dict_[k] = v
        return dict_

    def get_request(self, client_socket, decoded_url, headers, isHead):

        if "." in decoded_url['target'] and decoded_url['target'][-1] != ".":
            body = self.download(client_socket, decoded_url, headers, isHead)
        else:
            body = self.view(client_socket, decoded_url, headers, isHead)
        return body

    def post_request(self, client_socket, decoded_url, headers_dict, body:bytes):

        if decoded_url['target'] == "upload":
            return self.upload(decoded_url, body,headers_dict)
        elif decoded_url['target'] == "delete":
            return self.delete(decoded_url)
        else:
            return self.not_supported_request()

    def download(self, client_socket, decoded_url, headers_dict, isHead):
        path = decoded_url['path']
        path = DATA_ROOT + "\\\\" + path.replace("\\", "\\\\")
        path_ = Path(path)
        print(f"download: {decoded_url['path']}")
        ftype = mimetypes.guess_type(path_)[0]
        content = path_.open('rb').read()
        # return self.download_regular(content, ftype)

        q_dict = decoded_url["queries_dict"]
        if q_dict is None or q_dict.get("chunk") is None or q_dict["chunked"] != 1:
            return self.download_regular(content, ftype, isHead)
        else:
            return self.send_chunked(client_socket, content, ftype)

    @staticmethod
    def download_regular(content, mime_type, isHead) -> bytes:
        resp = Response()
        resp.set_status_line(SCHEME, 200, "OK")
        # print(mimetypes.guess_type(path)[0])
        resp.set_content_type(mime_type, "")
        resp.set_keep_alive()
        resp.body = content
        out = resp.build_byte()
        return out

    def view(self, client_socket, decoded_url, headers_dict, isHead):
        # if decoded_url['target'].endswith("."):
        path = decoded_url['path']
        path = path.replace("\\", "\\\\")
        path = path.replace("/", "\\")
        print(f"view: {path}")
        html_file = generate_view_html(DATA_ROOT + "\\" + path, path, LOCATION)
        ftype = MIME_TYPE["html"]

        q_dict = decoded_url["queries_dict"]
        if q_dict is None or len(q_dict) < 1:
            resp = Response()
            resp.set_status_line(SCHEME, 200, "OK")
            resp.set_content_type(MIME_TYPE["html"], "utf-8")
            resp.set_keep_alive()
            resp.body = html_file
            return resp.build()
        elif q_dict.get("chunk") is not None and q_dict["chunked"] == 1:
            return self.send_chunked(client_socket, html_file, ftype)
        elif headers_dict.get("Range") is not None:
            return self.send_ranged(client_socket, html_file, ftype, headers_dict["Range"])

    def send_chunked(self, client_socket, content, mime_type):
        # resp = Response()
        # resp.set_status_line(SCHEME, 200, "OK")
        # resp.set_content_type(mime_type, "")
        # resp.set_keep_alive()
        # resp.set_chunked()
        # resp.body = None

        resp_chunk = Response()
        if type(content).__name__() == "str":
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

    def send_ranged(self, client_socket, content, mime_type_, range_):
        logging.info("Range send triggered")
        resp_ranged = Response()
        resp_ranged.set_keep_alive()
        resp_ranged.set_accept_ranges()
        resp_ranged.set_status_line(SCHEME, 206, "Partial Content")
        if type(content).__name__() == "str":
            content = content.encode()
        # pointer = 0
        # rest_len = len(content)
        file_size = len(content)
        # range_tuple = list(tuple)
        if len(range_) > 1:
            mime_type = "multipart/byteranges"
        else:
            mime_type = mime_type_

        for r in range_:
            s, t = r.split("-")
            resp_ranged.set_ranged(s, t, file_size)
            if s is None:
                s_, t_ = file_size - t + 1, file_size
            elif t is None:
                s_, t_ = s, file_size
            else:
                s_, t_ = s, t
            resp_ranged.set_content_length(t_ - s_ + 1)
            resp_ranged.set_content_type(mime_type, "")
            if s_ < 0 or t_ > file_size:
                resp_ranged.set_range_not_satisfiable()
            else:
                resp_ranged.body = content[s_:t_]

            client_socket.sendall(resp_ranged.build_byte())

        # while True:
        #     resp_ranged.set_ranged(pointer,pointer+next_range,file_size)
        return

    def upload(self, decoded_url, body_:bytes,headers):
        pattern = re.compile(r"filename=(.+)")
        match = pattern.search(headers['Content-Disposition'])
        if match:
           file_name = match.group(1)
           print(file_name)
        body = body_.decode() #TODO
        q_dict = decoded_url["queries_dict"]
        path = q_dict["path"]
        path=path[:-1]
        path = DATA_ROOT + path.replace("\\", "\\\\")
        path=path.replace("\\","/")
        print(path)
        filee=path+'/'+file_name
        fill=open(filee,'wb')
        fill.write(body.encode())
        fill.close
        file_size = len(body)
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
        resp = Response()
        resp.set_status_line(SCHEME, 400, "Bad Request")
        resp.set_keep_alive()
        resp.body = open("400.html", "r").read()
        return resp.build()

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

    def pass_auth(self, usr):
        resp = Response()
        resp.set_status_line(SCHEME, 200, "OK")
        resp.set_auth()
        resp.set_keep_alive()
        cok = hash(usr) + rng.integers(1, 50)
        resp.set_cookie(usr, cok)
        session_dict[usr] = cok
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

    def set_accept_ranges(self):
        self.headers["Accept-Ranges"] = "bytes"

    def set_auth(self):
        self.headers["WWW-Authenticate"] = "Basic realm=\"Authorization Required\""

    def set_content_length(self, length):
        self.headers["Content-Length"] = str(length)

    def set_chunked(self):
        self.headers["Transfer-Encoding"] = "chunked"

    def set_ranged(self, start, end, maximum):
        self.headers["Content-Range"] = f"bytes {str(start)}-{str(end)}/{str(maximum)}"

    def set_range_not_satisfiable(self):
        self.set_status_line(SCHEME, 416, "Range Not Satisfiable")

    def set_cookie(self, usr, param):
        self.headers["Set-Cookie"] = str(usr) + "=" + str(param) + "; path=/"
        return

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
