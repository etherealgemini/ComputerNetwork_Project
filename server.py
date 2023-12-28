import base64
import logging
import sys
import mimetypes
import re
import socket
import threading
from ast import walk
from pathlib import Path
from hashlib import sha256
from re import Pattern

import numpy as np

from util import *

# 运行后，将在路径D:\\temp\pythonServer创建根目录文件夹，浏览器中运行http:\\localhost:8000\查看
os.environ['PYTHONUTF8'] = '1'

NEWLINE = "\r\n"
FILE_ROOT = os.getcwd()
DATA_ROOT = FILE_ROOT + "\\data"
LOCATION = "http:\\\\localhost:8080\\"
SCHEME = "HTTP/1.1"
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
session_usr_dict = dict()
rng = np.random.default_rng()

host = sys.argv[2] 
port = int(sys.argv[4])


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
        self.session_dict_init()
        print(host)
        print(port)
        server_socket.bind((host,8080))

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
        # 使用正则表达式准确定位头部和主体的位置
        headers_body_match = re.search(b'\r\n\r\n', data)

        if headers_body_match:
            # 使用 re.split 进行分割
            headers_body = re.split(b'\r\n\r\n', data, 1)
            headers = headers_body[0]
            body = headers_body[1] if len(headers_body) > 1 else b''
        else:
            headers = data
            body = b''

        headers = headers.decode("utf-8")
        try:
            body_ = body.decode("utf-8")
        except UnicodeDecodeError:
            body_ = body

        req = {
            "headers": headers,
            "body": body_  # 如果有主体的话，也进行 utf-8 解码
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
            response, isClose = self.handle_request(client_socket, req)
            self.send(client_socket, response)
            if isClose:
                client_socket.close()

            # finally:
            # client_socket.close()
            # break

    @staticmethod
    def send(client_socket: socket.socket, response, username=None):
        if response is None:
            logging.exception(f"trying to send an empty response to: {client_socket}")
            return

        if type(response).__name__ == "Response":
            response: Response
            if response.body is None:
                response.body = ""
            if username != None:
                response.set_session(username)
            bd_name = type(response.body).__name__
            if bd_name == "str":
                response = response.build()
            elif bd_name == "bytes":
                response = response.build_byte()

        if type(response).__name__ == "str":
            print(1)
            response = response.encode('utf-8')

        print("send")
        client_socket.sendall(response)

    def handle_first_req(self, client_socket, req: dict):

        auth_flag, username = self.check_auth(req)

        if auth_flag:
            response, isClose = self.handle_request(client_socket, req)
            self.send(client_socket, response, username)
            print("auth success")
            if isClose: client_socket.close()
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
        self.send(client_socket, response, username)
        print("auth success")
        if isClose: client_socket.close()
        return

    @staticmethod
    def check_auth(req: dict) -> (bool, None | str):
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
                    name_id, _ = cookie.split("=") if "=" in cookie else None, None
                    session_name, session_id = name_id
                    if session_name == "session-id" and session_id in session_usr_dict.keys():
                        auth_flag = True
                        usr_name = session_usr_dict[session_id]
                        break
                    if session_name is None or session_id is None:
                        continue
                    # if session_dict[session_name] != session_id:
                    #     continue
                    elif session_dict[session_name] == session_id:
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
            body: bytes
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
            return self.get_request(client_socket, decoded_url, headers_dict, isHead=req_method == "HEAD"), isClose
        elif req_method == "POST":
            headers_ = req["headers"]
            headers = headers_.split(NEWLINE)
            limit = False
            for header in headers:
                if header.__contains__("Authorization"):
                    _, r = header.split(":")
                    temp = r.split(" ")
                    if len(temp) < 2:
                        break
                    auth_method, code = temp[0], temp[len(temp) - 1]
                    temp = base64.b64decode(code).decode("utf-8").split(":")
                    #print(temp)
                    #print(temp[0])
                    q_dict = decoded_url["queries_dict"]
                    path = q_dict.get("path")
                    #print(path)
                    if (path != None):
                        path = path.split("/")[0]
                        #print(2)
                        #print(path)
                        if (temp[0] != path):
                            limit = True

            return self.post_request(client_socket, decoded_url, headers_dict, body, limit), isClose
        return self.method_not_allowed(), isClose

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

    def post_request(self, client_socket, decoded_url, headers_dict, body: bytes,limit):
        if limit:
            response = Response()
            response.set_status_line(SCHEME, 403, "Forbidden")
            response.set_content_type("text/plain", "")
            response.set_content_length(0)
            response.set_keep_alive()
            response.body = None
            return response
        if decoded_url['target'] == "upload":
            return self.upload(decoded_url, body, headers_dict)
        elif decoded_url['target'] == "delete":
            return self.delete(decoded_url)
        else:
            return self.method_not_allowed()

    def download(self, client_socket, decoded_url, headers_dict, isHead):
        path = decoded_url['path']
        path = DATA_ROOT + "\\\\" + path.replace("\\", "\\\\")
        path_ = Path(path)
        print(f"download: {decoded_url['path']}")
        ftype = mimetypes.guess_type(path_)[0]
        try:
            content = path_.open('rb').read()
        # return self.download_regular(content, ftype)
        except FileNotFoundError:
            return self.bad_request()
        q_dict = decoded_url["queries_dict"]
        if q_dict is None:
            return self.download_regular(content, ftype, isHead)
        elif headers_dict.get("Range") is not None:
            range__ = headers_dict["Range"]
            range_ = range__.split(",") if "," in range__ else range__.strip()
            return self.send_ranged(client_socket, content, ftype, range_)
        elif q_dict.get("chunk") is not None and q_dict["chunked"] == 1:
            return self.send_chunked(client_socket, content, ftype)
        else:
            return self.download_regular(content, ftype, isHead)

    @staticmethod
    def download_regular(content, mime_type, isHead) -> bytes:
        resp = Response()
        resp.set_status_line(SCHEME, 200, "OK")
        # print(mimetypes.guess_type(path)[0])
        resp.set_content_type(mime_type, "")
        resp.set_keep_alive()
        resp.body = content
        # out = resp.build_byte()
        return resp

    def view(self, client_socket, decoded_url, headers_dict, isHead):
        # if decoded_url['target'].endswith("."):
        path = decoded_url['path']
        path = path.replace("\\", "\\\\")
        path = path.replace("/", "\\")
        print(f"view: {path}")
        local_path = DATA_ROOT + "\\" + path
        html_file = generate_view_html(local_path, path, LOCATION)
        ftype = MIME_TYPE["html"]

        q_dict = decoded_url['queries_dict']
        if q_dict is None or q_dict.get('SUSTech-HTTP') is None or q_dict.get('SUSTech-HTTP') == '0' or isHead:
            resp = Response()
            resp.set_status_line(SCHEME, 200, "OK")
            if not isHead:
                resp.set_content_type(MIME_TYPE['html'], "utf-8")
                resp.body = html_file
            else:
                resp.body = ""
            print("view get html")
            return resp
        if q_dict.get('SUSTech-HTTP') == '1':
            resp = Response()
            resp.set_status_line(SCHEME, 200, "OK")
            resp.set_content_type("text/plain", "utf-8")
            resp.body = walk(local_path)
            print("view get list")
            return resp
        if q_dict.get("chunk") is not None and q_dict["chunked"] == 1:
            return self.send_chunked(client_socket, html_file, ftype)
        elif headers_dict.get("Range") is not None:
            range__ = headers_dict["Range"]
            range_ = range__.split(",") if "," in range__ else range__.strip()
            return self.send_ranged(client_socket, html_file, ftype, range_)

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
        if type(content).__name__ == "str":
            content = content.encode()
        # pointer = 0
        # rest_len = len(content)
        file_size = len(content)
        # range_tuple = list(tuple)
        if len(range_) > 1:
            mime_type = "multipart/byteranges"
            boundary = sha256(content + b'sustech').hexdigest()[:13]
            print(boundary)
            resp_ranged.set_content_type("", "", boundary)
            boundary = boundary.encode()

            resp_ranged.body = b''
            for idx in range(len(range_)):
                resp_ranged.body += b'--' + boundary
                resp_ranged.body += NEWLINE.encode()

                r = range_[idx]
                s, t = r.split("-")
                s = int(s)
                t = int(t)
                resp_ranged.body_build_ranged(s, t, file_size,isByte=True)
                resp_ranged.body += NEWLINE.encode()
                resp_ranged.body_build_content_type(mime_type_, isByte=True)
                resp_ranged.body += NEWLINE.encode()
                resp_ranged.body += NEWLINE.encode()

                if s is None:
                    s_, t_ = file_size - t + 1, file_size
                elif t is None:
                    s_, t_ = s, file_size
                else:
                    s_, t_ = s, t

                # resp_ranged.body_build_content_length(t_ - s_ + 1,isByte=True)
                if s_ < 0 or t_ > file_size:
                    resp_ranged.set_range_not_satisfiable()
                else:
                    resp_ranged.body += content[s_:t_]
                    resp_ranged.body += NEWLINE.encode()
                    if idx == len(range_) - 1:
                        resp_ranged.body += b'--' + boundary + b'--'


            client_socket.sendall(resp_ranged.build_byte())

        else:
            mime_type = mime_type_
            s, t = range_.split("-")
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

        #     single part



        # while True:
        #     resp_ranged.set_ranged(pointer,pointer+next_range,file_size)
        return

    def upload(self, decoded_url, body_: bytes, headers):
        print(headers)
        print(1)
        print(body_)
        body = body_  # TODO
        print(1)
        print(body)
        body_type = type(body).__name__
        if body_type=="str":
            pat_file_name = re.compile(r"filename=(.+)")
            pat_boundary = re.compile(r'--([a-f\d]+)')
            pat_content_disp = "Content-Disposition"
            pat_enter = "\n"
        elif body_type=="bytes":
            pat_file_name = re.compile(rb"filename=(.+)")
            pat_boundary = re.compile(rb'--([a-f\d]+)')
            pat_content_disp = b"Content-Disposition"
            pat_enter = b"\n"
        match = pat_file_name.search(body)
        if match:
            file_name = match.group(1)
            print(file_name)

        match = re.search(pat_boundary, body)
        if match:
            separator = match.group(1)

            # 找到Content-Disposition头部
            header_start = body.find(pat_content_disp)
            header_end = body.find(pat_enter, header_start)
            header = body[header_start:header_end]

            # 找到正文的开始和结束位置
            content_start = body.find(pat_enter, header_end) + 1
            content_end = body.find(separator, content_start) - 2

            # 提取正文内容
            content = body[content_start:content_end]

            body = content
        else:
            body = None
        print(body)
        q_dict = decoded_url["queries_dict"]
        path = q_dict["path"]
        path = DATA_ROOT + '\\' + path
        print(path)
        path = path.replace("\\", "/")
        print(path)
        file_name = file_name[1:-2]
        file_name = file_name if body_type == "str" else file_name.decode()
        filee = path + file_name
        print(filee)
        if not os.path.exists(path):
            os.makedirs(path)
        fill = open(filee, 'wb')
        if body_type == "str":
            body = body.encode()
        fill.write(body)
        fill.close()
        file_size = len(body)
        response = Response()
        response.set_status_line(SCHEME, 200, "OK")
        response.set_content_type("text/plain", "")
        response.set_content_length(0)
        response.set_keep_alive()
        response.body = None

        return response

    def delete(self, decoded_url):
        q_dict = decoded_url["queries_dict"]
        path = q_dict.get("path")
        print(2)
        print(path)

        if path:
            path = DATA_ROOT + "\\" + path.replace("/", "\\")
            print(2)
            print(path)

            if os.path.exists(path):
                os.remove(path)
                response = Response()
                response.set_status_line(SCHEME, 200, "OK")
                response.set_content_type("text/plain", "")
                response.set_content_length(0)  # Assuming no content in the response body for a successful delete
                response.set_keep_alive()
                response.body = None
                return response
            else:
                # File not found
                response = Response()
                response.set_status_line(SCHEME, 404, "Not Found")
                response.set_content_type("text/plain", "")
                response.set_content_length(0)
                response.set_keep_alive()
                response.body = None
                return response
        else:
            # Invalid request, missing 'path' parameter
            response = Response()
            response.set_status_line(SCHEME, 400, "Bad Request")
            response.set_content_type("text/plain", "")
            response.set_content_length(0)
            response.set_keep_alive()
            response.body = None
            return response

    # def not_supported_request(self):
    #     print("request not supported")
    #     resp = Response()
    #     resp.set_status_line(SCHEME, 400, "Bad Request")
    #     # resp.set_keep_alive(headers_dict.get('Connect') != "keep-alive")
    #     resp.body = open("400.html", "r").read()
    #     return resp.build()

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

    def bad_request(self):
        resp = Response()
        resp.set_status_line(SCHEME, 400, "Bad Request")
        resp.set_content_type(MIME_TYPE['html'], "utf-8")
        resp.body = open('400.html', "r").read()
        return resp.build()

    def method_not_allowed(self):
        resp = Response()
        resp.set_status_line(SCHEME, 405, "METHOD NOT ALLOWED")
        resp.set_content_type(MIME_TYPE['html'], "utf-8")
        resp.body = open('405.html', "r").read()
        return resp.build()

    def session_dict_init(self):
        for usr in user_dict.keys():
            session_usr_dict[str(hash(usr) + hash(user_dict[usr]))] = usr
        return


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

    def set_content_type(self, type_: str, charset: str, boundary=None):
        ct = type_
        if boundary is not None:
            ct += f"multipart/byteranges; boundary={boundary}"
            self.headers["Content-Type"] = ct
            return
        if charset != "":
            ct += "; charset=" + charset
        self.headers["Content-Type"] = ct

    def body_build_content_type(self, type_, isByte=False):
        ct = f"Content-Type:{str(type_)}"
        if isByte:
            ct = ct.encode()
        self.body += ct

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

    def body_build_content_length(self, length, isByte=False):
        cl = f"Content-Length:{str(length)}"
        if isByte:
            cl.encode()
        self.body += cl

    def set_chunked(self):
        self.headers["Transfer-Encoding"] = "chunked"

    def set_ranged(self, start, end, maximum):
        self.headers["Content-Range"] = f"bytes {str(start)}-{str(end)}/{str(maximum)}"

    def body_build_ranged(self, start, end, maximum, isByte=False):
        rg = f"Content-Range: bytes {str(start)}-{str(end)}/{str(maximum)}"
        if isByte:
            rg = rg.encode()
        self.body += rg

    def set_range_not_satisfiable(self):
        self.set_status_line(SCHEME, 416, "Range Not Satisfiable")

    def set_cookie(self, usr, param):
        self.headers["Set-Cookie"] = str(usr) + "=" + str(param) + "; path=/"
        return

    def set_session(self, usr):
        self.headers["Set-Cookie"] = "session-id=" + str(hash(usr) + hash(user_dict[usr])) + "; path=/"
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
