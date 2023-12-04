import copy
import socket
import threading

NEWLINE = "\r\n"


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
    :parameter url
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
        "scheme":scheme,
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
            client_socket.send(response)

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
        data = req.strip().split(NEWLINE)
        request_line = data[0].split()
        req_method = request_line[0]
        url = request_line[1]

        decoded_url = url_decoder(url)

        if len(request_line) == 0:
            return

        if req_method == "GET":
            return self.get_request(decoded_url)
        elif req_method == "POST":
            return self.post_request(decoded_url)
        return self.not_supported_request()

    def get_request(self, decoded_url):

        if "." in decoded_url["target"]:
            return self.download(decoded_url)
        else:
            return self.view(decoded_url)

    def post_request(self, decoded_url):

        if decoded_url["target"] == "upload":
            return self.upload(decoded_url)
        elif decoded_url["target"] == "delete":
            return self.delete(decoded_url)


if __name__ == "__main__":
    server()
