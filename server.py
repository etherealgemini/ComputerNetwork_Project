import socket
import threading


class server:
    def __init__(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = server_socket

        server_socket.bind(('localhost', 8000))

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
            data = client_socket.recv(1024)
            req = data.decode("utf-8")


if __name__ == "__main__":
    server()
