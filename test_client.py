import socket

# 客户端将socket套接字赋给sock套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 客户端调用sock.connect主动初始化服务器连接，参数为（hostname,port）
sock.connect(('127.0.0.1', 8000))
# 客户端调用sock.send向服务器发送数据
sock.send(b"GET/HTTP/1.1\r\nHost:127.0.0.1:8080\r\n\r\n")
# 客户端使用套接字data代替sock.recv接受的数据值
data = sock.recv(4096)
# 打印出来data
print(data)
# 关闭套接字
sock.close()
