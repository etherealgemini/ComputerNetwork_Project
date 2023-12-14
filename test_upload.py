import socket

# 定义要上传的 URL，可以根据需要修改
url = "http://localhost:8080/upload?path=/11912113/"

# 定义要上传的 HTML 文件的路径，可以根据需要修改
file_path = "C:/Users/14630/Desktop/ybb.txt"

# 以二进制模式打开文件，读取文件内容
with open(file_path, "rb") as f:
    file_content = f.read()

# 获取文件内容的长度
content_length = len(file_content)

# 定义请求头，指定内容类型为 text/html
headers = "Content-Type: text/html\r\n"

# 构造 HTTP 请求报文，注意要以 \r\n 结尾
request = f"POST {url} / HTTP/1.1\r\nAuthorization: Basic dGVzdDoxMjM0NTY=\r\n{headers}Content-Length: {content_length}\r\n\r\n".encode("utf-8") + file_content

# 创建一个 socket 对象，指定 IPv4 协议和 TCP 协议
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接到服务器的 IP 地址和端口号，可以根据需要修改
s.connect(("127.0.0.1", 8000))

# 发送请求报文
s.sendall(request)

# 接收响应报文，指定最大字节数，可以根据需要修改
response = s.recv(4096)

# 关闭 socket 连接
s.close()

# 打印响应报文
print(response.decode("utf-8"))