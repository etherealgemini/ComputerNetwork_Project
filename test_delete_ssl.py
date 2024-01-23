import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import serialization

# 定义要删除的 URL，可以根据需要修改
url = "http://localhost:8080/delete?path=/client1/a.py"

# 创建一个 socket 对象
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接到服务器
s.connect(("127.0.0.1", 8080))
s.send(b"request public key")
public_key_b64 = s.recv(1024)
public_key = serialization.load_pem_public_key(base64.b64decode(public_key_b64))
print("Server public key:", public_key_b64.decode())
symmetric_key = Fernet.generate_key()
encrypted_symmetric_key = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
s.send(encrypted_symmetric_key)
fernet = Fernet(symmetric_key)
print("Symmetric key:", symmetric_key.decode())

def encrypt_send(fernet,data,s:socket.socket):
    encrypted_data = fernet.encrypt(data)
    s.send(encrypted_data)

def decrypt_recv(fernet,s:socket.socket):
    # 接收加密数据
    encrypted_data = s.recv(1024)
    # 对称解密数据
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data


# 构造一个请求报文，包含请求行、请求头和请求体
request = f"POST {url} / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: python-requests/2.31.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\nContent-Length: 0\r\n\r\n"

# 将请求报文编码为字节串
request = request.encode("utf-8")

# 发送请求报文
encrypt_send(fernet,request,s)

# 接收响应报文
response=decrypt_recv(fernet,s)

# 打印响应报文
print(response)

# 关闭 socket 连接
s.close()
