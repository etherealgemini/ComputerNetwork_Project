# ComputerNetwork_Project_Group_10

## Member
|          |      |
|----------|------|
| 12112001 | 赵中伟  |
| 12112007 | 何子萌  |
| 12110722 | 郑凯晟  |

## Description

本项目实现了一个简单的HTTP server，具有如下功能：

1. 简单的HEAD, GET, POST操作，包括文件的查看、上传、下载、删除、新建文件夹
2. 简单的网页界面，可完成上述所有操作
3. 用户登录与权限控制，非本用户在其他用户文件夹是**只读**的。
4. 支持session与cookie，与自定义的过期时间，默认为3000秒
5. 支持分块传输
6. 支持断点续传，以及多线程下载（需客户端支持）。
7. url编码（如中文）的解码

在delete方法上测试了ssl功能。

## Requirement

Python 3.10.12

apscheduler, argparse, ast, 

base64, cryptography, datetime, hashlib, logging, 

mimetypes, numpy, re, socket, threading

cryptography: SSL
select: concurrent support
hashlib: generate trunk boundary
apscheduler: session expire timer
pathlib & ast: file tree structure read in



