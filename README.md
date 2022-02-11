# information-gathering

## information-gathering

​		一键信息收集项目,主要功能为自动收集域名的ICP备案信息,whois信息,通过爆破收集子域名信息，收集主域名和子域名的c段网络端口/主机信息。

- 支持版本：![](https://img.shields.io/badge/python-3.x-blue)
- 支持平台：![](https://img.shields.io/badge/platform-windows-green) ![](https://img.shields.io/badge/platform-linux-brightgreen) 
- 安装要求：Linux下需要nodejs和nmap的支持，windows下仅需nmap支持。

注意事项：

1.软件运行需要网络支持，请勿断网。
2.在linux环境下运行完成后可能会导致shell的混乱。
3.本项目采用了多线程，性能消耗较大，建议cpu不小于2核，运行内存大于2G。

## 参数说明

```sh
-t 目标网站的域名
-f 自定义文件名
-m 指定除主域名扫描外子域名c段网络扫描的最大数量
-s 跳过子域名的c段网络扫描，只扫描主域名的c段网络
```


## 运行项目

##### 下载代码

- git clone

```sh
git clone git://github.com/flalucifer/information-gathering.git
```

- releases

```
https://github.com/flalucifer/information-gathering/releases/ 下载对应压缩文件
```

##### 安装依赖

```sh
pip install -r requirements.txt
```

##### 安装nmap软件

​		https://nmap.org/download.html

##### linux下额外配置

​		安装node.js：https://nodejs.org/en/download/

##### 运行项目

```sh
python main.py -t exsample.com
```

## 问题反馈

​		任何问题欢迎在[Issues](https://github.com/flalucifer/information-gathering/issues) 中反馈，你的反馈会让此项目变得更加完美。

## 贡献代码

​		本项目依然不够完善，如果发现bug或有新的功能添加，请在[Issues](https://github.com/flalucifer/information-gathering/issues)中提交bug(或新功能)描述，我会尽力改进，使她它更加完美。

​		这里衷心感谢以下contributor的无私奉献：

​		[@flalucifer](https://github.com/flalucifer/) 



