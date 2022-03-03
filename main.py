#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse, signal
import time
from function import *
from classes import *
from global_variable import *

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    # 参数解析
    parser = argparse.ArgumentParser(description='信息收集工具')
    parser.add_argument('-t', '--target', help='目标网站的域名,格式:-t/--target 目标域名')
    parser.add_argument('-f', '--filename', help='自定义文件名,格式:-f/--filename 自定义文件名')
    parser.add_argument('-s', '--skipsubdomain', action='store_false', help='跳过子域名的c段网络扫描,只扫描主域c段网络')
    parser.add_argument('-m', '--maxsubdomain', help='指定最大子域名网络扫描数量')
    args = parser.parse_args()
    target = args.target
    filename = args.filename
    filename = input_filename(filename)
    skipsubdomain = args.skipsubdomain
    maxsubdomain = args.maxsubdomain
    maxsubdomain=deal_maxsubdomain(maxsubdomain)
    # 初始化文件
    init_excel(filename)
    # 实例化初始化处理域名函数
    init = initialize(target)
    # 获取主域
    domain = init.domain
    # 处理目标域名
    target = init.tartget
    # 获取目标ip
    target_ip = init.target_ip
    # 获取ICP备案信息
    ICP(domain)
    icp_info = ICP.get_beian()
    save_ICP_data(icp_info, filename)
    print(icp_info)
    # 获取whois信息
    whois = whois(domain)
    whois_info = whois.get_info()
    save_whois_data(whois_info, filename)
    print(whois_info)
    # 爆破子域名信息
    burp = bp(domain)
    subdomain_info = burp.subdomain_info
    subdomain_info = deal_subdomain_info(subdomain_info, domain, init.domain_ip)
    save_subdomain_data(subdomain_info, filename)
    print(subdomain_info)
    # 主域名网络扫描
    scan = syn_scan(target_ip, filename)
    # 获取剩余子域名
    last_subdomain_list=get_last_subdomain(filename,target_ip)
    last_subdomain_list=compare_ip_domain(filename,last_subdomain_list)
    # print(last_subdomain_list)
    # 是否跳过子域名网络扫描
    if skipsubdomain==True:
        # 不跳过网络扫描
        # 是否指定最大网络扫描子域名数量
        if maxsubdomain==None:
            num = 0
            while True:
                # 扫描剩下的子域名数量
                max_subdomain_num=len(last_subdomain_list)
                if max_subdomain_num==0:
                    break
                else:
                    subdomain_ip = last_subdomain_list[0][1]
                    if judge_repleate_ip(subdomain_ip,filename):
                        last_subdomain_list = compare_ip_domain(filename,last_subdomain_list)
                    else:
                        print('本次扫描ip',subdomain_ip)
                        # last_subdomain_list = compare_ip_domain(filename,last_subdomain_list)
                        scan = syn_scan(subdomain_ip, filename)
                        last_subdomain_list = compare_ip_domain(filename, last_subdomain_list)
            print('所有扫描完成！')
        else:
            # 设置计数器为0
            num=0
            while True:
                num+=1
                # 参数指定的最大子域名扫描数
                maxsubdomain=int(maxsubdomain)
                # 扫描剩下的子域名数量
                max_subdomain_num=len(last_subdomain_list)
                if max_subdomain_num==0:
                    break
                elif num>maxsubdomain:
                    break
                else:
                    subdomain_ip = last_subdomain_list[0][1]
                    if judge_repleate_ip(subdomain_ip, filename):
                        last_subdomain_list = compare_ip_domain(filename, last_subdomain_list)
                    else:
                        print('本次扫描ip', subdomain_ip)
                        scan = syn_scan(subdomain_ip, filename)
                        last_subdomain_list = compare_ip_domain(filename, last_subdomain_list)
            print('所有扫描完成！')
    elif skipsubdomain==False:
        # 跳过网络扫描 
        print('所有扫描完成！')
