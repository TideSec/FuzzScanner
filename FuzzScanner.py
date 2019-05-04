#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018-04-03 10:57
# @Author  : 重剑无锋
# @E-mail  : 6295259@qq.com


import os,ssl,sys,re
import socket
import random
import urllib,nmap
import urlparse
import time,requests
import threading,datetime
import xml.etree.cElementTree as ET


debug_mod = 0   #debug模式，0为关闭，1为开启
crawl_deepth = 2
c_all_port = 0  #C段是否扫全端口

try:
    import requests
except:
    print 'pip install requests[security]'
    os._exit(0)

try:
    import lxml
except:
    print 'pip install lxml'
    os._exit(0)

try:
    import nmap
except:
    print 'pip install python-nmap'
    os._exit(0)

# Check py version
pyversion = sys.version.split()[0]
if pyversion >= "3" or pyversion < "2.7":
    exit('Need python version 2.6.x or 2.7.x')

reload(sys)
sys.setdefaultencoding('utf-8')

lock = threading.Lock()
cookie = 'Qq:6295259'

global pwd,path,logpath,domain_ip,vulnerable

# Ignore warning
requests.packages.urllib3.disable_warnings()
# Ignore ssl warning info.
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

def requests_proxies():
    '''
    Proxies for every requests
    '''
    proxies = {
    'http':'',#127.0.0.1:1080 shadowsocks
    'https':''#127.0.0.1:8080 BurpSuite
    }
    return proxies

def url2ip(url):
    '''
    Url to ip
    '''
    ip = ''
    try:
        handel_url = urlparse.urlparse(url).hostname
        ip = socket.gethostbyname(handel_url)
    except:
        print '[!] Can not get ip'
        pass
    return ip

def requests_headers():
    '''
    Random UA  for every requests && Use cookie to scan
    '''
    user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
    'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
    'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60','Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']
    UA = random.choice(user_agent)
    headers = {
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'User-Agent':UA,'Upgrade-Insecure-Requests':'1','Connection':'keep-alive','Cache-Control':'max-age=0',
    'Accept-Encoding':'gzip, deflate, sdch','Accept-Language':'zh-CN,zh;q=0.8',
    "Referer": "http://www.baidu.com/link?url=www.so.com&url=www.soso.com&&url=www.sogou.com",
    'Cookie':cookie}
    return headers


def ip_into_int(ip):
    '''
    Check internal ip child function
    '''
    return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))

def is_internal_ip(ip):
    '''
    Filter internal ip
    10.x.x.x
    127.x.x.x
    172.x.x.x  # 172.16 | 172.31
    192.168.x.x
    '''
    ip = ip_into_int(ip)
    net_a = ip_into_int('10.255.255.255') >> 24
    net_b = ip_into_int('172.255.255.255') >> 24
    net_c = ip_into_int('192.168.255.255') >> 16
    net_d = ip_into_int('127.255.255.255') >> 24
    return ip >> 24 == net_a or ip >> 24 == net_b or ip >> 16 == net_c or ip >> 24 == net_d

def email_regex(raw):
    '''
    Collect email
    '''
    emails = []
    try:
        emails = re.findall(r"[\w!#$%&'*+=^_`|~-]+(?:\.[\w!#$%&'*+=^_`|~-]+)*[@#](?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])",str(raw))
    except Exception,e:
        print e
        pass
    return emails

def ip_regex(raw):
    '''
    Collect legal ip
    1.1.1.1 | 10.1.1.1 | 256.10.1.256 | 222.212.22.11 | 0.0.150.150 | 232.21.234.256
    '''
    ips = []
    try:
        re_ips = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',str(raw))
        for ip in re_ips:
            compile_ip = re.compile(r'^((?:(?:[1-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))(?:\.(?:(?:[0-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))){3})$')
            if compile_ip.match(ip):
                ips.append(ip)
    except Exception,e:
        print e
        pass
    return ips

def url_regex(raw):
    '''
    Collect url
    '''
    urls = []
    try:
        urls_regex = re.findall(r"((?:https?|ftp|file):\/\/[\-A-Za-z0-9+&@#/%?=~_|!:,.;\*]+[\-A-Za-z0-9+&@#/%=~_|])",str(raw))
        for url in urls_regex:
            url_flag = '<a href="'+url+'" target=_blank />'+url+'</a>'
            urls.append(url_flag)
    except Exception,e:
        print e
        pass
    return urls


def checkend(xmlfile):
    try:
        infile = open(xmlfile, 'r+')
        endxml = '''<runstats><finished time="1518405307" timestr="Sun Feb 11 22:15:07 2018" elapsed="396.80" summary="Nmap done at Sun Feb 11 22:15:07 2018; 256 IP addresses (136 hosts up) scanned in 396.80 seconds" exit="success"/><hosts up="136" down="120" total="256"/>
            </runstats>
            </nmaprun>'''
        x = infile.readlines()
        lens = len(x)
        if not x[lens - 3].startswith('<runstats>'):
            print xmlfile, " not endwith <runstats>"
            infile.write('\n')
            infile.write(endxml)
            infile.close()
            return "0"
        else:
            return "1"
    except:
        pass
def parse_xml(xmlfile,out):
    try:
        ip_data = ''
        dir_text = ''
        url =''
        tree = ET.ElementTree(file=xmlfile)
        for elem in tree.iterfind('host'):
            if (elem[0].attrib['state']) == "up":
                is_up = "up"
            else:
                is_up = "down"
            ip = elem[1].attrib['addr']
            print ip
            if elem[3].tag == 'hostnames':
                port_num = 4
            else:
                port_num = 3
            if len(elem)>3:
                ports = elem[port_num]
                port_info = ''
                dir_text_all = ''
                for x in ports.iterfind('port'):
                    port = x.attrib['portid']
                    protocol = x.attrib['protocol']
                    state = x[0].attrib['state']
                    service = ''
                    product = ''
                    product_ver = ''
                    extrainfo = ''
                    banner_brief = ''
                    url = ip + ":" + port

                    if (state == 'open'):

                        # site_info = get_header(url)
                        # if site_info:
                        #     banner_info = site_info
                        if (len(x) > 1):
                            if 'name' in x[1].keys():
                                service = x[1].attrib['name']

                            if 'product' in x[1].keys():
                                product = x[1].attrib['product']

                            if 'version' in x[1].keys():
                                product_ver = x[1].attrib['version']

                            if 'extrainfo' in x[1].keys():
                                extrainfo = x[1].attrib['extrainfo']

                            if 'ostype' in x[1].keys():
                                extrainfo = x[1].attrib['ostype']

                            if ('http' in service):
                                url = ip + ":" + port
                                rand_str = ''
                                rand_str = rand_str.join(random.sample('1234567890', 5))
                                log = logpath + 'temp/' + ip + "_" + port + "_" + str(rand_str) + '-temp.txt'
                                open(log, 'w+').close()
                                banner_brief = get_whatweb('', url, log)

                                if enumdir:
                                    dir_text = get_dirs('', url)
                                    dir_text_all = dir_text_all + '\n' + '-' * 20 + 'DirSearch_bg: ' + url + '-' * 20 + '\n' + dir_text + '\n' + '-' * 20 + 'DirSearch_ok: ' + url + '-' * 20 + '\n'

                                    # if (len(x) > 2) and ('output' in x[2].keys()):
                                    #     banner_brief = x[2].attrib['output']
                                    #     banner_brief = banner_brief.decode('utf-8', 'ignore').encode('utf-8')

                        port_data = {'port': port, 'protocol': protocol, 'state': state,
                                     'service': service, 'product': product,
                                     'extrainfo': extrainfo, 'product_ver': product_ver}

                        port_data = port + '|' + state + '|' + protocol + '|' + service + '|' + product + ' ' + product_ver + '|' + extrainfo + '###' + banner_brief

                        java_fxls = ['weblogic','jboss','websphere','rmi']

                        for java_fxl in java_fxls:
                            if java_fxl in product.lower():
                                vulnerable.write(ip+'|'+str(port_data)+'\n')
                        # print port_data
                        port_info = port_info + '\t' * 2 + str(port_data) + '\n'

                os = elem[port_num+1]
                os_info = ''
                if len(os) > 0:
                    for x in os.iterfind('osmatch'):
                        os_info = x.attrib['name']
                        break
                # print "os:", os_info

                hostnames = elem[port_num-1]
                hostname_info = ''
                if len(hostnames) > 0:
                    for x in hostnames.iterfind('hostname'):
                        hostname_info = x.attrib['name']
                        break
                # print "hostname_info:", hostname_info

                # ip_info = getipinfo(ip)
                ip_data = {'ip': ip, 'is_up': is_up, 'os': os_info, 'hostname': hostname_info}
                ip_data = ip + '|' + is_up + '|' + os_info + '|' + hostname_info
                if enumdir:
                    ip_data = '\t' + str(ip_data) + '\n' + port_info + '\n' + dir_text_all
                else:
                    ip_data = '\t' + str(ip_data) + '\n' + port_info
                # print ip_data

                # lock.acquire()
                out.write(str(ip_data) + '\n')
                # out.close()
                # lock.release()
                print "-" * 20

        return str(ip_data)
        # break
    except Exception, e:
        logfile = time.strftime('%Y-%m-%d', time.localtime(time.time()))
        now = time.strftime('%Y-%m-%d_%X', time.localtime(time.time()))
        info = '%s\n%s\nNmap scan error: %s' % (now, str(xmlfile), e)
        print info
        open(pwd + '/log/loginfo/' + logfile + '.txt', 'a+').write(info + '\n')
        return " nmap scan error "


def get_parent_paths(path):
    '''
    Get a path's parent paths
    '''
    paths = []
    if not path or path[0] != '/':
        return paths
    paths.append(path)
    if path[-1] == '/':
        path = path[:-1]
    while path:
        path = path[:path.rfind('/') + 1]
        paths.append(path)
        path = path[:-1]
    return paths
def url_paths(url):
    '''
    Get url paths
    '''
    key_urls = []
    url_path = urlparse.urlparse(url)
    url_pathss = get_parent_paths(url_path.path)
    for path in url_pathss:
        path = path.replace('//','/')
        if path != '/' and path[-1] == '/' and path[1] != '.':
            if path[:1] != '/':
                key_url = '%s://%s%s' % (url_path.scheme, url_path.netloc, path[-1])
                key_urls.append(key_url)
            else:
                key_url = '%s://%s%s' % (url_path.scheme, url_path.netloc, path)
                key_urls.append(key_url)
    return key_urls


def c_ip(ip):
    '''
    Get c_ip
    '''
    ip_list = []
    ip_split = ip.split('.')
    for c in xrange(1,255):
        ip = "%s.%s.%s.%d" % (ip_split[0],ip_split[1],ip_split[2],c)
        ip_list.append(ip)
    return ip_list

def baidu_site(key_domain):
    '''
    Get baidu site:target.com result
    '''
    headers = requests_headers()
    proxies = requests_proxies()
    baidu_domains,check = [],[]
    baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}'.format(key_domain)
    print baidu_url
    try:
        r = requests.get(url=baidu_url,headers=headers,timeout=30,proxies=proxies,verify=False).content
        if 'class=\"nors\"' not in r:# Check first
            for page in xrange(0,70):# max page_number
                pn = page * 10
                newurl = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}&pn={}&oq=site:{}'.format(key_domain,pn,key_domain)
                keys = requests.get(url=newurl,headers=headers,proxies=proxies,timeout=10,verify=False).content
                flags = re.findall(r'style=\"text-decoration:none;\">(.*?)%s.*?<\/a><div class=\"c-tools\"'%key_domain,keys)
                check_flag = re.findall(r'class="(.*?)"',keys)
                for flag in flags:
                    domain_handle = flag.replace('https://','').replace('http://','')
                    # xxooxxoo.xoxo.com ignore "..."
                    if domain_handle not in check and domain_handle != '':
                        check.append(domain_handle)
                        domain_flag = domain_handle + key_domain
                        print '[+] Get baidu site:domain > ' + domain_flag
                        baidu_domains.append(domain_flag)
                        if len(check_flag) < 2:
                            return baidu_domains
        else:
            print '[!] baidu site:domain no result'
            return baidu_domains
    except Exception,e:
        print e
        pass
    return baidu_domains


def task_subdomain(domain):
    sub_domains = []
    sub_domains.append(domain)
    fanjiexi_url = "http://6295259."+domain
    try:
        host = domain
        os.chdir(pwd)
        print "-------------baidu_domain_start-------------"

        baidu_domains = baidu_site(host)
        baidudomain = open(logpath + 'domain/' + domain + '-baidudomain.txt', 'r+')
        for baidu_domain in baidu_domains:
            baidudomain.write(baidu_domain + '\n')
        baidudomain.close()
        print "+++++++++++++baidu_domain_ok+++++++++++++"

        print "-------------wydomain_start-------------"
        wydomain = 'python ' + path + 'wydomain/wydomain.py -d ' + host + ' -o ' + logpath + 'domain/' + domain + '-wydomain.txt'
        print wydomain
        os.system(wydomain)
        print "+++++++++++++wydomain_ok+++++++++++++"

        try:
            requests.get(url=fanjiexi_url, headers=requests_headers, timeout=10, verify=False)
            print "%s is Fanjiexi." % (fanjiexi_url)
        except:
            print "-------------subdomain_start-------------"
            os.chdir(path + '/subDomainsBrute/')
            subdomain = 'python ' + path + 'subDomainsBrute/subDomainsBrute.py  ' + host + ' --out ' + logpath + 'domain/' + domain + '-subdomain.txt'
            print subdomain
            os.system(subdomain)
            print "+++++++++++++subdomain_ok+++++++++++++"

        print "-------------read_all_subdomain-------------"

        wydomain_text = open(logpath + 'domain/' + domain + '-wydomain.txt', 'r').read().replace(" ", '').replace(
            "\n", '').replace('"', '')[
                        1:-1].split(',')
        domain_all = []
        wydomains = []
        for wydomain in wydomain_text:
            wydomain = wydomain.strip('\r')
            wydomains.append(wydomain)
        if len(wydomains) < 100:
            for wydomain in wydomain_text:
                wydomain = wydomain.strip('\r')
                domain_all.append(wydomain)

        subdomain_text = open(logpath + 'domain/' + domain + '-subdomain.txt', 'r')
        sub_domain_num = []
        for x in subdomain_text.readlines():
            x = x.strip('\n').strip('\r')
            sub_domain_num.append(x)
        if len(sub_domain_num) < 100:
            for x in sub_domain_num:
                domain_all.append(x)

        baidudomain = open(logpath + 'domain/' + domain + '-baidudomain.txt', 'r')
        for baidu_domain in baidudomain.readlines():
            baidu_domain = baidu_domain.strip('\n').strip('\r')
            domain_all.append(baidu_domain)

        sub_domains = list(set(domain_all))
        domain_num = len(sub_domains)
        print logpath + domain + '-domain.txt'
        alldomain = open(logpath + domain + '-domain.txt', 'w')
        for sub_domain in sub_domains:
            sub_domain = sub_domain.strip()
            if sub_domain:
                alldomain.write(sub_domain + '\n')
                # domains = x + '\n' + domains

        print "+++++++++++++read_all_subdomain+++++++++++++"

        return sub_domains

    except:
        return sub_domains


def get_whatweb(domain,sub_domain,log):
    os.chdir(pwd)
    whatweb_text = ''
    try:
        # print "-------------whatweb_start-------------"
        whatweb = path + 'WhatWeb/whatweb --log-brief=' + log + " http://" + sub_domain
        print whatweb
        os.system(whatweb)
        # print "+++++++++++++whatweb_ok+++++++++++++"

        whatweb_text = open(log, 'r').read()
        if len(whatweb_text) > 10:
            # print whatweb_text
            pattern1 = re.compile('.*?HTTPServer\[(.*?)\]')
            httpserver = re.findall(pattern1, whatweb_text)
            if len(httpserver) > 0:
                httpserver = httpserver[0]
            else:
                httpserver = ''
            httpserver = httpserver.replace('][', ',')
            # print "httpserver:", httpserver

            pattern2 = re.compile('.*?Title\[(.*?)\]')
            title = re.findall(pattern2, whatweb_text)
            if len(title) > 0:
                title = title[0]
            else:
                title = ''
            title = title.decode('utf-8', 'ignore').encode('utf-8')
            # print title

            pattern3 = re.compile('.*?X-Powered-By\[(.*?)\]')
            xpb = re.findall(pattern3, whatweb_text)
            if len(xpb) > 0:
                xpb = xpb[0]
            else:
                xpb = ''

            pattern4 = re.compile('.*?IP\[(.*?)\]')
            ip = re.findall(pattern4, whatweb_text)
            if len(ip) > 0:
                ip = ip[0]
            else:
                ip = ''

            state = whatweb_text.split(']')[0].split('[')[1]
            return '|' + ip + '|' + state + '|' + title + '|' + httpserver + '|' + xpb + '|'
        else:
            return "|"
    except Exception,e:
        print e
        return ""



def get_waf(domain,sub_domain):
    os.chdir(pwd)
    try:
        print "-------------waf_start-------------"
        waf = 'wafw00f ' + "http://" + sub_domain + ' >> ' + logpath + 'sub/' + sub_domain + '-waf.txt'
        print waf
        os.system(waf)
        print "+++++++++++++waf_ok+++++++++++++"
        # --------------waf-------------
        waf_text = open(logpath + 'sub/' + sub_domain + '-waf.txt', 'r').read()
        # print waf_text
        pattern1 = re.compile('is behind a (.*)')
        waf1 = re.findall(pattern1, waf_text)
        waf = 'UnDetect'
        if waf1:
            waf = waf1[0]

        pattern2 = re.compile('.*?seems to be behind a WAF.*?')
        waf2 = re.findall(pattern2, waf_text)
        if waf2:
            waf = 'Unknown_Waf'

        pattern3 = re.compile('.*?No WAF detected by.*?')
        waf3 = re.findall(pattern3, waf_text)
        if waf3:
            waf = 'NoWaf'
            # print waf
        return waf
    except Exception,e:
        print "[!] Waf detect error ",e
        return ""


def get_spider(domain,sub_domain,crawl_deepth):
    print "-------------spider_start-------------"
    SRC_spider("http://" + sub_domain, logpath + 'spider/' + sub_domain + '-spider.txt',crawl_deepth)
    print "+++++++++++++spider_ok+++++++++++++"


def get_dirs(domain,sub_domain):
    try:
        dir_text = ''
        print "-------------dirsearch_start-------------"
        open(logpath + 'sub/' + sub_domain.replace(':', '_') + '-dirsearch.txt','w').close()
        dirsearch = 'python3 ' + path + 'dirsearch/dirsearch.py --max-retries 1 --timeout 3 -u ' + "http://" + sub_domain +' -e asp,php,jsp --plain-text-report ' + logpath + 'sub/' + sub_domain.replace(':', '_') + '-dirsearch.txt'
        print dirsearch
        if debug_mod:
            print "Debug_mode: dirsaerch with :", sub_domain
            open(logpath + 'sub/' + sub_domain.replace(':', '_') + '-dirsearch.txt', 'w').write("Debug_mode: dirsaerch with :"+str(sub_domain))
            time.sleep(10)
        else:
            # pass
            os.system(dirsearch)

        print "+++++++++++++dirsearch_ok+++++++++++++"

        # --------------dirsearch-------------
        dir_text = open(logpath + 'sub/' + sub_domain.replace(':', '_') + '-dirsearch.txt', 'r').read()
        if dir_text:
            return dir_text
        else:
            return "None"
    except Exception,e:
        logfile = time.strftime('%Y-%m-%d', time.localtime(time.time()))
        now = time.strftime('%Y-%m-%d_%X', time.localtime(time.time()))
        info = '%s\n%s\nDirsearch error: %s' % (now, str(sub_domain), e)
        print info
        open('./log/loginfo/' + logfile + '.txt', 'a+').write(info + '\n')
        return "Dirsearch error "


port = [1,11,13,15,17,19,21,22,23,25,26,30,31,32,33,34,35,36,37,38,39,43,53,69,70,79,80,81,82,83,84,85,88,98,100,102,110,111,113,119,123,135,137,139,143,161,179,199,214,264,280,322,389,407,443,444,445,449,465,497,500,502,505,510,514,515,517,518,523,540,548,554,587,591,616,620,623,626,628,631,636,666,731,771,782,783,789,873,888,898,900,901,902,989,990,992,993,994,995,1000,1001,1010,1022,1023,1026,1040,1041,1042,1043,1080,1091,1098,1099,1200,1212,1214,1220,1234,1241,1248,1302,1311,1314,1344,1400,1419,1432,1434,1443,1467,1471,1501,1503,1505,1521,1604,1610,1611,1666,1687,1688,1720,1723,1830,1900,1901,1911,1947,1962,1967,2000,2001,2002,2010,2024,2030,2048,2051,2052,2055,2064,2080,2082,2083,2086,2087,2160,2181,2222,2252,2306,2323,2332,2375,2376,2396,2404,2406,2427,2443,2455,2480,2525,2600,2628,2715,2869,2967,3000,3002,3005,3052,3075,3128,3280,3306,3310,3333,3372,3388,3389,3443,3478,3531,3689,3774,3790,3872,3940,4000,4022,4040,4045,4155,4300,4369,4433,4443,4444,4567,4660,4711,4848,4911,5000,5001,5007,5009,5038,5050,5051,5060,5061,5222,5269,5280,5357,5400,5427,5432,5443,5550,5555,5560,5570,5598,5601,5632,5800,5801,5802,5803,5820,5900,5901,5902,5984,5985,5986,6000,6060,6061,6080,6103,6112,6346,6379,6432,6443,6544,6600,6666,6667,6668,6669,6670,6679,6697,6699,6779,6780,6782,6969,7000,7001,7002,7007,7070,7077,7100,7144,7145,7180,7187,7199,7200,7210,7272,7402,7443,7479,7547,7776,7777,7780,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8025,8030,8042,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8098,8112,8118,8129,8138,8181,8182,8194,8333,8351,8443,8480,8500,8529,8554,8649,8765,8834,8880,8881,8882,8883,8884,8885,8886,8887,8888,8890,8899,8983,9000,9001,9002,9003,9030,9050,9051,9080,9083,9090,9091,9100,9151,9191,9200,9292,9300,9333,9334,9443,9527,9595,9600,9801,9864,9870,9876,9943,9944,9981,9997,9999,10000,10001,10005,10030,10035,10080,10243,10443,11000,11211,11371,11965,12000,12203,12345,12999,13013,13666,13720,13722,14000,14443,14534,15000,15001,15002,16000,16010,16922,16923,16992,16993,17988,18080,18086,18264,19150,19888,19999,20000,20547,23023,25000,25010,25020,25565,26214,26470,27015,27017,27960,28006,28017,29999,30444,31337,31416,32400,32750,32751,32752,32753,32754,32755,32756,32757,32758,32759,32760,32761,32762,32763,32764,32765,32766,32767,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,32786,32787,32788,32789,32790,32791,32792,32793,32794,32795,32796,32797,32798,32799,32800,32801,32802,32803,32804,32805,32806,32807,32808,32809,32810,34012,34567,34599,37215,37777,38978,40000,40001,40193,44443,44818,47808,49152,49153,50000,50030,50060,50070,50075,50090,50095,50100,50111,50200,52869,53413,55555,56667,60010,60030,60443,61616,64210,64738,4768]

def connect_port(ip, port):
    global open_port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            print '[+] ', port, 'open'
            open_port.append(port)
    except:
        pass

def scan_ip(ip,i):
    all_thread = []
    for p in range(i,i+scan_thread):
        if p==53:continue
        t = threading.Thread(target=connect_port, args=(ip, p))
        all_thread.append(t)
        t.start()
    for t in all_thread:
        t.join()

def ipaddrs(ip):
    ipaddl=ip.split('.')
    ipaddrs=[]
    for i in range(1,255):
        ipaddrs.append(ipaddl[0]+'.'+ipaddl[1]+'.'+ipaddl[2]+'.'+str(i))
    return ipaddrs


def up_host_scan(ipaddrs):
    try:
        ips_addr = str(ipaddrs)[2:-2].replace("', '"," ")
        nm = nmap.PortScanner()
        print "Scanning up host ."
        ping_scan_raw = nm.scan(hosts = ips_addr,arguments='-sn -PE')
        host_list_ip = []
        for result in ping_scan_raw['scan'].values():
            if result['status']['state'] == 'up':
                host_list_ip.append(result['addresses']['ipv4'])
        # return False
        return sorted(host_list_ip)
    except Exception,e:
        print "up_host_scan Error:",time.strftime('%Y-%m-%d', time.localtime(time.time())),e
        return False

def scan_domain_all_port(ip,scan_range):
    global open_port
    try:
        t1 = datetime.datetime.now()
        open_port = []
        print "scaning ip :", ip
        # for i in range(1, 65535, scan_thread):
        #     scan_ip(ip, i)
        
        all_thread = []
        for p in port:
            if p == 53: continue
            t = threading.Thread(target=connect_port, args=(ip, p))
            all_thread.append(t)
            t.start()
        for t in all_thread:
            t.join()

        port_items1 = set(list(open_port))
        port_items2 = []
        for x in port_items1:
            port_items2.append(x)
        port_items2.sort()
        open_port = port_items2

        target_port = str(open_port).replace(' ', '').replace('[', '').replace(']', '')
        print   ip, ':', target_port

        t2 = datetime.datetime.now()
        # print 'start_time', t1
        print '[ Scan ', ip, 'used', str((t2 - t1).seconds) + ' seconds ]'
        return target_port

    except:
        return ""


def scan_c_port(ip,scan_range,port_range):  # 扫描C段IP开放的端口，并返回C段开放的所有端口号（所有的累加后去重）
    try:
        global open_port
        if scan_range == 1:
            ipaddr = []
            ipaddr.append(ip)
        else:
            ipaddr = ipaddrs(ip)
            ip_up_addrs = up_host_scan(ipaddr)
            if ip_up_addrs:
                ipaddr = ip_up_addrs
        print "ipaddr length:",len(ipaddr)," ",ipaddr


        t1 = datetime.datetime.now()
        open_port = []

        for ip in ipaddr:

            if port_range == '1':   #port_range为1时扫描全端口
                print "scaning allport :", ip
                for i in range(1, 65535, scan_thread):
                # for i in port:
                    scan_ip(ip, i)
            else:
                print "scaning partport :", ip

                all_thread = []
                for p in port:
                    if p == 53: continue
                    t = threading.Thread(target=connect_port, args=(ip, p))
                    all_thread.append(t)
                    t.start()
                for t in all_thread:
                    t.join()

        port_items1 = set(list(open_port))
        port_items2 = []
        for x in port_items1:
            port_items2.append(x)
        port_items2.sort()
        open_port = port_items2
        target_port = str(open_port).replace(' ', '').replace('[', '').replace(']', '')
        print   ip, ':', target_port

        t2 = datetime.datetime.now()
        # print 'start_time', t1
        print '[ Scan ', ip, 'used', str((t2 - t1).seconds) + ' seconds ]'
        return target_port,ipaddr

    except:
        return "",""
def domain_nmap(xmlfile, nmapfile,domain,sub_domain):

    ip = url2ip('http://'+sub_domain)
    if ip:
        if ip in domain_ip:
            return ip + " is repeated with others in this file."
        else:
            domain_ip.append(ip)

            print "-------------nmap_start-------------"
            if debug_mod:
                nmap_cmd = "nmap -oX " + xmlfile + " " + sub_domain + " -Pn --open -sS  -sV  -O --script=banner  -p T:22,80,8080,3389,5000"
            else:
                traget_open_port = scan_domain_all_port(ip, 1)
                if traget_open_port:
                    nmap_cmd = "nmap -oX " + xmlfile + " " + sub_domain + " -Pn --open -sS  -sV  -O --script=banner   -p  " + traget_open_port
                else:
                    nmap_cmd = "nmap -oX " + xmlfile + " " + sub_domain + " -Pn --open -sS  -sV -T4 -O --script=banner --min-parallelism 100  --host-timeout 20m  -p T:1,11,13,15,17,19,21,22,23,25,26,30,31,32,33,34,35,36,37,38,39,43,53,69,70,79,80,81,82,83,84,85,88,98,100,102,110,111,113,119,123,135,137,139,143,161,179,199,214,264,280,322,389,407,443,444,445,449,465,497,500,502,505,510,514,515,517,518,523,540,548,554,587,591,616,620,623,626,628,631,636,666,731,771,782,783,789,873,888,898,900,901,902,989,990,992,993,994,995,1000,1001,1010,1022,1023,1026,1040,1041,1042,1043,1080,1091,1098,1099,1200,1212,1214,1220,1234,1241,1248,1302,1311,1314,1344,1400,1419,1432,1434,1443,1467,1471,1501,1503,1505,1521,1604,1610,1611,1666,1687,1688,1720,1723,1830,1900,1901,1911,1947,1962,1967,2000,2001,2002,2010,2024,2030,2048,2051,2052,2055,2064,2080,2082,2083,2086,2087,2160,2181,2222,2252,2306,2323,2332,2375,2376,2396,2404,2406,2427,2443,2455,2480,2525,2600,2628,2715,2869,2967,3000,3002,3005,3052,3075,3128,3280,3306,3310,3333,3372,3388,3389,3443,3478,3531,3689,3774,3790,3872,3940,4000,4022,4040,4045,4155,4300,4369,4433,4443,4444,4567,4660,4711,4848,4911,5000,5001,5007,5009,5038,5050,5051,5060,5061,5222,5269,5280,5357,5400,5427,5432,5443,5550,5555,5560,5570,5598,5601,5632,5800,5801,5802,5803,5820,5900,5901,5902,5984,5985,5986,6000,6060,6061,6080,6103,6112,6346,6379,6432,6443,6544,6600,6666,6667,6668,6669,6670,6679,6697,6699,6779,6780,6782,6969,7000,7001,7002,7007,7070,7077,7100,7144,7145,7180,7187,7199,7200,7210,7272,7402,7443,7479,7547,7776,7777,7780,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8025,8030,8042,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8098,8112,8118,8129,8138,8181,8182,8194,8333,8351,8443,8480,8500,8529,8554,8649,8765,8834,8880,8881,8882,8883,8884,8885,8886,8887,8888,8890,8899,8983,9000,9001,9002,9003,9030,9050,9051,9080,9083,9090,9091,9100,9151,9191,9200,9292,9300,9333,9334,9443,9527,9595,9600,9801,9864,9870,9876,9943,9944,9981,9997,9999,10000,10001,10005,10030,10035,10080,10243,10443,11000,11211,11371,11965,12000,12203,12345,12999,13013,13666,13720,13722,14000,14443,14534,15000,15001,15002,16000,16010,16922,16923,16992,16993,17988,18080,18086,18264,19150,19888,19999,20000,20547,23023,25000,25010,25020,25565,26214,26470,27015,27017,27960,28006,28017,29999,30444,31337,31416,32400,32750,32751,32752,32753,32754,32755,32756,32757,32758,32759,32760,32761,32762,32763,32764,32765,32766,32767,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,32786,32787,32788,32789,32790,32791,32792,32793,32794,32795,32796,32797,32798,32799,32800,32801,32802,32803,32804,32805,32806,32807,32808,32809,32810,34012,34567,34599,37215,37777,38978,40000,40001,40193,44443,44818,47808,49152,49153,50000,50030,50060,50070,50075,50090,50095,50100,50111,50200,52869,53413,55555,56667,60010,60030,60443,61616,64210,64738,4786"

            print nmap_cmd
            os.system(nmap_cmd)
            print "+++++++++++++nmap_ok+++++++++++++"

            checkend(xmlfile)
            nmap_info = parse_xml(xmlfile, nmapfile)
            # nmap_info = 'test'
            return nmap_info
    else:
        return ""


def c_nmap(xmlfile, nmapfile,domain,ip_c):

    print "-------------c_nmap_start-------------"
    if debug_mod:
        nmap_cmd = "nmap -oX " + xmlfile + " " + ip_c + " -Pn --open -sS  -sV -T4 -O --script=banner  -p T:22,80,8080,3389"
    else:
        if c_all_port:
            traget_open_port,ipaddr = scan_c_port(ip_c, 2, '1')
            if ipaddr:
                ip_c = str(ipaddr)[2:-2].replace("', '"," ")
            if traget_open_port:
                nmap_cmd = "nmap -oX " + xmlfile + " " + ip_c + " -Pn --open -sS -sV  -O --script=banner --min-hostgroup 256 --min-parallelism 100  -p "+traget_open_port
            else:
                nmap_cmd = "nmap -oX " + xmlfile + " " + ip_c + " -Pn --open -sS -sV  -O --script=banner  --min-hostgroup 256 --min-parallelism 100  -p T:1-65535"
        else:
            traget_open_port,ipaddr = scan_c_port(ip_c, 2, '0')
            if ipaddr:
                ip_c = str(ipaddr)[2:-2].replace("', '"," ")
            if traget_open_port:
                nmap_cmd = "nmap -oX " + xmlfile + " " + ip_c + " -Pn --open -sS -sV  -O --script=banner   -p "+traget_open_port
            else:
                nmap_cmd = "nmap -oX " + xmlfile + " " + ip_c + " -Pn --open -sS -sV  -O --script=banner   -p T:1,11,13,15,17,19,21,22,23,25,26,30,31,32,33,34,35,36,37,38,39,43,53,69,70,79,80,81,82,83,84,85,88,98,100,102,110,111,113,119,123,135,137,139,143,161,179,199,214,264,280,322,389,407,443,444,445,449,465,497,500,502,505,510,514,515,517,518,523,540,548,554,587,591,616,620,623,626,628,631,636,666,731,771,782,783,789,873,888,898,900,901,902,989,990,992,993,994,995,1000,1001,1010,1022,1023,1026,1040,1041,1042,1043,1080,1091,1098,1099,1200,1212,1214,1220,1234,1241,1248,1302,1311,1314,1344,1400,1419,1432,1434,1443,1467,1471,1501,1503,1505,1521,1604,1610,1611,1666,1687,1688,1720,1723,1830,1900,1901,1911,1947,1962,1967,2000,2001,2002,2010,2024,2030,2048,2051,2052,2055,2064,2080,2082,2083,2086,2087,2160,2181,2222,2252,2306,2323,2332,2375,2376,2396,2404,2406,2427,2443,2455,2480,2525,2600,2628,2715,2869,2967,3000,3002,3005,3052,3075,3128,3280,3306,3310,3333,3372,3388,3389,3443,3478,3531,3689,3774,3790,3872,3940,4000,4022,4040,4045,4155,4300,4369,4433,4443,4444,4567,4660,4711,4848,4911,5000,5001,5007,5009,5038,5050,5051,5060,5061,5222,5269,5280,5357,5400,5427,5432,5443,5550,5555,5560,5570,5598,5601,5632,5800,5801,5802,5803,5820,5900,5901,5902,5984,5985,5986,6000,6060,6061,6080,6103,6112,6346,6379,6432,6443,6544,6600,6666,6667,6668,6669,6670,6679,6697,6699,6779,6780,6782,6969,7000,7001,7002,7007,7070,7077,7100,7144,7145,7180,7187,7199,7200,7210,7272,7402,7443,7479,7547,7776,7777,7780,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8025,8030,8042,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8098,8112,8118,8129,8138,8181,8182,8194,8333,8351,8443,8480,8500,8529,8554,8649,8765,8834,8880,8881,8882,8883,8884,8885,8886,8887,8888,8890,8899,8983,9000,9001,9002,9003,9030,9050,9051,9080,9083,9090,9091,9100,9151,9191,9200,9292,9300,9333,9334,9443,9527,9595,9600,9801,9864,9870,9876,9943,9944,9981,9997,9999,10000,10001,10005,10030,10035,10080,10243,10443,11000,11211,11371,11965,12000,12203,12345,12999,13013,13666,13720,13722,14000,14443,14534,15000,15001,15002,16000,16010,16922,16923,16992,16993,17988,18080,18086,18264,19150,19888,19999,20000,20547,23023,25000,25010,25020,25565,26214,26470,27015,27017,27960,28006,28017,29999,30444,31337,31416,32400,32750,32751,32752,32753,32754,32755,32756,32757,32758,32759,32760,32761,32762,32763,32764,32765,32766,32767,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,32786,32787,32788,32789,32790,32791,32792,32793,32794,32795,32796,32797,32798,32799,32800,32801,32802,32803,32804,32805,32806,32807,32808,32809,32810,34012,34567,34599,37215,37777,38978,40000,40001,40193,44443,44818,47808,49152,49153,50000,50030,50060,50070,50075,50090,50095,50100,50111,50200,52869,53413,55555,56667,60010,60030,60443,61616,64210,64738,4786"
    print nmap_cmd
    os.system(nmap_cmd)
    print "+++++++++++++c_nmap_ok+++++++++++++"

    checkend(xmlfile)
    parse_xml(xmlfile, open(nmapfile,'w+'))
    nmap_info = open(nmapfile,'r').read()
    # nmap_info ='test'
    return nmap_info

def get_domain_info(domain,sub_domain):
    try:
        nmap_info = ''
        dir_text = ''
        sub_domain_info =''
        if ":" in sub_domain:
            target = sub_domain
            sub_domain = sub_domain.split(':')[0]
        else:
            target = sub_domain

        open(logpath + 'sub/' + sub_domain + '-waf.txt', 'w').close()
        open(logpath + 'sub/' + sub_domain + '-whatweb.txt', 'w').close()
        open(logpath + 'sub/' + sub_domain + '-dirsearch.txt', 'w').close()
        xmlfile = logpath + 'sub/' + sub_domain + '-nmap.xml'
        open(xmlfile, 'w').close()
        nmapfile = open(logpath + 'sub/' + sub_domain + '-nmap.txt', 'w')
        nmap_info = domain_nmap(xmlfile, nmapfile, domain, sub_domain)
        whatweb_info = get_whatweb(domain, target, logpath + 'sub/' + sub_domain + '-whatweb.txt')
        waf = get_waf(domain, sub_domain)

        if len(whatweb_info) > 5:
            if  debug_mod:
                print "Debug_mode:spider with :", sub_domain
                time.sleep(10)
            else:
                get_spider(domain, sub_domain, crawl_deepth)
            headers = requests_headers()
            try:
                requests.get(url='http://' + sub_domain, headers=headers, timeout=10, verify=False)
                if enumdir:
                    dir_text = get_dirs(domain, sub_domain)
            except:
                print sub_domain, " target unable to open"
            sub_domain_info = "http://" + sub_domain + whatweb_info + waf
        else:
            sub_domain_info = "http://" + sub_domain + '|' + "host_down"

        lock.acquire()
        sub_doamin_log = open(logpath + domain + '-sub_info.txt', 'a+')
        if enumdir:
            sub_doamin_log.write("#" * 30 + ' ' + sub_domain + ' ' + "#" * 30 + '\n' * 2 + sub_domain_info + '\n' + nmap_info +'\n'*2 + '-' * 20 +'DirSearch_bg: '+  sub_domain + '-' * 20 + '\n' + dir_text + '\n' + '-' * 20 + 'DirSearch_ok: '+  sub_domain + '-' * 20 + '\n'*3)
        else:
            sub_doamin_log.write("#" * 30 + ' ' + sub_domain + ' ' + "#" * 30 + '\n' * 2 + sub_domain_info + '\n' + nmap_info +'\n'*2)

        sub_doamin_log.close()
        lock.release()
        print sub_domain_info
    except Exception,e:
        print "get_domain_info error :",e



def get_c_info(domain,c_ip):
    nmap_info=''
    dir_text = ''

    xmlfile = logpath + 'c_ip/'+c_ip+'-nmap.xml'
    open(xmlfile,'w').close()
    nmapfile = logpath + 'c_ip/'+c_ip+'-nmap.txt'
    open(nmapfile, 'w').close()
    nmap_info = c_nmap(xmlfile,nmapfile,domain,c_ip+'/24')
    print  nmap_info
    open(logpath + domain + '-c_ip_info.txt', 'a+').write("#" * 30 + ' '+ c_ip+'/24'+ ' '+"#" * 30+'\n'*2+nmap_info + '\n'*2)


def get_domain(target):
    try:
        url = target
        if url[0:4] == 'http':
            proto, rest = urllib.splittype(url)
            host, rest = urllib.splithost(rest)
            if host[0:3] == 'www':
                host = host[4:]
        elif url[0:3] == 'www':
            host = url[4:]
        else:
            host = url
        if ':' in host:
            host = host.split(':')[0]
        if '/' in host:
            host = host.split('/')[0]

        return host
    except:
        return target


def url_protocol(url):
    domain = re.findall(r'.*(?=://)', url)
    if domain:
        return domain[0]
    else:
        return url

def same_url(urlprotocol,url):
    url = url.replace(urlprotocol + '://', '')
    if re.findall(r'^www', url) == []:
        sameurl = 'www.' + url
        if sameurl.find('/') != -1:
            sameurl = re.findall(r'(?<=www.).*?(?=/)', sameurl)[0]
        else:
            sameurl = sameurl + '/'
            sameurl = re.findall(r'(?<=www.).*?(?=/)', sameurl)[0]
    else:
        if url.find('/') != -1:
            sameurl = 'www.' + re.findall(r'(?<=www.).*?(?=/)', url)[0]
        else:
            sameurl = url + '/'
            sameurl = 'www.' + re.findall(r'(?<=www.).*?(?=/)', sameurl)[0]
    print('the domain is：' + sameurl)
    return sameurl

def requests_headers():
    '''
    Random UA  for every requests && Use cookie to scan
    '''
    user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
    'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
    'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60','Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']
    UA = random.choice(user_agent)
    headers = {
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'User-Agent':UA,'Upgrade-Insecure-Requests':'1','Connection':'keep-alive','Cache-Control':'max-age=0',
    'Accept-Encoding':'gzip, deflate, sdch','Accept-Language':'zh-CN,zh;q=0.8',
    "Referer": "http://www.baidu.com/link?url=www.so.com&url=www.soso.com&&url=www.sogou.com"}
    return headers


class linkQuence:
    def __init__(self):
        self.visited = []    #已访问过的url初始化列表
        self.unvisited = []  #未访问过的url初始化列表
        self.external_url=[] #外部链接

    def getVisitedUrl(self):  #获取已访问过的url
        return self.visited
    def getUnvisitedUrl(self):  #获取未访问过的url
        return self.unvisited
    def getExternal_link(self):
        return self.external_url   #获取外部链接地址
    def addVisitedUrl(self,url):  #添加已访问过的url
        return self.visited.append(url)
    def addUnvisitedUrl(self,url):   #添加未访问过的url
        if url != '' and url not in self.visited and url not in self.unvisited:
            return self.unvisited.insert(0,url)
    def addExternalUrl(self,url):   #添加外部链接列表
        if url!='' and url not in self.external_url:
            return self.external_url.insert(0,url)

    def removeVisited(self,url):
        return self.visited.remove(url)
    def popUnvisitedUrl(self):    #从未访问过的url中取出一个url
        try:                      #pop动作会报错终止操作，所以需要使用try进行异常处理
            return self.unvisited.pop()
        except:
            return None
    def unvisitedUrlEmpty(self):   #判断未访问过列表是不是为空
        return len(self.unvisited) == 0

class Spider():
    '''
    真正的爬取程序
    '''
    def __init__(self,url,domain_url,urlprotocol):
        self.linkQuence = linkQuence()   #引入linkQuence类
        self.linkQuence.addUnvisitedUrl(url)   #并将需要爬取的url添加进linkQuence对列中
        self.current_deepth = 1    #设置爬取的深度
        self.domain_url = domain_url
        self.urlprotocol = urlprotocol

    def getPageLinks(self,url):
        '''
            获取页面中的所有链接
        '''
        try:
            headers = requests_headers()
            content = requests.get(url, timeout=5, headers=headers, verify=False).text.encode('utf-8')
            links = []
            tags = ['a', 'A', 'link', 'script', 'area', 'iframe', 'form']  # img
            tos = ['href', 'src', 'action']
            if url[-1:] == '/':
                url = url[:-1]
            try:
                for tag in tags:
                    for to in tos:
                        link1 = re.findall(r'<%s.*?%s="(.*?)"' % (tag, to), str(content))
                        link2 = re.findall(r'<%s.*?%s=\'(.*?)\'' % (tag, to), str(content))
                        for i in link1:
                            links.append(i)
                            # if i not in links and '.png' not in i and 'javascript' not in i and '.svg' not in i and '.jpg' not in i and '.js' not in i and '.css' not in i and '/css?' not in i and '.gif' not in i and '.jpeg' not in i and '.ico' not in i and '.swf' not in i and '.mpg' not in i and '.pdf' not in i and 'mailto:' not in i and 'data:image' not in i and i != '':
                            #     if '://' in i or '//' in i:
                            #         i = i.replace(' ', '')
                            #         links.append(i)
                            #     else:
                            #         links.append(url + '/' + i)
                        for i in link2:
                            if i not in links:
                                links.append(i)
                            # if i not in links and '.png' not in i and 'javascript' not in i and '.svg' not in i and '.jpg' not in i and '.js' not in i and '.css' not in i and '/css?' not in i and '.gif' not in i and '.jpeg' not in i and '.ico' not in i and '.swf' not in i and '.mpg' not in i and '.pdf' not in i and 'mailto:' not in i and 'data:image' not in i and i != '':
                            #     if '://' in i or '//' in i:
                            #         i = i.replace(' ', '')
                            #         links.append(i)
                            #     else:
                            #         links.append(url + '/' + i)
            except Exception, e:
                print e
                print '[!] Get link error'
                pass
            return links
        except:
            return []
    def getPageLinks_bak(self,url):
        '''
        获取页面中的所有链接
        '''
        try:

            # pageSource=urllib2.urlopen(url).read()
            headers = requests_headers()
            time.sleep(0.5)
            pageSource = requests.get(url, timeout=5, headers=headers).text.encode('utf-8')
            pageLinks = re.findall(r'(?<=href=\").*?(?=\")|(?<=href=\').*?(?=\')', pageSource)
            # print pageLinks
        except:
            # print ('open url error')
            return []
        return pageLinks

    def processUrl(self,url):
        '''
        判断正确的链接及处理相对路径为正确的完整url
        :return:
        '''
        true_url = []
        in_link = []
        excludeext = ['.zip', '.rar', '.pdf', '.doc', '.xls', '.jpg', '.mp3', '.mp4','.png', '.ico', '.gif','.svg', '.jpeg','.mpg', '.wmv', '.wma','mailto','javascript','data:image']
        for suburl in self.getPageLinks(url):
            exit_flag = 0
            for ext in excludeext:
                if ext in suburl:
                    print "break:" + suburl
                    exit_flag = 1
                    break
            if exit_flag == 0:
                if re.findall(r'/', suburl):
                    if re.findall(r':', suburl):
                        true_url.append(suburl)
                    else:
                        true_url.append(self.urlprotocol + '://' + self.domain_url + '/' + suburl)
                else:
                    true_url.append(self.urlprotocol + '://' + self.domain_url + '/' + suburl)

        for suburl in true_url:
            print('from:' + url + ' get suburl：' + suburl)

        return true_url

    def sameTargetUrl(self,url):
        same_target_url = []
        for suburl in self.processUrl(url):
            if re.findall(self.domain_url,suburl):
                same_target_url.append(suburl)
            else:
                self.linkQuence.addExternalUrl(suburl)
        return same_target_url

    def unrepectUrl(self,url):
        '''
        删除重复url
        '''
        unrepect_url = []
        for suburl in self.sameTargetUrl(url):
            if suburl not in unrepect_url:
                unrepect_url.append(suburl)
        return unrepect_url

    def crawler(self,crawl_deepth=1):
        '''
        正式的爬取，并依据深度进行爬取层级控制
        '''
        self.current_deepth=0
        print "current_deepth:", self.current_deepth
        while self.current_deepth < crawl_deepth:
            if self.linkQuence.unvisitedUrlEmpty():break
            links=[]
            while not self.linkQuence.unvisitedUrlEmpty():
                visitedUrl = self.linkQuence.popUnvisitedUrl()
                if visitedUrl is None or visitedUrl == '':
                    continue
                print("#"*30 + visitedUrl +" :begin"+"#"*30)
                for sublurl in self.unrepectUrl(visitedUrl):
                    links.append(sublurl)
                # links = self.unrepectUrl(visitedUrl)
                self.linkQuence.addVisitedUrl(visitedUrl)
                print("#"*30 + visitedUrl +" :end"+"#"*30 +'\n')
            for link in links:
                self.linkQuence.addUnvisitedUrl(link)
            self.current_deepth += 1
        # print(self.linkQuence.visited)
        # print (self.linkQuence.unvisited)
        urllist=[]
        urllist.append("#" * 30 + ' VisitedUrl ' + "#" * 30)
        for suburl in self.linkQuence.getVisitedUrl():
            urllist.append(suburl)
        urllist.append("#" * 30 + ' UnVisitedUrl ' + "#" * 30)
        for suburl in self.linkQuence.getUnvisitedUrl():
            urllist.append(suburl)
        urllist.append("#" * 30 + ' External_link ' + "#" * 30)
        for sublurl in self.linkQuence.getExternal_link():
            urllist.append(sublurl)
        urllist.append("#" * 30 + ' Active_link ' + "#" * 30)
        actives = ['?', '.asp', '.jsp', '.php', '.aspx']
        struts_exts = ['.do', '.action']
        active_urls = []
        for sublurl in urllist:
            for struts_ext in struts_exts:
                if struts_ext in sublurl:
                    vulnerable.write(sublurl+'\n')
                    active_urls.append(sublurl)
            for active in actives:
                if active in sublurl:
                    active_urls.append(sublurl)
                    break
        for active_url in active_urls:
            urllist.append(active_url)
        return urllist
def writelog(log,urllist):
    filename=log
    outfile=open(filename,'w')
    for suburl in urllist:
        outfile.write(suburl+'\n')
    outfile.close()

def SRC_spider(url, log,crawl_deepth=3):
    # url = 'http://2014.liaocheng.gov.cn'

    urlprotocol = url_protocol(url)
    domain_url = same_url(urlprotocol, url)
    print "domain_url:" + domain_url
    spider = Spider(url,domain_url,urlprotocol)
    urllist = spider.crawler(crawl_deepth)
    writelog(log, urllist)
    print '-' * 20 + url + '-' * 20
    # for sublurl in urllist:
    #     print sublurl
    print '\n' + 'Result record in:' + log


def set_dirs(domain):

    try:
        global pwd, path, logpath, domain_ip, vulnerable
        path = pwd + '/libs/'
        logpath = pwd + '/log/' + domain + '/'
        if not os.path.exists(logpath):
            os.makedirs(logpath, 0755)
        if not os.path.exists(pwd + '/log/loginfo/'):
            os.makedirs(pwd + '/log/loginfo/', 0755)
        if not os.path.exists(logpath + 'sub/'):
            os.makedirs(logpath + 'sub/', 0755)
        if not os.path.exists(logpath + 'c_ip/'):
            os.makedirs(logpath + 'c_ip/', 0755)
        if not os.path.exists(logpath + 'temp/'):
            os.makedirs(logpath + 'temp/', 0755)
        if not os.path.exists(logpath + 'spider/'):
            os.makedirs(logpath + 'spider/', 0755)
        if not os.path.exists(logpath + 'domain/'):
            os.makedirs(logpath + 'domain/', 0755)

        open(logpath + domain + '-c_ip_info.txt', 'w').close()
        open(logpath + domain + '-c_ip.txt', 'w').close()
        open(logpath + domain + '-c_ip.txt', 'w').close()
        open(logpath + domain + '-domain.txt', 'w').close()
        open(logpath + domain + '-sub_info.txt', 'w').close()
        open(logpath + domain + '-vulnerable.txt', 'w').close()
        open(logpath + 'domain/' + domain + '-baidudomain.txt', 'w').close()
        open(logpath + 'domain/' + domain + '-wydomain.txt', 'w').close()
        open(logpath + 'domain/' + domain + '-subdomain.txt', 'w').close()
        vulnerable = open(logpath + domain + '-vulnerable.txt', 'a+')

    except Exception,e:
        print "[!] Set Dirs Error ",e
        pass


if __name__ == '__main__':
    start = datetime.datetime.now()
    usage = '''
        python FuzzScanner.py -hc target.com         -->  domain && web finger && Dir scan && C scan
        python FuzzScanner.py -Hc vuln_domains.txt   -->  domain && web finger && Dir scan && C scan
        python FuzzScanner.py -hca target.com        -->  domain && web finger && Dir scan && C scan && C allport
        python FuzzScanner.py -Hca vuln_domains.txt  -->  domain && web finger && Dir scan && C scan && C allport
        python FuzzScanner.py -h  target.com         -->  domain && web finger && Dir scan
        python FuzzScanner.py -H  vuln_domains.txt   -->  domain && web finger && Dir scan
        python FuzzScanner.py -c  192.168.1.1        -->  C scan
        python FuzzScanner.py -cd 192.168.1.1        -->  C scan  && Dir scan
        python FuzzScanner.py -C  vuln_ip.txt        -->  C scan
        python FuzzScanner.py -Cd vuln_ip.txt        -->  C scan  && Dir scan
        python FuzzScanner.py -ca 192.168.1.1        -->  C scan  && C allport
        python FuzzScanner.py -Ca vuln_ip.txt        -->  C scan  && C allport
        '''
    targets = []
    c_targets=[]
    domain_ip = []
    pwd = os.getcwd()
    enumdir = 0
    c_scan = 1
    scan_thread = 3000  #socket扫描线程
    c_all_port = 0
    if len(sys.argv) != 3:
        print usage
        exit(0)
    elif sys.argv[1] == '-hc':
        targets.append(sys.argv[2])
        c_scan = 1
        enumdir = 1
    elif sys.argv[1] == '-Hc':
        if os.path.exists(sys.argv[2]):
            for url in open(sys.argv[2],'r').readlines():
                url = url.strip()
                if url:
                    targets.append(url)
            c_scan = 1
            enumdir = 1
        else:
            print sys.argv[2]," file is not exist."
            exit(0)
    elif sys.argv[1] == '-hca':
        targets.append(sys.argv[2])
        c_scan = 1
        enumdir = 1
        c_all_port =1
    elif sys.argv[1] == '-Hca':
        if os.path.exists(sys.argv[2]):
            for url in open(sys.argv[2],'r').readlines():
                url = url.strip()
                if url:
                    targets.append(url)
            c_scan = 1
            enumdir = 1
            c_all_port = 1
        else:
            print sys.argv[2]," file is not exist."
            exit(0)
    elif sys.argv[1] == '-h':
        targets.append(sys.argv[2].strip())
        c_scan = 0
        enumdir = 1
    elif sys.argv[1] == '-H':
        if os.path.exists(sys.argv[2]):
            for url in open(sys.argv[2], 'r').readlines():
                url = url.strip()
                if url:
                    targets.append(url.strip())
            enumdir = 1
            c_scan = 0
        else:
            print sys.argv[2]," file is not exist."
            exit(0)

    elif sys.argv[1] == '-c':
        c_targets.append(sys.argv[2])
        enumdir = 0
    elif sys.argv[1] == '-ca':
        c_targets.append(sys.argv[2])
        enumdir = 0
        c_all_port =1
    elif sys.argv[1] == '-cd':
        c_targets.append(sys.argv[2])
        enumdir = 1
    elif sys.argv[1] == '-C':
        if os.path.exists(sys.argv[2]):
            for url in open(sys.argv[2], 'r').readlines():
                url = url.strip()
                if url:
                    c_targets.append(url)
            enumdir = 0
        else:
            print sys.argv[2]," file is not exist."
            exit(0)
    elif sys.argv[1] == '-Ca':
        if os.path.exists(sys.argv[2]):
            for url in open(sys.argv[2], 'r').readlines():
                url = url.strip()
                if url:
                    c_targets.append(url)
            enumdir = 0
            c_all_port = 1
        else:
            print sys.argv[2]," file is not exist."
            exit(0)
    elif sys.argv[1] == '-Cd':
        if os.path.exists(sys.argv[2]):
            for url in open(sys.argv[2], 'r').readlines():
                url = url.strip()
                if url:
                    c_targets.append(url.strip())
            enumdir = 1
        else:
            print sys.argv[2]," file is not exist."
            exit(0)
    else:
        print usage
        exit(0)

    #enumdir = 0  # 全局设定，不再进行dirsearch

    try:
        if len(targets) > 0:

            for target in targets:
                target = target.strip()
                sub_doamins = []
                domain_ip = []
                domain = get_domain(target)

                set_dirs(domain)
                logpath = pwd + '/log/' + domain + '/'

                if ip_regex(domain):  # 如果是IP
                    if ':' in target:
                        sub_doamins.append(domain + ':' + target.split(':')[-1].split('/')[0])
                else:
                    sub_doamins = task_subdomain(domain)
                    if len(sub_doamins) > 200:  # 域名数量大于100说明可能是泛解析
                        sub_doamins = []
                        sub_doamins.append(target)
                    else:
                        sub_doamins.append(target)
                        for x in open(logpath + domain + '-domain.txt', 'r').readlines():
                            x = x.strip()
                            if x != target:
                                sub_doamins.append(x)
                        sub_doamins_qc = set(list(sub_doamins))
                        sub_doamins = []
                        for x in sub_doamins_qc:
                            x = x.strip()
                            if x:
                                sub_doamins.append(x)

                domain_thread = []
                print "sub_doamins:"
                print sub_doamins
                time.sleep(5)
                for sub_doamin in sub_doamins:
                    sub_doamin = sub_doamin.strip()
                    if sub_doamin:
                        print '\n' * 2 + "Start Scan Sub_doamin:", sub_doamin, '\n'
                        t_domain = threading.Thread(target=get_domain_info, args=(domain, sub_doamin))
                        domain_thread.append(t_domain)
                        t_domain.start()
                for t_domain in domain_thread:
                    t_domain.join()

                # c_scan=0
                if c_scan:
                    enumdir = 0
                    domain_c_ip_qc = set(list(domain_ip))
                    domain_c_ip = []
                    for x in domain_c_ip_qc:
                        x.strip()
                        if x:
                            domain_c_ip.append(x)
                            open(logpath + domain + '-c_ip.txt', 'a+').write(x + '\n')
                    print '*' * 50, 'scan c', '*' * 50

                    c_thread = []
                    c_ips_qc =[]
                    for ip in domain_c_ip:
                        # print ip
                        ip = ip.strip()
                        if ip:
                            ip_split = ip.split('.')
                            c_ip = "%s.%s.%s.1" % (ip_split[0], ip_split[1], ip_split[2])
                            if c_ip not in c_ips_qc:
                                c_ips_qc.append(c_ip)

                    for c_ip_qc in c_ips_qc:
                        t_c = threading.Thread(target=get_c_info, args=(domain, c_ip_qc))
                        c_thread.append(t_c)
                        t_c.start()

                    for t_c in c_thread:
                        t_c.join()

        if len(c_targets) > 0:
            c_ip_qc = set(list(c_targets))
            c_ips = []
            domain = c_targets[0].strip().replace('/', '_')
            set_dirs(domain)
            logpath = pwd + '/log/' + domain + '/'
            # print c_ip_qc
            for x in c_ip_qc:
                x = x.strip()
                if x:
                    c_ips.append(x)
                    open(logpath + domain + '-c_ip.txt', 'a+').write(x + '\n')

            c_thread = []
            c_ips_qc = []
            for ip in c_ips:
                print ip
                ip = ip.strip()
                if ip:
                    ip_split = ip.split('.')
                    c_ip = "%s.%s.%s.1" % (ip_split[0], ip_split[1], ip_split[2])
                    if c_ip not in c_ips_qc:
                        c_ips_qc.append(c_ip)
            for c_ip_qc in c_ips_qc:
                t_c = threading.Thread(target=get_c_info, args=(domain, c_ip))
                c_thread.append(t_c)
                t_c.start()
            for t_c in c_thread:
                t_c.join()

        vulnerable.close()
        os.system('chmod -R 777 ' + pwd)
        end = datetime.datetime.now()

        print "starttime:", start
        print "endtime:", end
        print "time_use:", (end - start).seconds / 60, " 分钟"
    except Exception,e:
        logfile = time.strftime('%Y-%m-%d', time.localtime(time.time()))
        now = time.strftime('%Y-%m-%d_%X', time.localtime(time.time()))
        info = '%s\n\nMain Function error: %s' % (now, e)
        print info
        open('./log/loginfo/' + logfile + '.txt', 'a+').write(info + '\n')
