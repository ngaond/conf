from elasticsearch import Elasticsearch
import re
import sys
import time

badip_list = []
badip_list_bp = []
# 悪意フラグあるのip、かつ悪意リクエストのみ
badip_listp = []
# 悪意フラグあるのip、かつ悪意リクエストのみ
ip_list = []
output_list = []
count = 0
ipcount = 0
ip_string = "''"
es = Elasticsearch("http://172.23.32.103:9200")
flag1 = 0
flag2 = 0


class Requests(object):
    def __init__(self):
        self.source_ip = ''
        self.destination_ip = []
        self.destination_port = []
        self.requestq = "''"
        self.requests = []


def get_badip():
    list1 = []
    # 悪意フラグリクエスト抽出
    query = {'query':
        {'bool':
            {'must': [
                {'term': {'@timestamp': '2021-01-17'}},
                {'bool': {'should': [
                    {'regexp': {'request': 'wget.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'curl.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'fetch.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'java.net.URL.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'urlopen.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'bitsadmin.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'explorer.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'certutil.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'Wscript.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'getstore.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'HTTP.start.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'lwp-download.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'objXMLHTTP.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                    {'regexp': {'request': 'mshta.+https?://[\w/:\.\-]+', 'case_insensitive': true}}
                ]}}]}}}
    result = es.search(index="xpot_accesslog-2021.01", body=query, size=100000)
    for log in result["hits"]["hits"]["_source"]:
        ip_string = ip_string + ", '" + log["source_ip"] + "'"
        list1.append(log["source_ip"])
    badip_list = list(set(list1))
    badip_list_bp = badip_list
    list1 = []
    for badip in badip_list:
        query = {'query': {'bool': {'must': [{'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': badip}}],
                                    'must_not': [
                                        {'regexp': {'request': 'wget.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                                        {'regexp': {'request': 'curl.+https?://[\w/:\.\-]+', 'case_insensitive': true}},
                                        {'regexp': {'request': 'fetch.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'java.net.URL.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'urlopen.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'bitsadmin.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'explorer.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'certutil.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'Wscript.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'getstore.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'HTTP.start.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'lwp-download.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'objXMLHTTP.+https?://[\w/:\.\-]+',
                                                    'case_insensitive': true}},
                                        {'regexp': {'request': 'mshta.+https?://[\w/:\.\-]+', 'case_insensitive': true}}
                                    ]}}}
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        list1.append(result["hits"]["hits"]["_source"]["source_ip"])
        badip_list.remove(result["hits"]["hits"]["_source"]["source_ip"])


def get_path(a, ip):
    # パス種類判断
    while result != NULL:
        query = {
            'query':
                {'bool': {
                    'must': [
                        {'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': ip}}
                    ],
                    'must_not': [
                        {'terms': {'request': [a.requestq]}},
                        {'terms': {'request': ['HEAD / HTTP/1.0', 'HEAD / HTTP/1.1', 'POST / HTTP/1.0',
                                               'POST / HTTP/1.1', 'GET / HTTP/1.0', 'GET / HTTP/1.1', '/favicon.ico',
                                               '/.env', '/Nmap', 'OPTIONS / HTTP/1.0', 'OPTIONS / HTTP/1.1',
                                               'GET /version HTTP/1.1'
                                               ]}
                         }
                    ]
                }
                }
        }
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        if (result["hits"]["hits"]["_source"]["request"]) != null:
            print(result["hits"]["hits"]["_source"]["request"])
            print("パスやパラメータなどリクエストの特徴を入力ください")
            kaka = input()
            requestq = requestq + ",'" + kaka + "'"
            a.requests.append(kaka)
            print("同じ脆弱性複数の場合、ここで0を入力してください,違うの場合は1")
            j = input()
            if j == 1:
                a.rlist.append(kaka)
                a.destination_port.append(result["hits"]["hits"]["_source"]["destination_port"])
                a.destination_ip.append(result["hits"]["hits"]["_source"]["destination_ip"])
                a.source_ip = badip
                count = count + 1
                badip_list.remove(a.source_ip)
    return a


def get_deport(n, list1, list2, kip):
    deport = []
    portde = []
    ip_list_bk = ip_list
    for index in range(len(ip_list_bk)):
        sip = ip_list_bk[index].source_ip
        query = {
            'query':
                {'bool':
                    {'must': [
                        {'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': sip}}
                    ]
                    }
                }
        }
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=10000)
        for log in result["hits"]["hits"]["_source"]:
            deport.append(result["hits"]["hits"]["_source"]["destination_port"])
        deport = set(deport)
        if len(deport) != 1:
            output_list.append(ip_list_bk[index])
            del ip_list_bk[index]
            index = index - 1
        else:
            ipde.append(deip[0])
    if n == 0:  # 目標ハニーポット数に特徴なし
        print(ipde)
        print("複数ソースから同じポートを狙う特徴があるのか？")
        kport = input()
        if kport == null:
            get_deport("0")
            for index in range(len(ip_list)):
                print(ip_list[index])  # !!!!!!!!!
        else:
            for index in range(len(ip_list_bk)):
                if ip_list_bk[index].destination_port != kport:
                    output_list.append(ip_list_bk[index])
            print(output_list)  # !!!!!!!!!!!!!!
            print(ip_list_bk[index])
    else:  # 目標ハニーポット数に特徴あり
        for index in range(len(ip_list_bk)):
            print(ip_list_bk[index].destination_ip, ip_list_bk[index].destination_port)
        print("複数ソースから同じポートを狙う特徴があるのか？目標ハニーポット数を配慮し特徴ポート入力してください")
        kport = input()
        if kport == null:
            print(list1)  # !!!!!!!!!
            print(list2)
        else:
            output_list = []
            for index in range(len(ip_list)):
                if ip_list[index].destination_ip == kip & ip_list[index].destination_port == kport:
                    print(ip_list[index])
                else:
                    output_list.append(ip_list[index])
            print(output_list)


def get_deip():
    ipde = []
    ip_list_bk = ip_list
    i = 0
    for index in range(len(ip_list_bk)):
        sip = ip_list_bk[index].source_ip
        query = {
            'query':
                {'bool':
                    {'must': [
                        {'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': sip}}
                    ]
                    }
                }
        }
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=10000)
        deip = []
        for log in result["hits"]["hits"]["_source"]:
            deip.append(log["destination_ip"])
        deip = set(deip)
        if len(deip) != 1:
            output_list.append(ip_list_bk[index])
            del ip_list_bk[index]
            index = index - 1
        else:
            ipde.append(deip[0])
    print(ipde)
    print("複数ソースから同じハニーポットを狙う特徴があるのか？一番多いのハニーポットIpを入力してください")
    kip = input()
    if kip == null:
        get_deport("0", ip_list_bk, output_list, kip)
    else:
        for index in range(len(ip_list_bk)):
            if ip_list_bk[index].destination_ip != kip:
                output_list.append(ip_list_bk[index])
        get_deport("1", ip_list_bk, output_list, kip)


def group_analysis1(a, group):
    # パス一種類のみ
    if group == "bad":
        for badip in badip_list:
            query = {'query': {
                'bool': {'must': [{'term': {'@timestamp': '2021-01-17'}}, {'match_phrase': {'request': a.requests[0]}},
                                  {'term': {'source_ip': badip}}
                                  ]
                         }
            }}
            result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
            b = Requests()
            b = get_path(b, result["hits"]["hits"]["_source"]["source_ip"])
            if count == 1:
                ip_list.append(b)
                ipcount = ipcount + 1
        get_deip()
        for index in range(len(ip_list)):
            badip_list.remove(ip_list[index].source_ip)
    if group == "not bad":
        query = {
            'query':
                {'bool':
                    {'must': [
                        {'term': {'@timestamp': '2021-01-17'}},
                        {'match_phrase': {'request': a.requests[0]}}],
                        'must_not': [
                            {'terms': {
                                "source_ip": ['185.163.109.66 ', '198.20.69.74 ', '198.20.69.98 ', '198.20.87.98 ',
                                              '198.20.99.130 ', '198.20.70.114 ', '66.240.192.138 ',
                                              '66.240.205.34 ',
                                              '66.240.219.146 ', '66.240.236.119 ', '71.6.135.131 ',
                                              '71.6.146.185 ',
                                              '71.6.146.186 ', '71.6.158.166 ', '71.6.165.200 ', '71.6.167.142 ',
                                              '80.82.77.139 ',
                                              '80.82.77.33 ', '82.221.105.6 ', '82.221.105.7 ', '89.248.167.131 ',
                                              '89.248.172.16 ', '93.120.27.62 ', '93.174.95.106 ',
                                              '94.102.49.190 ',
                                              '94.102.49.193 ''162.142.125.53',
                                              '162.142.125.54', '162.142.125.55', '162.142.125.56',
                                              '162.142.125.39', '162.142.125.38', '162.142.125.37',
                                              '162.142.125.40',
                                              '162.142.125.60', '162.142.125.59', '162.142.125.57',
                                              '162.142.125.43',
                                              '162.142.125.41', '162.142.125.58', '162.142.125.44',
                                              '162.142.125.42',
                                              '162.142.125.196', '162.142.125.194', '162.142.125.193',
                                              '162.142.125.195',
                                              '162.142.125.96', '74.120.14.56', '74.120.14.55', '74.120.14.54',
                                              '74.120.14.38',
                                              '74.120.14.53', '74.120.14.39', '74.120.14.40', '167.248.133.56',
                                              '167.248.133.40',
                                              '167.248.133.53', '74.120.14.37', '167.248.133.38', '167.248.133.55',
                                              '167.248.133.54', '167.248.133.39', '167.248.133.37',
                                              '167.248.133.59',
                                              '167.248.133.42', '167.248.133.43', '167.248.133.44',
                                              '167.248.133.58',
                                              '167.248.133.41', '167.248.133.57', '167.248.133.60',
                                              '167.248.133.114',
                                              '167.248.133.116', '167.248.133.113', '167.248.133.115',
                                              '167.94.138.59',
                                              '167.94.138.44', '167.94.138.58', '167.94.138.43', '167.94.138.41',
                                              '167.94.138.60', '167.94.138.57', '167.94.138.42', '167.94.138.114',
                                              '167.94.138.116', '167.94.138.113', '167.94.138.115', '74.120.14.43',
                                              '74.120.14.57', '74.120.14.59', '74.120.14.44', '74.120.14.42',
                                              '74.120.14.113', '74.120.14.41', '74.120.14.60', '74.120.14.115',
                                              '74.120.14.114', '74.120.14.58', '74.120.14.116', '162.142.125.121',
                                              '31.44.185.57', '31.44.185.115', '167.94.146.57', '167.94.145.58',
                                              '167.94.146.59', '167.94.146.60', '167.94.145.59', '167.94.145.60',
                                              '167.94.145.57', '167.94.146.58', '91.243.46.122', '192.35.168.240',
                                              '162.142.125.33', '162.142.125.34', '162.142.125.35',
                                              '162.142.125.36',
                                              '167.94.138.2', '178.57.220.188', '163.172.164.243',
                                              '167.248.133.96',
                                              '74.120.14.96', '185.220.101.51', '46.254.20.36', '185.220.100.252',
                                              '162.142.125.128']}},  # shodan and censys

                            {'terms':
                                 {'request': ['HEAD / HTTP/1.0', 'HEAD / HTTP/1.1', 'POST / HTTP/1.0',
                                              'POST / HTTP/1.1',
                                              'GET / HTTP/1.0', 'GET / HTTP/1.1', '/favicon.ico', '/.env', '/Nmap',
                                              'OPTIONS / HTTP/1.0', 'OPTIONS / HTTP/1.1', 'GET /version HTTP/1.1']
                                  }
                             }
                        ],
                        'must_not': {'terms': {'source_ip': [ip_string]}}
                    }
                }
        }
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        b = Requests()
        b = get_path2(b, result["hits"]["hits"]["_source"]["source_ip"])
        if count == 1:
            ip_list.append(b)
            ip_string = ip_string + ", '" + b.source_ip + "'"
        get_deip()


def group_analysis2(a, group):
    ipl = []
    if group == "bad":
        for badip in badip_list:
            ncount = 0
            query = {'query': {
                'bool': {'must': [{'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': badip}}
                                  ],
                         'should': {'terms': {'request': a.requestq}},
                         }
            }}
            result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
            if result != null:
                ipl.append(badip)
                ncount = ncount + 1
                for index in range(len(a.requests)):
                    query = {'query': {
                        'bool': {'must': [{'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': badip}}
                                          ],
                                 'should': {'terms': {'request': a.requests[index]}},
                                 }
                    }}
                    result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
                    if result != null:
                        ncount = ncount + 1
                if ncount >= (len(a.requests) / 2) & len(a.requests) > 6:
                    print(ipl)
                    print("重ね合わせたパスが多いので、手で調べてください,関連がれば1、なければ0を入力してください")
                    if input() == 0:
                        ipl.remove(badip)
                elif len(a.requests) < 6 & ncount >= (len(a.requests)) - 1:
                    print(ipl)
                    print("重ね合わせたパスが多いので、手で調べてください,関連がれば1、なければ0を入力してください")
                    if input() == 0:
                        ipl.remove(badip)
                else:
                    ipl.remove(badip)
        print(ipl)
        print(a.requests)
    else:
        query = {
            'query':
                {'bool':
                    {'must':
                        {'term': {'@timestamp': '2021-01-17'}},
                     'should':
                        {'terms': {'request': requestq}},
                     'must_not': [
                            {'terms': {
                                "source_ip": ['185.163.109.66 ', '198.20.69.74 ', '198.20.69.98 ', '198.20.87.98 ',
                                              '198.20.99.130 ', '198.20.70.114 ', '66.240.192.138 ',
                                              '66.240.205.34 ',
                                              '66.240.219.146 ', '66.240.236.119 ', '71.6.135.131 ',
                                              '71.6.146.185 ',
                                              '71.6.146.186 ', '71.6.158.166 ', '71.6.165.200 ', '71.6.167.142 ',
                                              '80.82.77.139 ',
                                              '80.82.77.33 ', '82.221.105.6 ', '82.221.105.7 ', '89.248.167.131 ',
                                              '89.248.172.16 ', '93.120.27.62 ', '93.174.95.106 ',
                                              '94.102.49.190 ',
                                              '94.102.49.193 ''162.142.125.53',
                                              '162.142.125.54', '162.142.125.55', '162.142.125.56',
                                              '162.142.125.39', '162.142.125.38', '162.142.125.37',
                                              '162.142.125.40',
                                              '162.142.125.60', '162.142.125.59', '162.142.125.57',
                                              '162.142.125.43',
                                              '162.142.125.41', '162.142.125.58', '162.142.125.44',
                                              '162.142.125.42',
                                              '162.142.125.196', '162.142.125.194', '162.142.125.193',
                                              '162.142.125.195',
                                              '162.142.125.96', '74.120.14.56', '74.120.14.55', '74.120.14.54',
                                              '74.120.14.38',
                                              '74.120.14.53', '74.120.14.39', '74.120.14.40', '167.248.133.56',
                                              '167.248.133.40',
                                              '167.248.133.53', '74.120.14.37', '167.248.133.38', '167.248.133.55',
                                              '167.248.133.54', '167.248.133.39', '167.248.133.37',
                                              '167.248.133.59',
                                              '167.248.133.42', '167.248.133.43', '167.248.133.44',
                                              '167.248.133.58',
                                              '167.248.133.41', '167.248.133.57', '167.248.133.60',
                                              '167.248.133.114',
                                              '167.248.133.116', '167.248.133.113', '167.248.133.115',
                                              '167.94.138.59',
                                              '167.94.138.44', '167.94.138.58', '167.94.138.43', '167.94.138.41',
                                              '167.94.138.60', '167.94.138.57', '167.94.138.42', '167.94.138.114',
                                              '167.94.138.116', '167.94.138.113', '167.94.138.115', '74.120.14.43',
                                              '74.120.14.57', '74.120.14.59', '74.120.14.44', '74.120.14.42',
                                              '74.120.14.113', '74.120.14.41', '74.120.14.60', '74.120.14.115',
                                              '74.120.14.114', '74.120.14.58', '74.120.14.116', '162.142.125.121',
                                              '31.44.185.57', '31.44.185.115', '167.94.146.57', '167.94.145.58',
                                              '167.94.146.59', '167.94.146.60', '167.94.145.59', '167.94.145.60',
                                              '167.94.145.57', '167.94.146.58', '91.243.46.122', '192.35.168.240',
                                              '162.142.125.33', '162.142.125.34', '162.142.125.35',
                                              '162.142.125.36',
                                              '167.94.138.2', '178.57.220.188', '163.172.164.243',
                                              '167.248.133.96',
                                              '74.120.14.96', '185.220.101.51', '46.254.20.36', '185.220.100.252',
                                              '162.142.125.128']}},  # shodan and censys

                            {'terms':
                                 {'request': ['HEAD / HTTP/1.0', 'HEAD / HTTP/1.1', 'POST / HTTP/1.0',
                                              'POST / HTTP/1.1',
                                              'GET / HTTP/1.0', 'GET / HTTP/1.1', '/favicon.ico', '/.env', '/Nmap',
                                              'OPTIONS / HTTP/1.0', 'OPTIONS / HTTP/1.1', 'GET /version HTTP/1.1']
                                  }
                             }
                        ],
                     'must_not': {'terms': {'source_ip': [ip_string]}}
                    }
                }
        }
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        if result != null:
            ncount = ncount + 1
    if ncount >= (len(a.requests) / 2) & len(a.requests) > 6:
        print(ipl)
        print("重ね合わせたパスが多いので、手で調べてください,関連がれば1、なければ0を入力してください")
        if input() == 0:
            ipl.remove(badip)
    elif len(a.requests) < 6 & ncount >= (len(a.requests)) - 1:
        print(ipl)
        print("重ね合わせたパスが多いので、手で調べてください,関連がれば1、なければ0を入力してください")
        if input() == 0:
            ipl.remove(badip)
    else:
        ipl.remove(badip)
    print(ipl)
    print(a.requests)


def get_ip2():
    query = {
        'query':
            {'bool':
                 {'must':
                      {'term': {'@timestamp': '2021-01-17'}},
                  'must_not': [
                      {'terms': {"source_ip": ['185.163.109.66 ', '198.20.69.74 ', '198.20.69.98 ', '198.20.87.98 ',
                                               '198.20.99.130 ', '198.20.70.114 ', '66.240.192.138 ',
                                               '66.240.205.34 ',
                                               '66.240.219.146 ', '66.240.236.119 ', '71.6.135.131 ', '71.6.146.185 ',
                                               '71.6.146.186 ', '71.6.158.166 ', '71.6.165.200 ', '71.6.167.142 ',
                                               '80.82.77.139 ',
                                               '80.82.77.33 ', '82.221.105.6 ', '82.221.105.7 ', '89.248.167.131 ',
                                               '89.248.172.16 ', '93.120.27.62 ', '93.174.95.106 ', '94.102.49.190 ',
                                               '94.102.49.193 ''162.142.125.53',
                                               '162.142.125.54', '162.142.125.55', '162.142.125.56',
                                               '162.142.125.39', '162.142.125.38', '162.142.125.37', '162.142.125.40',
                                               '162.142.125.60', '162.142.125.59', '162.142.125.57', '162.142.125.43',
                                               '162.142.125.41', '162.142.125.58', '162.142.125.44', '162.142.125.42',
                                               '162.142.125.196', '162.142.125.194', '162.142.125.193',
                                               '162.142.125.195',
                                               '162.142.125.96', '74.120.14.56', '74.120.14.55', '74.120.14.54',
                                               '74.120.14.38',
                                               '74.120.14.53', '74.120.14.39', '74.120.14.40', '167.248.133.56',
                                               '167.248.133.40',
                                               '167.248.133.53', '74.120.14.37', '167.248.133.38', '167.248.133.55',
                                               '167.248.133.54', '167.248.133.39', '167.248.133.37', '167.248.133.59',
                                               '167.248.133.42', '167.248.133.43', '167.248.133.44', '167.248.133.58',
                                               '167.248.133.41', '167.248.133.57', '167.248.133.60',
                                               '167.248.133.114',
                                               '167.248.133.116', '167.248.133.113', '167.248.133.115',
                                               '167.94.138.59',
                                               '167.94.138.44', '167.94.138.58', '167.94.138.43', '167.94.138.41',
                                               '167.94.138.60', '167.94.138.57', '167.94.138.42', '167.94.138.114',
                                               '167.94.138.116', '167.94.138.113', '167.94.138.115', '74.120.14.43',
                                               '74.120.14.57', '74.120.14.59', '74.120.14.44', '74.120.14.42',
                                               '74.120.14.113', '74.120.14.41', '74.120.14.60', '74.120.14.115',
                                               '74.120.14.114', '74.120.14.58', '74.120.14.116', '162.142.125.121',
                                               '31.44.185.57', '31.44.185.115', '167.94.146.57', '167.94.145.58',
                                               '167.94.146.59', '167.94.146.60', '167.94.145.59', '167.94.145.60',
                                               '167.94.145.57', '167.94.146.58', '91.243.46.122', '192.35.168.240',
                                               '162.142.125.33', '162.142.125.34', '162.142.125.35', '162.142.125.36',
                                               '167.94.138.2', '178.57.220.188', '163.172.164.243', '167.248.133.96',
                                               '74.120.14.96', '185.220.101.51', '46.254.20.36', '185.220.100.252',
                                               '162.142.125.128']}},  # shodan and censys

                      {'terms':
                           {'request': ['HEAD / HTTP/1.0', 'HEAD / HTTP/1.1', 'POST / HTTP/1.0', 'POST / HTTP/1.1',
                                        'GET / HTTP/1.0', 'GET / HTTP/1.1', '/favicon.ico', '/.env', '/Nmap',
                                        'OPTIONS / HTTP/1.0', 'OPTIONS / HTTP/1.1', 'GET /version HTTP/1.1']
                            }
                       }
                  ],
                  'must_not': {'terms': {'source_ip': [ip_string]}}
                  }
             }
    }
    result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
    result1 = es.search(index="xpot_accesslog-2021.01", body=query, size=2000)
    if len(result1["hits"]["hits"]["_source"]) < 2000:
        flag1 = 1
    sip = result["hits"]["hits"]["_source"]["source_ip"]
    return sip


def get_path2(a,sip):
    while result != NULL:
        query = {
            'query':
                {'bool': {
                    'must': [
                        {'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': sip}}
                    ],
                    'must_not':
                        {'terms': {'request': [a.requestq]}

                         }

                }
                }
        }
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        result2 = es.search(index="xpot_accesslog-2021.01", body=query, size=2000)
        if len(result["hits"]["hits"]["_source"]) < 30:
            flag2 = 1
        if (result["hits"]["hits"]["_source"]["request"]) != null:
            print(result["hits"]["hits"]["_source"]["request"])
            print("パスやパラメータなどリクエストの特徴を入力ください")
            kaka = input()
            requestq = requestq + ",'" + kaka + "'"
            a.requests.append(kaka)
            print("同じ脆弱性複数の場合、ここで0を入力してください,違うの場合は1")
            j = input()
            if j == 1:
                a.rlist.append(kaka)
                a.destination_port.append(result["hits"]["hits"]["_source"]["destination_port"])
                a.destination_ip.append(result["hits"]["hits"]["_source"]["destination_ip"])
                a.source_ip = badip
                count = count + 1
                badip_list.remove(a.source_ip)
    return a


if __name__ == "__main__":
    get_badip()
    print(badip_listp)  # !!!!!!!!
    for badip in badip_list:
        a = Requests()
        ip_list = []
        output_list = []
        a = get_path(a, badip)
        ipcount = 0
        if count == 1:  # パス一種類だけ
            ip_list.append(a)
            ipcount = ipcount + 1
            group_analysis1(a, "bad")
        else:  # 複数システムを狙う
            ip_list.append(a)
            ipcount = ipcount + 1
            group_analysis2(a, "bad")
    get_onerequest()
    loopcount = 0
    while (1):
        a = Requests()
        ip_list = []
        output_list = []
        a = get_path2(a, (get_ip2()))
        ipcount = 0
        if count == 1:  # パス一種類だけ
            loopcount = loopcount + 1
            ip_list.append(a)
            ipcount = ipcount + 1
            group_analysis1(a, "not bad")
            ip_string = ip_string + ", '" + a.source_ip + "'"
        else:
            loopcount == 0
            ip_list.append(a)
            ipcount = ipcount + 1
            group_analysis2(a, "not bad")
        if loopcount >= 3 & flag1 == 1 & flag2 == 1:
            break

    query = {
        'query':
            {'bool':
                 {'must':
                      {'term': {'@timestamp': '2021-01-17'}},
                  'must_not':
                      {'terms': {
                          "source_ip": ['185.163.109.66 ', '198.20.69.74 ', '198.20.69.98 ', '198.20.87.98 ',
                                        '198.20.99.130 ', '198.20.70.114 ', '66.240.192.138 ',
                                        '66.240.205.34 ',
                                        '66.240.219.146 ', '66.240.236.119 ', '71.6.135.131 ',
                                        '71.6.146.185 ',
                                        '71.6.146.186 ', '71.6.158.166 ', '71.6.165.200 ', '71.6.167.142 ',
                                        '80.82.77.139 ',
                                        '80.82.77.33 ', '82.221.105.6 ', '82.221.105.7 ', '89.248.167.131 ',
                                        '89.248.172.16 ', '93.120.27.62 ', '93.174.95.106 ',
                                        '94.102.49.190 ',
                                        '94.102.49.193 ''162.142.125.53',
                                        '162.142.125.54', '162.142.125.55', '162.142.125.56',
                                        '162.142.125.39', '162.142.125.38', '162.142.125.37',
                                        '162.142.125.40',
                                        '162.142.125.60', '162.142.125.59', '162.142.125.57',
                                        '162.142.125.43',
                                        '162.142.125.41', '162.142.125.58', '162.142.125.44',
                                        '162.142.125.42',
                                        '162.142.125.196', '162.142.125.194', '162.142.125.193',
                                        '162.142.125.195',
                                        '162.142.125.96', '74.120.14.56', '74.120.14.55', '74.120.14.54',
                                        '74.120.14.38',
                                        '74.120.14.53', '74.120.14.39', '74.120.14.40', '167.248.133.56',
                                        '167.248.133.40',
                                        '167.248.133.53', '74.120.14.37', '167.248.133.38', '167.248.133.55',
                                        '167.248.133.54', '167.248.133.39', '167.248.133.37',
                                        '167.248.133.59',
                                        '167.248.133.42', '167.248.133.43', '167.248.133.44',
                                        '167.248.133.58',
                                        '167.248.133.41', '167.248.133.57', '167.248.133.60',
                                        '167.248.133.114',
                                        '167.248.133.116', '167.248.133.113', '167.248.133.115',
                                        '167.94.138.59',
                                        '167.94.138.44', '167.94.138.58', '167.94.138.43', '167.94.138.41',
                                        '167.94.138.60', '167.94.138.57', '167.94.138.42', '167.94.138.114',
                                        '167.94.138.116', '167.94.138.113', '167.94.138.115', '74.120.14.43',
                                        '74.120.14.57', '74.120.14.59', '74.120.14.44', '74.120.14.42',
                                        '74.120.14.113', '74.120.14.41', '74.120.14.60', '74.120.14.115',
                                        '74.120.14.114', '74.120.14.58', '74.120.14.116', '162.142.125.121',
                                        '31.44.185.57', '31.44.185.115', '167.94.146.57', '167.94.145.58',
                                        '167.94.146.59', '167.94.146.60', '167.94.145.59', '167.94.145.60',
                                        '167.94.145.57', '167.94.146.58', '91.243.46.122', '192.35.168.240',
                                        '162.142.125.33', '162.142.125.34', '162.142.125.35',
                                        '162.142.125.36',
                                        '167.94.138.2', '178.57.220.188', '163.172.164.243',
                                        '167.248.133.96',
                                        '74.120.14.96', '185.220.101.51', '46.254.20.36', '185.220.100.252',
                                        '162.142.125.128']}},  # shodan and censys
                  'must_not':
                      {'terms':
                           {'request': ['HEAD / HTTP/1.0', 'HEAD / HTTP/1.1', 'POST / HTTP/1.0',
                                        'POST / HTTP/1.1',
                                        'GET / HTTP/1.0', 'GET / HTTP/1.1', '/favicon.ico', '/.env', '/Nmap',
                                        'OPTIONS / HTTP/1.0', 'OPTIONS / HTTP/1.1', 'GET /version HTTP/1.1']
                            }
                       },
                  'must_not': {'terms': {'source_ip': [ip_string]}}
                  }
             }
    }
    remainder= []
    result = es.search(index="xpot_accesslog-2021.01", body=query, size=10000)
    for log in result["hits"]["hits"]["_source"]:
        c = Requests()
        c.source_ip.append(log["source_ip"])
        c.requests.append(log["request"])
        remainder.append(c)
        c = null
    remainder= set(remainder)
    print(remainder)
