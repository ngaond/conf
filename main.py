from elasticsearch import Elasticsearch
import re
import sys
import time


class Requests(object):
    def __init__(self):
        self.source_ip = ''
        self.destination_ip = []
        self.destination_port = []
        self.requests = []


def init_day():
    global day1
    global day2
    print('年入力')
    year = input()
    print('月入力(1月なら01)')
    month = input()
    print('日入力')
    day = input()
    day1 = 'xpot_accesslog-' + year + '.' + month
    day2 = year + '-' + month + '-' + day


def get_badip():  # 攻撃（悪意フラグ）ip
    global badip_list
    global ip_string
    global day1
    global day2
    ip_string = []
    log = 'TEST'
    # while len(ip_string) < 100:
    while len(log) != 0:
        query = {'query':
                     {'bool':
                          {'must':
                               {'term': {'@timestamp': day2}},
                           'should': [
                               {'regexp': {'request': '.*wget.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*curl.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*fetch.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*java.net.URL.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*urlopen.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*bitsadmin.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*explorer.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*certutil.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*Wscript.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*getstore.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*HTTP.start.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*lwp-download.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*objXMLHTTP.*http.*:[0-9].*'}},
                               {'regexp': {'request': '.*mshta.*http.*:[0-9].*'}}
                           ],
                           'must_not':[
                               {'match_phrase': {'source_ip': '0'}}
                           ]}}}
        result = es.search(index=day1, body=query, size=1)
        log = result["hits"]["hits"]
        if len(log) != 0:
            query['query']['bool']['must_not'].append({'match_phrase': {'source_ip': log[0]["_source"]["source_ip"]}})
            # ip_string.append(log["_source"]["source_ip"])
            badip_list.append(log[0]["_source"]["source_ip"])
    print('攻撃活動のip数')
    print(len(badip_list))


def get_path(ip):  # パス種類判断
    global badip_list
    global count
    global ip_list
    m = 1
    a = Requests()
    a.source_ip = ip
    query = {
        'query':
            {'bool': {
                'must': [
                    {'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': ip}}],
                'must_not': [{'match_phrase': {'request.keyword': 'GET HTTP/1.1'}}]
            }}
    }
    if len(ip_list) != 0:
        query['query']['bool']['must_not'].append({'match_phrase': {'request': ip_list[0].requests[0]}})
    while m != 0:
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        m = len(result["hits"]["hits"])
        if m != 0:
            print(result["hits"]["hits"][0]["_source"]["source_ip"])
            print(result["hits"]["hits"][0]["_source"]["request"])
            print("パスやパラメータなどリクエストの特徴を入力ください")
            kaka = input()
            a.requests.append(kaka)
            query['query']['bool']['must_not'].append({'match_phrase': {'request': kaka}})
            # print(a.requestq)
            j = 1
            if count != 0:
                print("同じ脆弱性複数の場合、ここで0を入力してください,違うの場合は1")
                j = input()
            if j == 1:
                count = count + 1
    return a


def get_deport(n, list1, list2, kip):
    global output_list
    global ip_list
    ip_list_bk = ip_list
    m = 0
    while m < len(ip_list_bk):
        sip = ip_list_bk[m].source_ip
        deport = []
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
        for log in result["hits"]["hits"]:
            deport.append(log["_source"]["destination_port"])
        deport = list(set(deport))
        ip_list_bk[m].destination_port = deport
        print('sip: ', end=" ")
        print(ip_list_bk[m].source_ip, end=" ")
        print('---dport: ', end=" ")
        print(deport)
        m = m + 1
    print("複数ソースが同じポートを狙う特徴があるのか？なければ0を入力")
    kport = input()
    deport_l = kport.split(",")
    # output
    if n == '0':  # 目標ハニーポット数に特徴なし
        if kport == '0':  # 全体的なポート特徴なし
            print('sip: ', end=" ")
            for index in range(len(ip_list)):
                print(ip_list[index].source_ip)
            print('パス： ', end=" ")
            print(ip_list[0].requests)
            print("1.パターン:複数目標、複数ポート")
        else:  # ポート特徴あり
            count_1 = 0  # 同じパスで、ポート特徴ありとなし、2つパターン
            count_2 = 0
            output_list1 = output_list
            for index in range(len(ip_list_bk)):
                if ip_list_bk[index].destination_port != deport_l:
                    output_list1.append(ip_list_bk[index])
                    count_2 == 1
                else:
                    if count_1 == 0:
                        print('sip: ', end=" ")
                    print(ip_list_bk[index].source_ip)
                    count_1 = 1
            if count_1 == 1:
                print('dport: ', end=" ")
                print(deport_l)
                print('パス： ', end=" ")
                print(ip_list_bk[0].requests)
                print("2.複数目標、特定ポート")
            if count_2 == 1:
                print('sip: ', end=" ")
                for index in range(len(output_list1)):
                    print(output_list1[index].source_ip)
                print('パス： ', end=" ")
                print(output_list1[0].requests)
                print("3.パターン:複数目標、複数ポート")
    else:  # 目標ハニーポット数に特徴あり
        if kport == '0':  # ポート特徴なし
            count_1 = 0  # 同じパスで、目標ハニーポット数、特徴ありとなし、2つパターン
            count_2 = 0
            for index in range(len(list1)):
                if count_1 == 0:
                    print('sip: ', end=" ")
                print(list1[index].source_ip)
                count_1 = 1
            if len(list1) > 0:
                print('deip: ', end=" ")
                print(kip)
                print('パス： ', end=" ")
                print(list1[0].requests)
                print("4.特定目標、複数ポート")
            for index in range(len(list2)):
                if count_2 == 0:
                    print('sip: ', end=" ")
                print(list2[index].source_ip)
                count_2 = 1
            if count_2 == 1:
                print('sip: ', end=" ")
                for index in range(len(list2)):
                    print(list2[index].source_ip)
                print('パス： ', end=" ")
                print(list2[0].requests)
                print("5.パターン:複数目標、複数ポート")
        else:  # ポート特徴あり
            count_1 = 0  # 同じパスで、目標ハニーポット、目標ポート、4つパターン
            count_2 = 0
            count_3 = 0
            count_4 = 0
            output_list2 = []
            output_list3 = []
            for index in range(len(list1)):
                if list1[index].destination_port != deport_l:
                    output_list2.append(list1[index])
                    count_2 = 1
                else:
                    if count_1 == 0:
                        print('sip: ', end=" ")
                    print(list1[index].source_ip)
                    count_1 = 1
            if count_1 == 1:
                print('deip: ', end=" ")
                print(kip)
                print('deport: ', end=" ")
                print(deport_l)
                print('パス： ', end=" ")
                print(list1[0].requests)
                print("パターン:特定目標、特定ポート")
            if count_2 == 1:
                print('sip: ', end=" ")
                for index in range(len(output_list2)):
                    print(output_list2[index].source_ip)
                print('deip: ', end=" ")
                print(kip)
                print('パス： ', end=" ")
                print(list1[0].requests)
                print("特定目標、複数ポート")
            for index in range(len(list2)):
                if list2[index].destination_port != deport_l:
                    output_list3.append(list2[index])
                    count_4 = 1
                else:
                    if count_3 == 0:
                        print('sip: ', end=" ")
                    print(list2[index].source_ip)
                    count_3 = 1
            if count_3 == 1:
                print('deport: ', end=" ")
                print(deport_l)
                print('パス： ', end=" ")
                print(list1[0].requests)
                print("パターン:複数目標、特定ポート")
            if count_4 == 1:
                print('sip: ', end=" ")
                for index in range(len(output_list3)):
                    print(output_list3[index].source_ip)
                print('パス： ', end=" ")
                print(list2[0].requests)
                print("複数目標、複数ポート")


def get_deip():
    global output_list
    global ip_list
    ip_list_bk = ip_list
    m = 0
    while m < len(ip_list_bk):
        deip = []
        sip = ''
        sip = ip_list_bk[m].source_ip
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
        for log in result["hits"]["hits"]:
            deip.append(log["_source"]["destination_ip"])
        deip = list(set(deip))
        ip_list_bk[m].destination_ip = deip
        if len(deip) != 1:
            output_list.append(ip_list_bk[m])
            del ip_list_bk[m]
        else:
            print('sip: ', end=" ")
            print(ip_list_bk[m].source_ip, end=" ")
            print('---dip: ', end=" ")
            print(deip)
            m = m + 1
    print("複数ソースが同じハニーポットを狙う特徴があるのか？なければ0を入力")
    kip = input()
    if kip == '0':
        get_deport("0", ip_list_bk, output_list, kip)  # 全体の特徴がない、sipごとに特定目標が’ip_list_bk’
    else:
        for n in range(len(ip_list_bk)):
            if ip_list_bk[n].destination_ip[0] != kip:
                output_list.append(ip_list_bk[n])
        get_deport("1", ip_list_bk, output_list, kip)  # 複数sipの特徴があるのもは’ip_list_bk’


def group_analysis1(a, group):
    global ip_string
    global badip_list
    global count
    badip_list_bp = badip_list
    # パス一種類のみ
    if group == "bad":
        for badip in badip_list_bp:
            b = Requests()
            b.source_ip = ''
            b.requests = []
            b.destination_port = []
            b.destination_ip = []
            count = 0
            query = {'query': {
                'bool': {'must': [{'term': {'@timestamp': '2021-01-17'}},
                                  {'match_phrase': {'request': a.requests[0]}},
                                  {'term': {'source_ip': badip}}
                                  ]
                         }
            }}
            result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
            if len(result["hits"]["hits"]) != 0:
                count = 1
                b = get_path(badip)
                if count == 1:
                    b.requests = a.requests
                    ip_list.append(b)
                    badip_list.remove(badip)
        get_deip()
        # for index in range(len(ip_list)):
        #    badip_list.remove(ip_list[index].source_ip)
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
                            {'match_phrase': {'request': '/.env'}},
                            {'match_phrase': {'request': 'HEAD / HTTP/1.0'}},
                            {'match_phrase': {'request': 'HEAD / HTTP/1.1'}},
                            {'match_phrase': {'request': 'POST / HTTP/1.0'}},
                            {'match_phrase': {'request': 'POST / HTTP/1.1'}},
                            {'match_phrase': {'request': 'GET / HTTP/1.0'}},
                            {'match_phrase': {'request': 'GET / HTTP/1.1'}},
                            {'match_phrase': {'request': '/Nmap'}},
                            {'match_phrase': {'request': 'GET /version HTTP/1.1'}}
                        ],
                        'must_not': {'terms': {'source_ip': ip_string}}
                    }
                }
        }
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        if len(result["hits"]["hits"]) != 0:
            b = Requests()
            count = 1
            b = get_path2(result["hits"]["hits"][0]["_source"]["source_ip"])
            if count == 1:
                ip_list.append(b)
                ip_string.append(b.source_ip)
        get_deip()


def group_analysis2(a, group):
    global ip_string
    global badip_list
    ipl = []
    ipl.append(a.source_ip)
    reqset = []
    if group == "bad":
        for badip in badip_list:
            ncount = 0
            query = {'query': {
                'bool': {'must': [{'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': badip}}
                                  ],
                         'should': []},
            }
            }

            for index in a.requests:
                query['query']['bool']['should'].append({'match_phrase': {'request': index}})
            #   query1['query']['bool']['should'].append({'match_phrase': {'request': a.requests[index]}})
            result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
            # result1 = es.search(index="xpot_accesslog-2021.01", body=query, size=100)
            if len(result["hits"]["hits"]) != 0:
                ipl.append(badip)
                ncount = ncount + 1
                for index in a.requests:
                    query1 = {'query': {
                        'bool': {'must': [{'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': badip}}
                                          ]
                                 }
                    }}
                    query['query']['bool']['must'].append({'match_phrase': {'request': index}})
                    result = es.search(index="xpot_accesslog-2021.01", body=query1, size=1)
                    if len(result["hits"]["hits"]) != 0:
                        ncount = ncount + 1
                        reqset.append(index)
                if ncount >= (len(a.requests) / 2) and len(a.requests) > 6:
                    print(a.requests)
                    print(ipl)
                    print(reqset)
                    print("同じパス多い、関連性を判断してください,関連がれば1、なければ0を入力してください")
                    judge = input()
                    if judge == 0:
                        ipl.remove(badip)
                    # elif judge == 1:
                    #    if len(result1["hits"]["hits"]) != 0:
                    #        for n in result1["hits"]["hits"]:
                    #            a.requests.append(n["_source"]["result"])
                elif len(a.requests) < 6 and ncount >= (len(a.requests)) - 1:
                    print(a.requests)
                    print(ipl)
                    print(reqset)
                    print("同じパス多い、関連性を判断してください,関連がれば1、なければ0を入力してください")
                    judge = input()
                    if judge == 0:
                        ipl.remove(badip)
                else:
                    ipl.remove(badip)
        for index in ipl:
            badip_list.remove(index)
        print(ipl)
        print(a.requests)
    else:
        ncount = 0
        query = {
            'query':
                {'bool':
                     {'must':
                          {'term': {'@timestamp': '2021-01-17'}},
                      'should':
                          '',
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
                          {'match_phrase': {'request': '/.env'}},
                          {'match_phrase': {'request': 'HEAD / HTTP/1.0'}},
                          {'match_phrase': {'request': 'HEAD / HTTP/1.1'}},
                          {'match_phrase': {'request': 'POST / HTTP/1.0'}},
                          {'match_phrase': {'request': 'POST / HTTP/1.1'}},
                          {'match_phrase': {'request': 'GET / HTTP/1.0'}},
                          {'match_phrase': {'request': 'GET / HTTP/1.1'}},
                          {'match_phrase': {'request': '/Nmap'}},
                          {'match_phrase': {'request': 'GET /version HTTP/1.1'}}
                      ],
                      'must_not': {'terms': {'source_ip': ip_string}}
                      }
                 }
        }
        for index in a.requests:
            query['query']['bool']['should'].append({'match_phrase': {'request': index}})
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        if len(result["hits"]["hits"]) != 0:
            ncount = ncount + 1
    if ncount >= (len(a.requests) / 2) and len(a.requests) > 6:
        print(ipl)
        print("重ね合わせたパスが多いので、手で調べてください,関連がれば1、なければ0を入力してください")
        if input() == 0:
            ipl.remove(badip)
    elif len(a.requests) < 6 and ncount >= (len(a.requests)) - 1:
        print(ipl)
        print("重ね合わせたパスが多いので、手で調べてください,関連がれば1、なければ0を入力してください")
        if input() == 0:
            ipl.remove(badip)
    else:
        ipl.remove(badip)
    print(ipl)
    print(a.requests)


def get_ip2():
    global ip_string
    global flag1
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
                      {'match_phrase': {'request': '/.env'}},
                      {'match_phrase': {'request': 'HEAD / HTTP/1.0'}},
                      {'match_phrase': {'request': 'HEAD / HTTP/1.1'}},
                      {'match_phrase': {'request': 'POST / HTTP/1.0'}},
                      {'match_phrase': {'request': 'POST / HTTP/1.1'}},
                      {'match_phrase': {'request': 'GET / HTTP/1.0'}},
                      {'match_phrase': {'request': 'GET / HTTP/1.1'}},
                      {'match_phrase': {'request': '/Nmap'}},
                      {'match_phrase': {'request': 'GET /version HTTP/1.1'}}
                  ],
                  'must_not': {'terms': {'source_ip': ip_string}}
                  }
             }
    }
    result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
    result1 = es.search(index="xpot_accesslog-2021.01", body=query, size=2000)
    if len(result1["hits"]["hits"]) < 2000:
        flag1 = 1
    sip = result["hits"]["hits"][0]["_source"]["source_ip"]
    return sip


def get_path2(a, sip):
    global badip_list
    global flag2
    m = 1
    while m != 0:
        query = {
            'query':
                {'bool': {
                    'must': [
                        {'term': {'@timestamp': '2021-01-17'}}, {'term': {'source_ip': sip}}
                    ],
                    'must_not': ''

                }
                }
        }
        for index in a.requests:
            query['query']['bool']['must_not'].append({'match_phrase': {'request': index}})
        result = es.search(index="xpot_accesslog-2021.01", body=query, size=1)
        m = len(result["hits"]["hits"])
        result2 = es.search(index="xpot_accesslog-2021.01", body=query, size=2000)
        if len(result2["hits"]["hits"]) < 30:
            flag2 = 1
        if m != 0:
            print(result["hits"]["hits"][0]["_source"]["request"])
            print("パスやパラメータなどリクエストの特徴を入力ください")
            kaka = input()
            # a.requestq = a.requestq + ",'" + kaka + "'"
            j = 1
            if count != 0:
                print("同じ脆弱性複数の場合、ここで0を入力してください,違うの場合は1")
                j = input()
            if j == 1:
                a.destination_port.append(result["hits"]["hits"][0]["_source"]["destination_port"])
                a.destination_ip.append(result["hits"]["hits"][0]["_source"]["destination_ip"])
                a.source_ip = result["hits"]["hits"][0]["_source"]["source_ip"]
                count = count + 1
                badip_list.remove(a.source_ip)
    return a


if __name__ == "__main__":
    # 対象日設定
    global day1
    day1 = ''
    global day2
    day2 = ''
    init_day()

    global badip_list  # 攻撃（悪意フラグ）のip
    badip_list = []

    global badip_listp
    badip_listp = []
    global ip_list
    ip_list = []
    global output_list
    output_list = []
    global count
    count = 0
    global ip_string
    ip_string = []

    global es
    es = Elasticsearch("http://172.23.32.103:9200")
    global flag1
    flag1 = 0
    global flag2
    flag2 = 0
    get_badip()  # 攻撃（悪意フラグ）ipの抽出
'''
    for badip in badip_list:  # ipごとに活動パターン調査
        # ipの行為データをRequests(object)に保存
        a = Requests()
        a.requests = []
        a.source_ip = ''
        a.destination_ip = []
        ip_list = []
        count = 0  # パス種類数カウント
        output_list = []
        a = get_path(badip)  # Ipのパス種類数調査
        if count == 1:  # パス一種類だけ
            badip_list.remove(badip)
            ip_list.append(a)
            group_analysis1(a, "bad")  # パターン分類関数1
        elif count == 0:
            print('data error')
        else:  # 複数パス
            badip_list.remove(badip)
            ip_list.append(a)
            group_analysis2(a, "bad")  # パターン分類関数2
    k = input()
    path = []
    while k != 0:
        path = path + k
        k = input()
    loopcount = 0
'''

