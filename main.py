from elasticsearch import Elasticsearch
import re
import sys
import time
import operator


class Requests(object):
    def __init__(self):
        self.source_ip = ''
        self.destination_ip = []
        self.destination_port = []
        self.path = []


class Patterns(object):
    def __init__(self):
        self.pattern1_1_a = []
        self.pattern1_1_b = []
        self.pattern1_1_c = []
        self.pattern1_1_d = []
        self.pattern2_1_a = []
        self.pattern2_1_b = []
        self.pattern2_1_c = []
        self.pattern2_1_d = []
        self.pattern2_2 = []
        self.pattern3 = []
        self.pattern2_2_count = 0


def init_day():  # 日時設定
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


def get_badip():  # 攻撃（悪意フラグ）ip抽出
    global badip_list
    global day1
    global day2
    log = ['TEST']
    query = {'query':
        {'bool': {
            'must': [{'regexp': {'analysis_tags.keyword': '.*'}},
                     {'term': {'@timestamp': day2}}],
            'must_not': [
                {'match_phrase': {'source_ip': '0.0.0.0'}}
            ]}}}

    while len(log) != 0:
        result = es.search(index=day1, body=query, size=1)
        log = result["hits"]["hits"]
        if len(log) != 0:
            query['query']['bool']['must_not'].append({'match_phrase': {'source_ip': log[0]["_source"]["source_ip"]}})
            badip_list.append(log[0]["_source"]["source_ip"])
    print('攻撃活動のip数:')
    print(len(badip_list))


def get_pattern3():  # 単発リクエストのIp抽出
    global badip_list
    global day1
    global day2
    iplist = []
    for ip in badip_list:
        query = {
            'query':
                {'bool': {
                    'must': [
                        {'term': {'@timestamp': day2}}, {'term': {'source_ip': ip}}]
                }}
        }
        result = es.search(index=day1, body=query, size=5)
        if len(result["hits"]["hits"]) == 1:
            iplist.append(ip)
            badip_list.remove(ip)
    return iplist


def path_cut(url):  # urlからパス抽出
    index = 0
    index_x = 0
    surl = ''
    surl = url
    if '?' in surl:
        index = surl.find('?')
    if 'wget' in surl:
        index_x = surl.find('wget')
        if index_x < index:
            index = index_x
    if 'curl' in surl:
        index_x = surl.find('curl')
        if index_x < index:
            index = index_x
    if 'fetch' in surl:
        index_x = surl.find('fetch')
        if index_x < index:
            index = index_x
    if index > 1:
        url = surl[0:index]
    return url


def get_path(ip):  # パス種類数調査
    global badip_list
    global count
    global day1
    global day2
    m = ['test']
    a = Requests()
    a.source_ip = ip
    query = {
        'query':
            {'bool': {
                'must': [
                    {'term': {'@timestamp': day2}}, {'term': {'source_ip': ip}}],
                'must_not': [
                    {'match_phrase': {'request': 'HEAD / HTTP/1.0'}},
                    {'match_phrase': {'request': 'HEAD / HTTP/1.1'}},
                    {'match_phrase': {'request': 'POST / HTTP/1.0'}},
                    {'match_phrase': {'request': 'POST / HTTP/1.1'}},
                    {'match_phrase': {'request': 'GET / HTTP/1.0'}},
                    {'match_phrase': {'request': 'GET / HTTP/1.1'}}
                    ]
            }}
    }
    while len(m) != 0:
        result = es.search(index=day1, body=query, size=1)
        m = result["hits"]["hits"]
        if len(m) != 0:
            url = path_cut(m[0]["_source"]["url"])
            a.path.append(url)
            query['query']['bool']['must_not'].append({'match_phrase': {'url': url}})
            count = count + 1
    return a


def get_de(request):  # 目標ハニーポット・ポート数調査
    global day1
    global day2
    global flag1
    global flag2
    ip = request.source_ip
    log = ['test']
    deip = []  # 目標ハニーポットのリスト
    query = {
        'query':
            {'bool': {
                'must': [
                    {'term': {'@timestamp': day2}}, {'term': {'source_ip': ip}}],
                'must_not': [{'match_phrase': {'source_ip': '0.0.0.0'}}
                             ]
            }
            }
    }
    while len(log) != 0:  # 目標ハニーポット数
        result = es.search(index=day1, body=query, size=1)
        log = result["hits"]["hits"]
        if len(log) != 0:
            if len(deip) == 0:
                deip.append(log[0]["_source"]["destination_ip"])
                request.destination_ip.append(log[0]["_source"]["destination_ip"])
                query['query']['bool']['must_not'].append(
                    {'match_phrase': {'destination_ip': log[0]["_source"]["destination_ip"]}})
            elif len(deip) == 1:
                deip.append(log[0]["_source"]["destination_ip"])
                # request.destination_ip.append(log[0]["_source"]["destination_ip"])
                flag1 = 2
                log = []
                # 変更より全部の目標ハニーポット統計が可能になる
    if len(deip) == 1:
        flag1 = 1
    elif len(deip) == 0:
        print('data error')
    query = {
        'query':
            {'bool': {
                'must': [
                    {'term': {'@timestamp': day2}}, {'term': {'source_ip': ip}}],
                'must_not': [{'match_phrase': {'source_ip': '0.0.0.0'}}
                             ]
            }
            }
    }
    log = ['test']
    deport = []  # 目標ポートのリスト
    while len(log) != 0:  # 目標ポート数
        result = es.search(index=day1, body=query, size=1)
        log = result["hits"]["hits"]
        if len(log) != 0:
            if len(deport) == 0:
                deport.append(log[0]["_source"]["destination_port"])
                request.destination_port.append(log[0]["_source"]["destination_port"])
                query['query']['bool']['must_not'].append(
                    {'match_phrase': {'destination_port': log[0]["_source"]["destination_port"]}})
            elif len(deport) == 1:
                deport.append(log[0]["_source"]["destination_port"])
                # request.destination_port.append(log[0]["_source"]["destination_port"])
                flag2 = 2
                log = []
                # 変更より全部のポート統計が可能になる
    if len(deport) == 1:
        flag2 = 1
    elif len(deport) == 0:
        print('data error')


def group_analysis1(request):  # パターン分類関数1
    global flag1
    global flag2
    global count
    global day1
    global day2
    global output
    flag1 = 0
    flag2 = 0
    get_de(request)  # 目標ハニーポット・ポート数調査
    # パターン分類
    if flag1 == 1 and flag2 == 1:
        output.pattern1_1_a.append(request.source_ip)
    elif flag1 == 1 and flag2 == 2:
        output.pattern1_1_b.append(request.source_ip)
    elif flag1 == 2 and flag2 == 1:
        output.pattern1_1_c.append(request.source_ip)
    elif flag1 == 2 and flag2 == 2:
        output.pattern1_1_d.append(request.source_ip)


def group_analysis2(request):  # 複数パスの場合，同じパス使用のipがグループになるが，先に2-1-a～2-1-dに分類
    global flag1
    global flag2
    global count
    global day1
    global day2
    global output
    global path_list
    global path_ip
    global path_pattern
    path_ip.append(request.source_ip)
    path_list.append(request.path)
    flag1 = 0
    flag2 = 0
    get_de(request)  # 目標ハニーポット・ポート数調査
    if flag1 == 1 and flag2 == 1:
        output.pattern2_1_a.append(request.source_ip)
        path_pattern.append('1')
    elif flag1 == 1 and flag2 == 2:
        output.pattern2_1_b.append(request.source_ip)
        path_pattern.append('2')
    elif flag1 == 2 and flag2 == 1:
        output.pattern2_1_c.append(request.source_ip)
        path_pattern.append('3')
    elif flag1 == 2 and flag2 == 2:
        output.pattern2_1_d.append(request.source_ip)
        path_pattern.append('4')


def get_group():  # 2-1-a～2-1-dから同じパス使用のipがグループになって，2-2に変更
    global output
    global path_list
    global path_ip
    global path_pattern
    ip_n = 0
    judge = []
    for ip_s in path_ip:
        judge.append(0)
    while len(path_ip) > ip_n:
        path = path_list[ip_n]
        ip = path_ip[ip_n]
        ip_m = 0
        group_ip = [ip]
        while ip_m < len(path_ip):  # 複数ipが同じ複数パスの場合，2-1-xから2-2に変更
            if ip_m != ip_n:
                if operator.eq(path, path_list[ip_m]):
                    if judge[ip_n] == 0:
                        if path_pattern[ip_n] == '1':
                            output.pattern2_1_a.remove(ip)
                        elif path_pattern[ip_n] == '2':
                            output.pattern2_1_b.remove(ip)
                        elif path_pattern[ip_n] == '3':
                            output.pattern2_1_c.remove(ip)
                        elif path_pattern[ip_n] == '4':
                            output.pattern2_1_d.remove(ip)
                        judge[ip_n] = 1
                    if judge[ip_m] == 0:
                        group_ip.append(path_ip[ip_m])
                        if path_pattern[ip_m] == '1':
                            output.pattern2_1_a.remove(path_ip[ip_m])
                        elif path_pattern[ip_m] == '2':
                            output.pattern2_1_b.remove(path_ip[ip_m])
                        elif path_pattern[ip_m] == '3':
                            output.pattern2_1_c.remove(path_ip[ip_m])
                        elif path_pattern[ip_m] == '4':
                            output.pattern2_1_d.remove(path_ip[ip_m])
                        judge[ip_m] = 1
                    ip_m = ip_m + 1
                else:
                    ip_m = ip_m + 1
            else:
                ip_m = ip_m + 1
        if len(group_ip) != 0:
            output.pattern2_2.append(group_ip)
            output.pattern2_2_count = output.pattern2_2_count + len(group_ip)
        ip_n = ip_n + 1


def pattern_result():
    global output
    print('パターン1-1-aのip数:')
    print(len(output.pattern1_1_a))
    print('パターン1-1-bのip数:')
    print(len(output.pattern1_1_b))
    print('パターン1-1-cのip数:')
    print(len(output.pattern1_1_c))
    print('パターン1-1-dのip数:')
    print(len(output.pattern1_1_d))
    print('パターン2-1-aのip数:')
    print(len(output.pattern2_1_a))
    print('パターン2-1-bのip数:')
    print(len(output.pattern2_1_b))
    print('パターン2-1-cのip数:')
    print(len(output.pattern2_1_c))
    print('パターン2-1-dのip数:')
    print(len(output.pattern2_1_d))
    print('パターン2-2のip数:')
    print(output.pattern2_2_count)
    print('パターン3のip数:')
    print(len(output.pattern3))
    # 一部のパラメータを変更することで、特定のipまたは特定のpathを出力できる。


if __name__ == "__main__":
    # 対象日設定
    global day1
    day1 = ''
    global day2
    day2 = ''
    init_day()
    # esサーバー設定
    es = Elasticsearch("http://172.23.32.103:9200")
    # 攻撃（悪意フラグ）のip
    global badip_list
    badip_list = []
    get_badip()  # 攻撃（悪意フラグ）ipの抽出
    # 　結果の保存先設定
    global output
    output = Patterns()
    # 攻撃（悪意フラグ）のip(単発)
    output.pattern3 = get_pattern3()

    global count  # パス種類数用
    count = 0
    global flag1  # 目標ハニーポット数用
    global flag2  # 目標ポート数用
    global path_list  # 複数ipのグループ用
    path_list = []
    global path_ip
    path_ip = []
    global path_pattern
    path_pattern = []
    # ipごとに活動パターン調査
    while len(badip_list) > 0:
        badip = badip_list[0]
        # ipの行為データをRequests(object)に保存
        a = Requests()
        a.path = []
        a.source_ip = ''
        a.destination_ip = []
        ip_list = []
        count = 0  # パス種類数カウント
        output_list = []
        a = get_path(badip)  # Ipのパス種類数調査
        if count == 1:  # パス一種類だけ
            badip_list.remove(badip)
            group_analysis1(a)
        elif count == 0:
            output.pattern1_1_a.append(badip)
            badip_list.remove(badip)
            print("'/'から攻撃がある")
        else:  # 複数パス
            a.path.sort()
            group_analysis2(a)
            badip_list.remove(badip)
    get_group()  # 複数パスのグループ化
    pattern_result()  # 各パターンのip数
