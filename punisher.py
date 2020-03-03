#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Seaky
# @Date:   2019/5/1 22:52

import argparse
import pickle as cp
import re
import shlex
import shutil
import struct
import subprocess
import time
from functools import partial, wraps
from pathlib import Path
from pprint import pprint
from socket import inet_aton, inet_ntoa

import ipdb

NETWORK_TRUST = ['192.168.0.0/16']
NETWORK_THREAT = []
IPSET_TRUST, IPSET_THREAT = 'TRUST', 'THREAT'
ARGS = {}
CACHE = {}
LOG_FILE = '/var/log/iptables.log'
PATTERN_TRUST = '(?P<last_seen>[A-Z][a-z]+ +\d+ +[\d:]+).+TRUST: .+SRC=(?P<src>[\S]+) DST.* LEN=128 .* PROTO=(?P<proto>[\S]+)'
PATTERN_THREAT = '(?P<last_seen>[A-Z][a-z]+ +\d+ +[\d:]+).+THREAT: .+SRC=(?P<src>[\S]+) DST.*PROTO=(?P<proto>[\S]+) SPT=(?P<spt>[\S]+) DPT=(?P<dpt>[\S]+)'
CP_FILE = 'history.cp'


def count_time(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        start_time = time.time()
        result = f(*args, **kwargs)
        elapsed_time = round(time.time() - start_time, 2)
        print('{0:.2f}s {1}.'.format(elapsed_time, f.__name__))
        return result

    return wrap


def get_term_width():
    width, depth = shutil.get_terminal_size((80, 20))
    return width


_pprint = partial(pprint, width=get_term_width())


def ip2long(ip):
    packed = inet_aton(ip)
    lng = struct.unpack("!L", packed)[0]
    return lng


def long2ip(lng):
    packed = struct.pack("!L", lng)
    ip = inet_ntoa(packed)
    return ip


def get_ip_loc(ip, db_name='ipipfree.ipdb'):
    '''
    :param v:   str ip
    :param db_name: use ipipfree.ipdb
    :return:
    '''
    if 'db' not in CACHE:
        db = ipdb.City(db_name)
        CACHE['db'] = db
    else:
        db = CACHE['db']
    d = db.find_map(ip, "CN")
    # location = '-'.join([d[k] for k in ['country_name', 'region_name', 'city_name'] if d.get(k)])
    location = '{country_name}-{region_name}-{city_name}'.format(**d) if d.get(
        'city_name') else '{country_name}'.format(**d)
    return location


def shell(cmd):
    '''
    out, err, rc = shell(cmd)
    '''
    # cmd = 'sudo ' + cmd
    child = subprocess.Popen(shlex.split(cmd),
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    # child.wait()
    return [x.decode('utf-8') if isinstance(x, bytes) else x for x in (*child.communicate(), child.returncode)]


def iptables_get_ips(tag, table='INPUT'):
    '''
    ipt_trust    '\n(?P<n>[\d]+) .+\*\s+(?P<ip>[\S]+) .+ADD TRUST'
    ipt_threat   '\n(?P<n>[\d]+) .+\*\s+(?P<ip>[\S]+) .+ADD THREAT'
    '''
    out, err, rc = shell('iptables -nvL {} --line-numbers'.format(table))
    p = re.compile('\n(?P<n>[\d]+) .+\*\s+(?P<ip>[\S]+) .+{}'.format(tag))
    ips = {}
    for i, x in enumerate(p.finditer(out)):
        d = x.groupdict()
        ip = d['ip']
        ips[ip] = d
    return ips


def iptabels_add_ips(new, exist, exclude=None, rule='trust'):
    action, comment = ('ACCEPT', 'TRUST') if rule == 'trust' else ('DROP', 'THREAT')
    for ip in new:
        if exclude and ip in exclude:
            continue
        if ip not in exist:
            cmd = 'iptables -A INPUT -s {} -j {} -m comment --comment "ADD {}"'.format(ip, action, comment)
            shell(cmd)


def log_get_ips(regexp, loc=False):
    content = open(LOG_FILE).read()
    p = re.compile(regexp)
    ips = {}
    for i, x in enumerate(p.finditer(content)):
        d = x.groupdict()
        ip = d['src']
        if ip not in ips:
            ips[ip] = {'ip': ip, 'hits': 0}
            if loc:
                ips[ip]['location'] = get_ip_loc(ip)
        ips[ip]['hits'] += 1
        ips[ip]['last_seen'] = d['last_seen']
        if d.get('dpt'):
            if 'dpt' not in ips[ip]:
                ips[ip]['dpt'] = []
            dpt = int(d['dpt'])
            if dpt not in ips[ip]['dpt']:
                ips[ip]['dpt'].append(dpt)
    for k, v in ips.items():
        if v.get('dpt'):
            v['dpt'] = sorted(v['dpt'])
    return ips


def ipset_get_ips(ipset_name):
    p = re.compile('\n(?P<src>[\d\./]+) timeout (?P<timeout>\d+)')
    cmd = 'ipset list {}'.format(ipset_name)
    out, err, rc = shell(cmd)
    ips = {}
    for i, x in enumerate(p.finditer(out)):
        d = x.groupdict()
        ips[d['src']] = d['timeout']
    return ips


def ipset_create(ipset_name):
    out, err, rc = shell('ipset list -n')
    sets = out.split('\n')
    if ipset_name not in sets:
        cmd = 'ipset create {} hash:net hashsize 4096 maxelem 1000000 timeout 0'.format(ipset_name)
        shell(cmd)
    return True


def is_threat(v, ipset_name):
    if ipset_name == IPSET_THREAT:
        if v.get('hits') > ARGS['hits'] or ('dpt' in v and len(v['dpt']) > ARGS['dpts']):
            return True
    elif ipset_name == IPSET_TRUST:
        return True


# @count_time
def ipset_add(ips_list, ipset_name):
    ips_exist = ipset_get_ips(ipset_name)
    if isinstance(ips_list, list):
        ips_list = {ip: {'hits': 9999} for ip in ips_list}
    for ip, v in ips_list.items():
        if ip not in ips_exist and is_threat(v, ipset_name):
            cmd = 'ipset add {} {} timeout 0'.format(ipset_name, ip)
            shell(cmd)
    return True


def modify_ipset_trust_threat():
    ips_trust_from_log = log_get_ips(PATTERN_TRUST)
    ips_threat_from_log = log_get_ips(PATTERN_THREAT)
    ipset_add(ips_trust_from_log, IPSET_TRUST)
    ipset_add(ips_threat_from_log, IPSET_THREAT)
    return True


def init():
    ipset_create(IPSET_TRUST) and ipset_add(NETWORK_TRUST, IPSET_TRUST) and \
    ipset_create(IPSET_THREAT) and ipset_add(NETWORK_THREAT, IPSET_THREAT)
    if Path(CP_FILE).exists():
        hist = cp.load(open(CP_FILE, 'rb'))
        ipset_add(hist['trust'], IPSET_TRUST) and ipset_add(hist['threat'], IPSET_THREAT)


def save():
    new = {'trust': log_get_ips(PATTERN_TRUST, loc=True), 'threat': log_get_ips(PATTERN_THREAT, loc=True)}
    if not Path(CP_FILE).exists():
        hist = new
    else:
        hist = cp.load(open(CP_FILE, 'rb'))
        for clas, d in new.items():
            for ip, v in d.items():
                if ip not in hist[clas]:
                    hist[clas][ip] = v
                else:
                    hist[clas][ip]['hits'] += v['hits']
                    for x in ['location', 'last_seen']:
                        if v.get(x):
                            hist[clas][ip][x] = v[x]
                    if clas == 'threat':
                        hist[clas][ip]['dpt'] = sorted(list(set(hist[clas][ip]['dpt'] + v['dpt'])))
    cp.dump(hist, open(CP_FILE, 'wb'))
    print("run \"sudo sh -c ':>{}'\" to clear logs.".format(LOG_FILE))


def show_history():
    if Path(CP_FILE).exists():
        hist = cp.load(open(CP_FILE, 'rb'))
        _sort(hist['threat'])


def _sort(data):
    def sort_by_hit(v):
        return v['hits']

    l = sorted(
        [v for k, v in data.items() if
         is_threat(v, ipset_name=IPSET_THREAT) and (not ARGS['loc_spec'] or (ARGS['loc_spec'] in v['location']))],
        key=sort_by_hit)
    _pprint(l)
    print('threat count(hits>{}): {}'.format(ARGS['hits'], len(l)))


def sort_ipset():
    l = sorted([k for k, v in ipset_get_ips(IPSET_THREAT).items()], key=lambda k: ip2long(k))
    nws = {}
    for ip in l[:]:
        nw, host = ip.rsplit('.', 1)
        if nw not in nws:
            nws[nw] = {'nw': nw, 'count': 0, 'host': [], 'location': get_ip_loc(ip)}
        nws[nw]['count'] += 1
        nws[nw]['host'].append(int(host))
    for nw, v in nws.items():
        v['host'] = sorted(v['host'])
    _pprint(sorted([v for k, v in nws.items() if v['count'] >= ARGS['hits']], key=lambda v: v['count']))


def run():
    if ARGS.get('sort_ipset'):
        sort_ipset()
    elif ARGS.get('history'):
        show_history()
    elif ARGS.get('save'):
        save()
    elif ARGS.get('stat'):
        _sort(log_get_ips(PATTERN_THREAT, loc=ARGS['loc']))
    elif ARGS.get('init'):
        init()
    elif ARGS.get('work'):
        modify_ipset_trust_threat()
    else:
        if CACHE.get('parser'):
            CACHE['parser'].print_help()
        else:
            print('--help for more infomation.')


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', action='store_true', default=False, help='cron work')
    parser.add_argument('--init', action='store_true', default=False, help='initiate the ipset')
    parser.add_argument('--stat', action='store_true', default=False, help='stat threat items')
    parser.add_argument('--loc', action='store_true', default=False, help='show location when stat')
    parser.add_argument('--loc_spec', type=str, default='', help='location spec when stat')
    parser.add_argument('--cn', action='store_true', default=False, help='show china ip')
    parser.add_argument('--save', action='store_true', default=False, help='dump log')
    parser.add_argument('--history', action='store_true', default=False, help='show history from file')
    parser.add_argument('--sort_ipset', action='store_true', default=False, help='sort ipset by networks')
    parser.add_argument('--hits', type=int, default=5, help='minimum hists')
    parser.add_argument('--dpts', type=int, default=2, help='minimum number of dpts')
    CACHE['parser'] = parser
    args = parser.parse_args()
    if args.cn and not args.loc_spec:
        args.loc_spec = '中国'
    ARGS.update(args.__dict__)
    return True


if __name__ == '__main__':
    parse() and run()
