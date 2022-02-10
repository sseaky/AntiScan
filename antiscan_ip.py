#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Seaky
# @Date:   2020/12/16 17:00

import os
import re

import ipdb

PROJECT_DIR = '/root/.antiscan'
DB_FILE = '{}/ipipfree.ipdb'.format(PROJECT_DIR)


def parse(f):
    title = ['ip', 'count', 'datetime', 'unixstamp', 'port']
    loc = ['country_name', 'region_name', 'city_name']
    if os.path.exists(f):
        l = []
        db = ipdb.City(DB_FILE)
        for line in open(f).readlines():
            if not re.match('\d+', line):
                continue
            line = line.strip()
            d = {title[i]: x for i, x in enumerate(line.split(','))}
            d['count'] = int(d['count'])
            d['unixstamp'] = int(d['unixstamp'])
            d1 = db.find_map(d['ip'], 'CN')
            locl = []
            for k in loc:
                if d1.get(k) and d1[k] not in locl:
                    locl.append(d1[k])
            d['location'] = '-'.join(locl)
            l.append(d)
        l.sort(key=lambda v: v['unixstamp'])
        title.insert(5, 'location')
        l.insert(0, {x: x for x in title})
        print('-- {} --'.format(f))
        for i, x in enumerate(l):
            if i == 0:
                print('{ip:<15}  {count:<5}  {datetime:<17}  {unixstamp:<10}  {location:　<11}  {port}'.format(**x))
            else:
                print('{ip:<15}  {count:<5}  {datetime:<17}  {unixstamp:<10}  {location:　<7}  {port}'.format(**x))


if __name__ == '__main__':
    if not os.path.exists(DB_FILE):
        exit(1)
    for f in ['threat', 'trust']:
        parse('{}/{}.csv'.format(PROJECT_DIR, f))
