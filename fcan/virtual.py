from lxml import html
import requests
import json
import sys


release = sys.argv[1]
url = 'https://packages.debian.org/{}/virtual/'.format(release)
page = requests.get(url)
tree = html.fromstring(page.content)
virtual_pkgs = tree.xpath('//dt/a/text()')
pkgs = tree.xpath('//dd')

res = {v.split()[0]: [l.text.split()[0] for l in p]
       for v, p in zip(virtual_pkgs, pkgs)}

with open('fcan/data/virtual/{}.json'.format(release), 'w') as f:
    json.dump(res, f)
