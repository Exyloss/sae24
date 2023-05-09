#!/usr/bin/env python3

from scapy.all import *
import base64

def render_entry(entry):
    print(f"IP source : {entry['src']} ; IP destination : {entry['dst']} ; Port source : {entry['sport']} ; utilisateur : {entry['user']} ; mot de passe : {entry['password']}")

def get_www_capture(file):
    trames = rdpcap(file)
    passwd = []
    for i in trames:
        pw = get_www_req(i)
        if pw not in passwd and pw != {}:
            passwd.append(pw)
    return passwd

def get_www_req(req):
    pw = {}
    if req.haslayer('Raw') and req.haslayer('TCP') and req.dport == 80 and 'Authorization' in req['TCP'].load.decode('utf-8'):
        pw = {
            'src': req['IP'].src,
            'dst': req['IP'].dst,
            'sport': req['TCP'].sport,
            'dport': req['TCP'].dport
        }
        http = req.load.decode('utf-8').split('\r\n')
        for i in http:
            if 'Authorization' in i:
                pass64 = i.split(' ')[-1]
                cred = base64.b64decode(pass64).decode('utf-8').split(':')
                pw['user'] = cred[0]
                pw['password'] = cred[1]
                break
    return pw

def get_www_sniff(frame):
    global entries
    data = get_www_req(frame)
    if data != {} and data not in entries:
        entries.append(data)
        render_entry(data)

if __name__ == '__main__':
    entries = []
    trames = rdpcap("../capture/www-total.pcapng")
    for i in trames:
        get_www_sniff(i)

    # sniff(filter='tcp', prn=get_www_sniff, iface='lo')
