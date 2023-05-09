#!/usr/bin/env python3

from scapy.all import *
import argparse

def render_entry(entry):
    print(f"IP source : {entry['src']} ; IP destination : {entry['dst']} ; Port source : {entry['sport']} ; utilisateur : {entry['user']} ; mot de passe : {entry['password']}")

def get_req_infos(frame, passwd, files):
    if frame.haslayer('Raw') and frame.haslayer('TCP'):
        try:
            data_b = frame.load
            data = frame.load.decode('utf-8').split('\r\n')[0]
        except:
            data = ''
            pass

        if frame.dport == 21 and 'USER' in data:
            passwd.append({})
            passwd[-1]['sport'] = frame.sport
            passwd[-1]['src'] = frame['IP'].src
            passwd[-1]['dst'] = frame['IP'].dst
            passwd[-1]['user'] = data.split('USER ')[1]
            passwd[-1]['end'] = False
        elif frame.dport == 21 and 'PASS' in data:
            for j in range(len(passwd)):
                if 'password' not in passwd[j] and passwd[j]['sport'] == frame.sport and passwd[j]['src'] == frame['IP'].src:
                    passwd[j]['password'] = data.split('PASS ')[1]
                    passwd[j]['end'] = True
        elif frame.dport == 21 and 'RETR ' in data:
            filename = data.split('RETR ')[1]
            files.append({'cmd_sport': frame.sport, 'data_sport': 0, 'src': frame['IP'].src, 'dst': frame['IP'].dst, 'file': filename, 'data': b'', 'end': False})
        elif frame.sport == 20:
            for i in range(len(files)):
                if files[i]['data_sport'] == frame.dport and files[i]['src'] == frame['IP'].dst:
                    files[i]['data'] += data_b
        elif frame.sport == 21 and 'Transfer complete' in data:
            for i in range(len(files)):
                if files[i]['cmd_sport'] == frame.dport and files[i]['src'] == frame['IP'].dst:
                    files[i]['end'] = True

    elif frame.haslayer('TCP') and frame.dport == 20 and frame['TCP'].flags == 18:
        for i in range(len(files)):
            if files[i]['src'] == frame['IP'].src and files[i]['data_sport'] == 0:
                files[i]['data_sport'] = frame.sport

    return (passwd, files)

def get_ftp_capture(file):
    trames = rdpcap(file)
    passwd = []
    files = []
    for i in trames:
        passwd, files = get_req_infos(i, passwd, files)
    return (passwd, files)

def get_ftp_sniff(frame):
    global entries, files, last_frame
    if frame == last_frame:
        return None

    last_frame = frame
    entries, files = get_req_infos(frame, entries, files)
    i = 0
    l = len(entries)
    while i < l:
        if entries[i]['end'] == True:
            render_entry(entries[i])
            entries.pop(i)
            l = len(entries)
        i += 1

def sniff_main(interface):
    global entries, files, last_frame
    entries = []
    files = []
    last_frame = TCP()
    sniff(filter='tcp', prn=get_ftp_sniff, iface=interface)

def capture_main(file):
    entries = get_ftp_capture(file)
    for i in entries[0]:
        render_entry(i)
    for j in entries[1]:
        if j['end'] == True:
            file = open(j['file'], 'wb')
            file.write(j['data'])
            file.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Lecteur de base de données keepass.")
    parser.add_argument("--file", help="Afficher les mots de passe du fichier de capture renseigné", metavar='FICHIER')
    parser.add_argument("--sniff", help="Sniffez une interface renseignée", metavar='INTERFACE')
    args = parser.parse_args()
    if args.sniff != None:
        sniff_main(args.sniff)
    elif args.file != None:
        capture_main(args.file)
