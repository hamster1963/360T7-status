#!/usr/bin/env python3
# coding: utf-8
# Update by : https://github.com/cppla/ServerStatus, Update date: 20220530
# 版本：1.0.3, 支持Python版本：2.7 to 3.10
# 支持操作系统： Linux, OSX, FreeBSD, OpenBSD and NetBSD, both 32-bit and 64-bit architectures
# 说明: 默认情况下修改server和user就可以了。丢包率监测方向可以自定义，例如：CU = "www.facebook.com"。

SERVER = "127.0.0.1"
USER = "home_router"

PASSWORD = "USER_DEFAULT_PASSWORD"
PORT = 35601
CU = "cu.tz.cloudcpp.com"
CT = "ct.tz.cloudcpp.com"
CM = "cm.tz.cloudcpp.com"
PROBEPORT = 80
PROBE_PROTOCOL_PREFER = "ipv4"  # ipv4, ipv6
PING_PACKET_HISTORY_LEN = 100
INTERVAL = 2

Uptime = 0
CPU = 0
MemoryUsed = 0
UpSpeed = 0
DownSpeed = 0
NetworkDown = 0
NetworkUp = 0

import socket
import time
import timeit
import re
import os
import sys
import json
import errno
import subprocess
import threading

try:
    from queue import Queue  # python3
except ImportError:
    print("ImportError: from queue import Queue")
    # from Queue import Queue     # python2


def get_uptime():
    with open('/proc/uptime', 'r') as f:
        uptime = f.readline().split('.', 2)
        return int(uptime[0])


def get_memory():
    re_parser = re.compile(r'^(?P<key>\S*):\s*(?P<value>\d*)\s*kB')
    result = dict()
    for line in open('/proc/meminfo'):
        match = re_parser.match(line)
        if not match:
            continue
        key, value = match.groups(['key', 'value'])
        result[key] = int(value)
    MemTotal = float(result['MemTotal'])
    MemUsed = MemTotal - float(result['MemFree']) - float(result['Buffers']) - float(result['Cached']) - float(
        result['SReclaimable'])
    SwapTotal = float(result['SwapTotal'])
    SwapFree = float(result['SwapFree'])
    return int(MemTotal), int(MemUsed), int(SwapTotal), int(SwapFree)


def get_hdd():
    p = subprocess.check_output(
        ['df', '-Tlm', '--total', '-t', 'ext4', '-t', 'ext3', '-t', 'ext2', '-t', 'reiserfs', '-t', 'jfs', '-t', 'ntfs',
         '-t', 'fat32', '-t', 'btrfs', '-t', 'fuseblk', '-t', 'zfs', '-t', 'simfs', '-t', 'xfs']).decode("Utf-8")
    total = p.splitlines()[-1]
    used = total.split()[3]
    size = total.split()[2]
    return int(size), int(used)


def get_time():
    with open("/proc/stat", "r") as f:
        time_list = f.readline().split(' ')[2:6]
        for i in range(len(time_list)):
            time_list[i] = int(time_list[i])
        return time_list


def delta_time():
    x = get_time()
    time.sleep(INTERVAL)
    y = get_time()
    for i in range(len(x)):
        y[i] -= x[i]
    return y


def get_cpu():
    t = delta_time()
    st = sum(t)
    if st == 0:
        st = 1
    result = 100 - (t[len(t) - 1] * 100.00 / st)
    return round(result, 1)


def liuliang():
    NET_IN = 0
    NET_OUT = 0
    return NET_IN, NET_OUT


def tupd():
    '''
    tcp, udp, process, thread count: for view ddcc attack , then send warning
    :return:
    '''
    s = subprocess.check_output("ss -t|wc -l", shell=True)
    t = int(s[:-1]) - 1
    s = subprocess.check_output("ss -u|wc -l", shell=True)
    u = int(s[:-1]) - 1
    s = subprocess.check_output("ps -ef|wc -l", shell=True)
    p = int(s[:-1]) - 2
    s = subprocess.check_output("ps -eLf|wc -l", shell=True)
    d = int(s[:-1]) - 2
    return t, u, p, d


def get_network(ip_version):
    if (ip_version == 4):
        HOST = "ipv4.google.com"
    elif (ip_version == 6):
        HOST = "ipv6.google.com"
    try:
        socket.create_connection((HOST, 80), 2).close()
        return True
    except:
        return False


lostRate = {
    '10010': 0.0,
    '189': 0.0,
    '10086': 0.0
}
pingTime = {
    '10010': 0,
    '189': 0,
    '10086': 0
}
netSpeed = {
    'netrx': 0.0,
    'nettx': 0.0,
    'clock': 0.0,
    'diff': 0.0,
    'avgrx': 0,
    'avgtx': 0
}
diskIO = {
    'read': 0,
    'write': 0
}


def _ping_thread(host, mark, port):
    lostPacket = 0
    packet_queue = Queue(maxsize=PING_PACKET_HISTORY_LEN)

    IP = host
    if host.count(':') < 1:  # if not plain ipv6 address, means ipv4 address or hostname
        try:
            if PROBE_PROTOCOL_PREFER == 'ipv4':
                IP = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
            else:
                IP = socket.getaddrinfo(host, None, socket.AF_INET6)[0][4][0]
        except Exception:
            pass

    while True:
        if packet_queue.full():
            if packet_queue.get() == 0:
                lostPacket -= 1
        try:
            b = timeit.default_timer()
            socket.create_connection((IP, port), timeout=1).close()
            pingTime[mark] = int((timeit.default_timer() - b) * 1000)
            packet_queue.put(1)
        except socket.error as error:
            if error.errno == errno.ECONNREFUSED:
                pingTime[mark] = int((timeit.default_timer() - b) * 1000)
                packet_queue.put(1)
            # elif error.errno == errno.ETIMEDOUT:
            else:
                lostPacket += 1
                packet_queue.put(0)

        if packet_queue.qsize() > 30:
            lostRate[mark] = float(lostPacket) / packet_queue.qsize()

        time.sleep(INTERVAL)


def _net_speed():
    while True:
        with open("/proc/net/dev", "r") as f:
            net_dev = f.readlines()
            avgrx = 0
            avgtx = 0
            for dev in net_dev[2:]:
                dev = dev.split(':')
                if "lo" in dev[0] or "tun" in dev[0] \
                        or "docker" in dev[0] or "veth" in dev[0] \
                        or "br-" in dev[0] or "vmbr" in dev[0] \
                        or "vnet" in dev[0] or "kube" in dev[0]:
                    continue
                dev = dev[1].split()
                avgrx += int(dev[0])
                avgtx += int(dev[8])
            now_clock = time.time()
            netSpeed["diff"] = now_clock - netSpeed["clock"]
            netSpeed["clock"] = now_clock
            netSpeed["netrx"] = int((avgrx - netSpeed["avgrx"]) / netSpeed["diff"])
            netSpeed["nettx"] = int((avgtx - netSpeed["avgtx"]) / netSpeed["diff"])
            netSpeed["avgrx"] = avgrx
            netSpeed["avgtx"] = avgtx
        time.sleep(INTERVAL)


def _disk_io():
    '''
    good luck for opensource! by: cpp.la
    磁盘IO：因为IOPS原因，SSD和HDD、包括RAID卡，ZFS等阵列技术。IO对性能的影响还需要结合自身服务器情况来判断。
    比如我这里是机械硬盘，大量做随机小文件读写，那么很低的读写也就能造成硬盘长时间的等待。
    如果这里做连续性IO，那么普通机械硬盘写入到100Mb/s，那么也能造成硬盘长时间的等待。
    磁盘读写有误差：4k，8k ，https://stackoverflow.com/questions/34413926/psutil-vs-dd-monitoring-disk-i-o
    :return:
    '''
    while True:
        # pre pid snapshot
        snapshot_first = {}
        # next pid snapshot
        snapshot_second = {}
        # read count snapshot
        snapshot_read = 0
        # write count snapshot
        snapshot_write = 0
        # process snapshot
        pid_snapshot = [str(i) for i in os.listdir("/proc") if i.isdigit() is True]
        for pid in pid_snapshot:
            try:
                with open("/proc/{}/io".format(pid)) as f:
                    pid_io = {}
                    for line in f.readlines():
                        if "read_bytes" in line:
                            pid_io["read"] = int(line.split("read_bytes:")[-1].strip())
                        elif "write_bytes" in line and "cancelled_write_bytes" not in line:
                            pid_io["write"] = int(line.split("write_bytes:")[-1].strip())
                    pid_io["name"] = open("/proc/{}/comm".format(pid), "r").read().strip()
                    snapshot_first[pid] = pid_io
            except:
                if pid in snapshot_first:
                    snapshot_first.pop(pid)

        time.sleep(INTERVAL)

        for pid in pid_snapshot:
            try:
                with open("/proc/{}/io".format(pid)) as f:
                    pid_io = {}
                    for line in f.readlines():
                        if "read_bytes" in line:
                            pid_io["read"] = int(line.split("read_bytes:")[-1].strip())
                        elif "write_bytes" in line and "cancelled_write_bytes" not in line:
                            pid_io["write"] = int(line.split("write_bytes:")[-1].strip())
                    pid_io["name"] = open("/proc/{}/comm".format(pid), "r").read().strip()
                    snapshot_second[pid] = pid_io
            except:
                if pid in snapshot_first:
                    snapshot_first.pop(pid)
                if pid in snapshot_second:
                    snapshot_second.pop(pid)

        for k, v in snapshot_first.items():
            if snapshot_first[k]["name"] == snapshot_second[k]["name"] and snapshot_first[k]["name"] != "bash":
                snapshot_read += (snapshot_second[k]["read"] - snapshot_first[k]["read"])
                snapshot_write += (snapshot_second[k]["write"] - snapshot_first[k]["write"])
        diskIO["read"] = snapshot_read
        diskIO["write"] = snapshot_write


def get_realtime_data():
    '''
    real time get system data
    :return:
    '''
    t1 = threading.Thread(
        target=_ping_thread,
        kwargs={
            'host': CU,
            'mark': '10010',
            'port': PROBEPORT
        }
    )
    t2 = threading.Thread(
        target=_ping_thread,
        kwargs={
            'host': CT,
            'mark': '189',
            'port': PROBEPORT
        }
    )
    t3 = threading.Thread(
        target=_ping_thread,
        kwargs={
            'host': CM,
            'mark': '10086',
            'port': PROBEPORT
        }
    )
    t4 = threading.Thread(
        target=login,
    )
    # t5 = threading.Thread(
    #     target=_disk_io,
    # )
    for ti in [t1, t2, t3, t4]:
        ti.daemon = True
        ti.start()


def byte_str(object):
    '''
    bytes to str, str to bytes
    :param object:
    :return:
    '''
    if isinstance(object, str):
        return object.encode(encoding="utf-8")
    elif isinstance(object, bytes):
        return bytes.decode(object)
    else:
        print(type(object))


import requests
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder

headers = {
    'Accept': 'application/json, text/plain, */*',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/110.0.0.0 Safari/537.36',
    'Host': '192.168.31.1',
    'Origin': 'http://192.168.31.1',
    'Referer': 'http://192.168.31.1/',
    'Cookie': '',
    'Token-ID': '',
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
}


def gen_aes_str(rand_key):
    mode = AES.MODE_CBC
    iv = b'\x33\x36\x30\x6c\x75\x79\x6f\x75\x40\x69\x6e\x73\x74\x61\x6c\x6c'  # "360luyou@install".decode('hex')
    encryptor = AES.new(rand_key, mode, iv)
    encoder = PKCS7Encoder()
    text = "deny1963"  # password
    pad_text = encoder.encode(text)
    cipher = encryptor.encrypt(bytes(pad_text, "utf-8"))
    return cipher


def get_rand_aes_key():
    r = requests.post('http://192.168.31.1/router/get_rand_key.cgi')
    key = r.content
    key = eval(key)
    rand_key = key['rand_key']
    return rand_key


def login():
    # 通过接口获取随机密钥
    rand_aes_key = get_rand_aes_key()
    # 用后32位进行AES加密
    aes_key = rand_aes_key[32:]
    result = gen_aes_str(bytes.fromhex(aes_key))
    # 进行登录获取cookie和token用于后续请求
    url = "http://192.168.31.1/router/web_login.cgi"
    payload = 'user=admin&pass=%s&form=1' % (rand_aes_key[:32] + result.hex())
    # print(payload)
    response = requests.request("POST", url, headers=headers, data=payload)
    res = eval(response.text)
    if res['success'] == "1":
        print('登录成功')
        # 获取cookie和token
        cookie = response.headers['Set-Cookie']
        token = res['Token-ID']
        headers['Cookie'] = cookie
        headers['Token-ID'] = token
    else:
        print('登录失败')
    time.sleep(30)


def get_router_info():
    global Uptime, CPU, MemoryUsed, UpSpeed, DownSpeed, NetworkDown, NetworkUp
    # 获取路由器信息
    response = requests.request("POST", "http://192.168.31.1/web360/getrouterinfo.cgi", headers=headers)
    res_info: dict = eval(response.text)
    if res_info.get('err_no') == '0':
        # print('获取路由器信息成功')
        Uptime = int(res_info['data']['uptime'])
        CPU = float(res_info['data']['cpu'])
        MemoryUsed = 256 - int(res_info['data']['ramfree'])
        # print('运行时间：%s, CPU占用：%s, 内存使用：%sm' % (Uptime, CPU, MemoryUsed))

    # 获取路由器网速
    response = requests.request("POST", "http://192.168.31.1/web360/getwanspeed.cgi", headers=headers)
    res_info: dict = eval(response.text)
    if res_info.get('err_no') == '0':
        # print('获取路由器信息成功')
        UpSpeed = int(res_info['data']['up_speed'])
        DownSpeed = int(res_info['data']['down_speed'])
        # print('上行速度：%s, 下行速度：%s' % (UpSpeed, DownSpeed))

    # 获取路由器信息
    response = requests.request("POST", "http://192.168.31.1/router/mesh_get_topology_info.cgi", headers=headers)
    res_info: dict = eval(response.text)
    NetworkDown = 0
    NetworkUp = 0
    if res_info.get('err_no') == '0':
        for x in list(res_info['data'][0]["client_node"]):
            NetworkUp += int(x['up_bytes'])
            NetworkDown += int(x['down_bytes'])
        # print('上行流量：%d, 下行流量：%d' % (NetworkUp, NetworkDown))

    time.sleep(INTERVAL)


if __name__ == '__main__':
    for argc in sys.argv:
        if 'SERVER' in argc:
            SERVER = argc.split('SERVER=')[-1]
        elif 'PORT' in argc:
            PORT = int(argc.split('PORT=')[-1])
        elif 'USER' in argc:
            USER = argc.split('USER=')[-1]
        elif 'PASSWORD' in argc:
            PASSWORD = argc.split('PASSWORD=')[-1]
        elif 'INTERVAL' in argc:
            INTERVAL = int(argc.split('INTERVAL=')[-1])
    socket.setdefaulttimeout(30)
    get_realtime_data()
    while True:
        try:
            print("Connecting...")
            s = socket.create_connection((SERVER, PORT))
            data = byte_str(s.recv(1024))
            if data.find("Authentication required") > -1:
                s.send(byte_str(USER + ':' + PASSWORD + '\n'))
                data = byte_str(s.recv(1024))
                if data.find("Authentication successful") < 0:
                    print(data)
                    raise socket.error
            else:
                print(data)
                raise socket.error

            print(data)
            if data.find("You are connecting via") < 0:
                data = byte_str(s.recv(1024))
                print(data)

            timer = 0
            check_ip = 0
            if data.find("IPv4") > -1:
                check_ip = 6
            elif data.find("IPv6") > -1:
                check_ip = 4
            else:
                print(data)
                raise socket.error

            while True:
                # CPU = get_cpu()
                # Uptime = get_uptime()
                # Load_1, Load_5, Load_15 = os.getloadavg()
                # MemoryTotal, MemoryUsed, SwapTotal, SwapFree = get_memory()
                # HDDTotal, HDDUsed = get_hdd()
                # login()
                get_router_info()

                array = {}
                if not timer:
                    array['online' + str(check_ip)] = get_network(check_ip)
                    timer = 10
                else:
                    timer -= 1 * INTERVAL

                array['uptime'] = Uptime
                array['memory_total'] = 256 * 1024
                array['memory_used'] = MemoryUsed * 1024
                array['cpu'] = CPU
                array['network_rx'] = DownSpeed
                array['network_tx'] = UpSpeed
                array['network_in'] = NetworkUp
                array['network_out'] = NetworkDown

                array['load_1'] = 0
                array['load_5'] = 0
                array['load_15'] = 0
                array['swap_total'] = 0
                array['swap_used'] = 0
                array['hdd_total'] = 0
                array['hdd_used'] = 0

                # todo: 流量统计

                # todo：兼容旧版本，下个版本删除ip_status
                array['ip_status'] = True
                array['ping_10010'] = lostRate.get('10010') * 100
                array['ping_189'] = lostRate.get('189') * 100
                array['ping_10086'] = lostRate.get('10086') * 100
                array['time_10010'] = pingTime.get('10010')
                array['time_189'] = pingTime.get('189')
                array['time_10086'] = pingTime.get('10086')
                array['tcp'], array['udp'], array['process'], array['thread'] = tupd()
                array['io_read'] = 0
                array['io_write'] = 0
                s.send(byte_str("update " + json.dumps(array) + "\n"))
        except KeyboardInterrupt:
            raise
        except socket.error:
            print("Disconnected...")
            if 's' in locals().keys():
                del s
            time.sleep(3)
        except Exception as e:
            print("Caught Exception:", e)
            if 's' in locals().keys():
                del s
            time.sleep(3)
