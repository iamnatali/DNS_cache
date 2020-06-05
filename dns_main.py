import socket
from datetime import datetime
import pickle
import os

port = 53
ip = "127.0.0.1"


class Header:
    def __init__(self):
        self.id = None
        self.query_request = None
        self.query_type = None
        self.authoritative_answer = None
        self.truncate = None
        self.recursion_desired = None
        self.recursion_available = None
        self.z = None
        self.response_code = None
        self.QDCOUNT = None
        self.ANCOUNT = None
        self.NSCOUNT = None
        self.ARCOUNT = None
        self.in_bytes = None

    def make_answer(self, ans_c):
        self.query_request='1'
        self.authoritative_answer='1'
        self.recursion_available='1'
        self.ANOUNT = 1
        str_byte1 = self.query_request+self.query_type\
                    +self.authoritative_answer+self.truncate\
                    +self.recursion_desired
        byte1 = bytes([int(str_byte1,2)])
        str_byte2 = self.recursion_available +self.z+self.response_code
        byte2 = bytes([int(str_byte2, 2)])
        ANCOUNT = (ans_c).to_bytes(2, byteorder ='big')
        return self.in_bytes[0:2]+byte1+byte2+self.in_bytes[4:6]+ANCOUNT+self.in_bytes[8:12]

    def from_bytes(self, bytes_ar):
        self.in_bytes = bytes_ar[:12]
        self.id = int.from_bytes(bytes_ar[0:2], 'big')

        byte1 = bytes_ar[2:3]
        line_byte1 = one_byte_to_int(byte1)
        self.query_request = line_byte1[0]
        self.query_type = line_byte1[1:5]
        self.authoritative_answer = line_byte1[5]
        self.truncate = line_byte1[6]
        self.recursion_desired =line_byte1[7]

        byte2 = bytes_ar[3:4]
        line_byte2 = one_byte_to_int(byte2)
        self.recursion_available =line_byte2[0]
        self.z =line_byte2[1:4]
        self.response_code=line_byte2[4:8]

        self.QDCOUNT = int.from_bytes(bytes_ar[4:6], 'big')
        self.ANCOUNT = int.from_bytes(bytes_ar[6:8], 'big')
        self.NSCOUNT = int.from_bytes(bytes_ar[8:10], 'big')
        self.ARCOUNT = int.from_bytes(bytes_ar[10:12], "big")

        return bytes_ar[12:]

    def __str__(self):
        list_str = []
        list_str.append("id "+ str(self.id))
        list_str.append("qr " + str(self.query_request))
        list_str.append("qtype " + str(self.query_type))
        list_str.append("aa " + str(self.authoritative_answer))
        list_str.append("tr " + str(self.truncate))
        list_str.append("rd " + str(self.recursion_desired))
        list_str.append("ra " + str(self.recursion_available))
        list_str.append("z " + str(self.z))
        list_str.append("resp code " + str(self.response_code))
        list_str.append("qd count " + str(self.QDCOUNT))
        list_str.append("an count " + str(self.ANCOUNT))
        list_str.append("ns count " + str(self.NSCOUNT))
        list_str.append("arc count " + str(self.QDCOUNT))
        return '\n'.join(list_str)


class Record:
    def __init__(self):
        self.query = None
        self.ttl = None
        self.length = None
        self.data = None
        self.record_part_bytes = None

    def from_bytes(self, byte_arr, all_array):
        self.query = Query()
        left_part = self.query.from_bytes(byte_arr, all_array)
        self.ttl = int.from_bytes(left_part[:4], 'big')
        self.length = int.from_bytes(left_part[4:6], 'big')
        self.data = left_part[6:6+self.length]
        self.record_part_bytes = left_part[:6+self.length]
        return left_part[6+self.length:]

    def __str__(self):
        str_list = []
        str_list.append(str(self.query))
        str_list.append("ttl " + str(self.ttl))
        str_list.append("length " + str(self.length))
        str_list.append("data " + str(self.data))
        return '\n'.join(str_list)


class Query:
    def __init__(self):
        self.qname = None
        self.qname_bytes = None
        self.qtype = None
        self.qtype_bytes = None
        self.qclass = None
        self.type_list = {
            1:'A',
            2:'NS',
            3:'MD',
            4:'MF',
            5:'CNAME',
            6:'SOA',
            7:'MB',
            8:'MG',
            9:'MR',
            10:'NULL',
            11:'WKS',
            12:'PTR',
            13:'HINFO',
            14:'MINFO',
            15:'MX',
            16:'TXT',
            28:'AAAA',
            255:'ANY'}

    def __str__(self):
        str_list = []
        str_list.append("name "+ str(self.qname))
        str_list.append("type " + str(self.qtype))
        str_list.append("class " + str(self.qclass))
        return '\n'.join(str_list)

    @staticmethod
    def get_name(byte_arr, all_array):
        length = byte_arr[0]
        to_int = one_byte_to_int(byte_arr[0:1])
        prev_length = 0
        name = []
        while length != 0 and to_int[:2] != '11':
            arr_part = byte_arr[prev_length + 1:prev_length + length + 1]
            prev_length = prev_length + length + 1
            length = byte_arr[prev_length]
            name.append(str(arr_part)[2:].replace('\'', ''))
            to_int = one_byte_to_int(byte_arr[prev_length:prev_length+1])
        if to_int[:2] == '11':
            second = byte_arr[prev_length+1:prev_length+2]
            sec_line = one_byte_to_int(second)
            start = int(to_int[2:] + sec_line, 2)
            prev_length += 1
            name.append(Query.get_name(all_array[start:], all_array)[0])
            qname = '.'.join(name)
        else:
            qname = '.'.join(name)
        return (qname, prev_length)

    def get_ANY_query(self):
        any_type = b'\x00\xff'
        return self.qname_bytes+any_type+self.qclass

    def from_bytes(self, byte_arr, all_array):
        pair = Query.get_name(byte_arr, all_array)
        self.qname = pair[0]
        prev_length = pair[1]
        self.qname_bytes = byte_arr[:prev_length+1]
        self.qtype_bytes = byte_arr[prev_length+1:prev_length+3]
        ind = int.from_bytes(self.qtype_bytes, 'big')
        try:
            self.qtype = self.type_list[ind]
        except KeyError:
            self.qtype = 'unknown'
        self.qclass = byte_arr[prev_length+3:prev_length+5]
        return byte_arr[prev_length+5:]


class Packet:
    def __init__(self):
        self.header = Header()
        self.query = Query()
        self.answers = []
        self.ns = []
        self.additional = []

    def __str__(self):
        res = str(self.header)+'\n'+str(self.query)+'\n'
        res += "answers\n"
        for s in self.answers:
            res += str(s)+"\n"
        res += "ns\n"
        for s in self.ns:
            res += str(s)+"\n"
        res += "additional\n"
        for s in self.additional:
            res += str(s)+"\n"
        return res

    def from_bytes(self, bytes):
        left = self.header.from_bytes(bytes)
        left = self.query.from_bytes(left, bytes)
        if self.header.ANCOUNT != 0:
            for n in range(self.header.ANCOUNT):
                r = Record()
                left=r.from_bytes(left, bytes)
                self.answers.append(r)
        if self.header.NSCOUNT != 0:
            for n in range(self.header.NSCOUNT):
                r = Record()
                left=r.from_bytes(left, bytes)
                self.ns.append(r)
        if self.header.ARCOUNT != 0:
            for n in range(self.header.ARCOUNT):
                r = Record()
                left=r.from_bytes(left, bytes)
                self.answers.append(r)


def one_byte_to_int(byte):
    i = (int.from_bytes(byte, 'big'))
    s = format(i, '08b')
    return s


def add_rec(r):
    pair_key = (r.query.qname, r.query.qtype_bytes)
    record = r.record_part_bytes
    if pair_key in records_dict:
        cache_rec = map(lambda triple: triple[2], records_dict[pair_key])
        if record not in cache_rec:
            records_dict[pair_key].append((datetime.now(), r.ttl, record))
    else:
        records_dict[pair_key] = []
        records_dict[pair_key].append((datetime.now(), r.ttl, record))


def save_data(any_data, p):
    print("data to cache")
    any_packet = Packet()
    any_packet.from_bytes(any_data)
    for r in any_packet.answers:
        add_rec(r)
    for r in p.answers:
        add_rec(r)


def send_once(ip, query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, (ip, 53))
        sock.settimeout(10)
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            print("parent server does not respond")
        else:
            print("got once data")
            return data


def analyze_query(data, query, ip):
    response_code_dict = {
        '0001': 'Format error - The name server was unable to interpret the query',
        '0010': 'Server failure - The name server was unable '
                'to process this query due to a problem with the name server.',
        '0011': 'Name Error - Meaningful only for responses from an authoritative name server, '
               'this code signifies that the domain name referenced in the query doesnot exist',
        '0100': 'Not Implemented - The name server does not support the requested kind of query.',
        '0101': 'Refused - The name server refuses to '
               'perform the specified operation for policy reasons.'
    }
    print("start analysis")
    p = Packet()
    p.from_bytes(data)
    if p.header.response_code != '0000':
        try:
            print(response_code_dict[p.header.response_code])
        except KeyError:
            print("unexpected response code")
    elif p.header.ANCOUNT != 0:
        print("found answer")
        any_query = p.query.get_ANY_query()
        header = query[:12]
        any_data = send_once(ip, header+any_query)
        if any_data:
            save_data(any_data, p)
        return data
    elif p.header.NSCOUNT != 0:
        r = p.ns[0]
        name = Query.get_name(r.data, data)[0]
        if name == ip:
            return data
        return send_query(name, query)
    else:
        print("no suitable nameservers")


def send_query(ip, query):
    print("send query to "+ip)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, (ip, 53))
        sock.settimeout(10)
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            print("parent server does not respond")
        else:
            print("receive data from "+ip)
            return analyze_query(data, query, ip)


def process_all(data):
    print("start processing")
    p = Packet()
    p.from_bytes(data)
    try:
        rec_list = records_dict[(p.query.qname,p.query.qtype_bytes)]
        res = p.header.make_answer(len(rec_list))+\
              p.query.qname_bytes+p.query.qtype_bytes+p.query.qclass
        for record in rec_list:
            res += p.query.qname_bytes+p.query.qtype_bytes+p.query.qclass + record[2]
        print("answer from cache")
        return res
    except KeyError:
        print("no answer in cache")
        root = 'a.root-servers.net'
        res = send_query(root, data)
        return res


def serialize():
    with open('storage.txt','wb') as fp:
        pickle.dump(records_dict, fp)


def get_loop():
    global records_dict
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((ip, port))
        try:
            while True:
                sock.settimeout(0.001)
                try:
                    data, addr = sock.recvfrom(512)
                except socket.timeout:
                    pass
                else:
                    print()
                    print("got data")
                    records_dict = filter_dict(records_dict)
                    ans = process_all(data)
                    if ans:
                        print("send answer")
                        print(str(sock.sendto(ans, addr))+" bytes sent")
        except KeyboardInterrupt:
            print("you exited dns with Ctrl+C")
            print("try serializing data")
            try:
                serialize()
                print("serialized successfully")
            except Exception:
                pass


def filter_dict(diction):
    current_time = datetime.now()
    n_dict = dict()
    for (key, value) in diction.items():
        a = all(map(lambda v:(current_time-v[0]).total_seconds()<v[1], value))
        if a:
            n_dict[key] = value
    return n_dict


if __name__ == '__main__':
    global records_dict
    r_dict = {}
    target = 'storage.txt'
    if os.path.getsize(target) > 0:
        with open(target,'rb') as fp:
            r_dict = pickle.load(fp)
    records_dict = filter_dict(r_dict)
    get_loop()
