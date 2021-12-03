#!/usr/bin/env python
import time
import socket
import struct
import select
import random
import asyncore

ICMP_ECHO_REQUEST = 8

ICMP_CODE = socket.getprotobyname('icmp')
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
    }

__all__ = ['create_packet', 'do_one', 'verbose_ping', 'PingQuery',
           'multi_ping_query']


def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1])*256+ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(id):
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = 192 * 'Q'
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
                         socket.htons(my_checksum), id, 1)
    return header + data


def do_one(dest_addr, timeout=1):
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except socket.error, (errno, msg):
        if errno in ERROR_DESCR:
            raise socket.error(''.join((msg, ERROR_DESCR[errno])))
        raise
    try:
        host = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return
    packet_id = int((id(timeout) * random.random()) / 65535)
    packet = create_packet(packet_id)
    while packet:
        sent = my_socket.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]
    delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return delay


def receive_ping(my_socket, packet_id, time_sent, timeout):
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []: # Timeout
            return
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack(
            'bbHHh', icmp_header)
        if p_id == packet_id:
            return time_received - time_sent
        time_left -= time_received - time_sent
        if time_left <= 0:
            return


def verbose_ping(dest_addr, timeout=2, count=4):
    for i in xrange(count):
        print 'ping {}...'.format(dest_addr),
        delay = do_one(dest_addr, timeout)
        if delay == None:
            print 'failed. (Timeout within {} seconds.)'.format(timeout)
        else:
            delay = round(delay * 1000.0, 4)
            print 'get ping in {} milliseconds.'.format(delay)
    print


class PingQuery(asyncore.dispatcher):
    def __init__(self, host, p_id, timeout=0.5, ignore_errors=False):
        asyncore.dispatcher.__init__(self)
        try:
            self.create_socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        except socket.error, (errno, msg):
            if errno in ERROR_DESCR:
                raise socket.error(''.join((msg, ERROR_DESCR[errno])))
            raise
        self.time_received = 0
        self.time_sent = 0
        self.timeout = timeout

        self.packet_id = int((id(timeout) / p_id) / 65535)
        self.host = host
        self.packet = create_packet(self.packet_id)
        if ignore_errors:
            self.handle_error = self.do_not_handle_errors
            self.handle_expt = self.do_not_handle_errors

    def writable(self):
        return self.time_sent == 0

    def handle_write(self):
        self.time_sent = time.time()
        while self.packet:
            sent = self.sendto(self.packet, (self.host, 1))
            self.packet = self.packet[sent:]

    def readable(self):
        if (not self.writable()
            and self.timeout < (time.time() - self.time_sent)):
            self.close()
            return False
        return not self.writable()

    def handle_read(self):
        read_time = time.time()
        packet, addr = self.recvfrom(1024)
        header = packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack("bbHHh", header)
        if p_id == self.packet_id:
            self.time_received = read_time
            self.close()

    def get_result(self):
        if self.time_received > 0:
            return self.time_received - self.time_sent

    def get_host(self):
        return self.host

    def do_not_handle_errors(self):
        pass

    def create_socket(self, family, type, proto):
        sock = socket.socket(family, type, proto)
        sock.setblocking(0)
        self.set_socket(sock)
        self.family_and_type = family, type

    def handle_connect(self):
        pass

    def handle_accept(self):
        pass

    def handle_close(self):
        self.close()


def multi_ping_query(hosts, timeout=1, step=512, ignore_errors=False):
    results, host_list, id = {}, [], 0
    for host in hosts:
        try:
            host_list.append(socket.gethostbyname(host))
        except socket.gaierror:
            results[host] = None
    while host_list:
        sock_list = []
        for ip in host_list[:step]:
            id += 1
            sock_list.append(PingQuery(ip, id, timeout, ignore_errors))
            host_list.remove(ip)
        asyncore.loop(timeout)
        for sock in sock_list:
            results[sock.get_host()] = sock.get_result()
    return results


if __name__ == '__main__':
    verbose_ping('www.heise.de')
    verbose_ping('google.com')
    verbose_ping('an-invalid-test-url.com')
    verbose_ping('127.0.0.1')
    host_list = ['www.heise.de', 'google.com', '127.0.0.1',
                 'an-invalid-test-url.com']
    for host, ping in multi_ping_query(host_list).iteritems():
        print host, '=', ping
