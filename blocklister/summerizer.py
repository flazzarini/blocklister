import socket
import struct


def dottedQuadToNum(ip):
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def numToDottedQuad(n):
    return socket.inet_ntoa(struct.pack('!L', n))


def buildRange(start, end):
    starttxt = numToDottedQuad(start)
    if (start == end):
        return starttxt
    endtxt = numToDottedQuad(end)
    return "{}-{}".format(starttxt, endtxt)


class Summerizer(object):
    """Given a list of IPs, summarize them into smaller groups"""
    def __init__(self, ips):
        new_iplist = [self.individualize(x) for x in ips]
        ip_list = [x for y in new_iplist for x in y]

        # Convert into a sorted list of uniques
        ip_set = set(ip_list)
        self.ip_list = list(ip_set)
        self.ip_list.sort()

        self.range = [buildRange(x[0], x[1]) for x in self.find_ranges()]

    def summary(self):
        return self.range

    def individualize(self, entry):
        if '-' not in entry:
            return [dottedQuadToNum(entry)]

        # Split into start and end, removing all whitespace
        entry_nows = ''.join(entry.split())
        start, end = entry_nows.split('-')

        # Convert to integers
        start_dec = dottedQuadToNum(start)
        end_dec = dottedQuadToNum(end)

        # If the entries are not an easy range, fix that
        if (start_dec > end_dec):
            start_dec, end_dec = end_dec, start_dec

        # Return a new list
        return [x for x in range(start_dec, end_dec + 1)]

    def find_ranges(self):
        rangelist = []
        rangestart = self.ip_list[0]
        rangeend = rangestart
        for x in self.ip_list[1:]:
            if x == (rangeend + 1):
                rangeend = x
                continue
            rangelist.append((rangestart, rangeend))
            rangestart = x
            rangeend = x
        rangelist.append((rangestart, rangeend))
        return rangelist
