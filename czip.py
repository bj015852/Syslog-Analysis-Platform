'''
Created on Feb.26.2015
This module is to query ip geographic information based on chunzhen ip database.
Referenced from the code from http://www.jb51.net/article/27176.htm.
@author: Jidong
@ip database: http://www.cz88.net/

The structrue of QQWry.Dat is as following divided into three regions:
        +-------------+
        | file header | (8 Bytes size)
        +-------------+
        |   records   | (uncertain size)
        +-------------+
        |    index    | (depending on file header)
        +-------------+
All the data is stored in little-endian.
1. file header: 4Bytes of the beginning offset of index followed by 4Bytes of the end offset of index, which determine the index's location.
2. records: ip record entry format ==> [ip address][country info][area info]
    For country info, there are three record types depending on the value of the fifth byte(first byte in country info string) in the ip record:
    1) direct mode: if the fifth byte is unequal to 0x01 nor 0x02,
    the ip record entry contains fully information including country info and area info. In shot, we could read two strings continuously directly.
    2) redirect mode 1: if the fifth byte is 0x01,
    then the next three bytes are redirect info rather than country info and area info. We should query again to get both country and area info by the redirect info.
    3) redirect mode 2: if the fifth byte is 0x02,
    the next three bytes are redirect info and followed by area info. We should query again to get the country info by the redirect info.
3. index: index entry is a seven Bytes size [key][value] format ==> [ip address][record offset]
    After querying the index by ip address, the input argument, we obtain a entry of a three Bytes size value represents the offset in the record region.
'''
import os, sys
import socket
from struct import pack, unpack

class Czip(object):
    def __init__(self, ipdb):
        '''
        Initialized by cz ip database name.
        Binary stream could support some kind of buffering(inherit from io.BufferedIOBase), no decoding, newline.
        '''
        self.ipdb = ipdb
        f = open(ipdb, 'rb')
        self.img = f.read()
        f.close()
        # get the index region and calculate its size. Each entry is seven Bytes size.
        (self.indexstart, self.indexend) = unpack('<II', self.img[:8])
        self.indexcount = (self.indexend - self.indexstart)//7 + 1
        #print('index_start:{0}, index_last:{1}'.format(self.indexstart, self.indexend))
        #print('index size:{0}'.format(self.indexcount))
        
    def get_addr_info(self, ip):
        '''
        Main function, invoking other self.func.
        The input argument is the ip address in string format such as '123.45.67.89'.
        The output is a list contains a pair of country info and area info.
        '''
        ip = unpack('!I', socket.inet_aton(ip))[0]
        # Query the index by ip address, index means the no. of the corresponding entry from 0 to the total size of the index.
        index = self._find_index(ip, 0, self.indexcount - 1)
        # Get the record offset from the index entry in index region by the index. The record offset locates the record entry in the db file.
        # Skip the first four bytes in the index entry which is the ip address.
        indexoffset = self.indexstart + index * 7
        recordoffset = self._get_record_offset(indexoffset + 4)
        # Get the infomation by the record offset.
        # Skip the first four bytes in the record entry which is the ip address.
        [countryinfo, areainfo] = self._get_info_from_record(recordoffset + 4)
        return [countryinfo, areainfo]

    def _get_info_from_record(self, recordoffset):
        # There are three types of record entry storage.
        # The following statement is equivalent to 'ord(self.img[recordoffset]) == 2'
        if self.img[recordoffset] == 1:
            #print('method 2!')
            offsetnew = self._get_record_offset(recordoffset+1)
            return self._get_info_from_record(offsetnew)
        elif self.img[recordoffset] == 2:
            #print('method 3!')
            # modified to a new record offset:
            offsetnew = self._get_record_offset(recordoffset+1)
            countryinfo = self._get_string_from_record(offsetnew)
            recordoffset = recordoffset + 4
            areainfo = self._get_string_from_record(recordoffset)
            return [countryinfo, areainfo]
        else:
            #print('method 1!')
            countryinfo = self._get_string_from_record(recordoffset)
            recordoffset = self.img.find(b'\0', recordoffset) + 1
            areainfo = self._get_string_from_record(recordoffset)
            return [countryinfo, areainfo]

    def _get_string_from_record(self, recordoffset):
        # Get the string information in the record entry. The string is encoded in gb2312.
        #byte = ord(self.img[recordoffset])
        if self.img[recordoffset] == 1 or self.img[recordoffset] == 2:
            recordoffset = self._get_record_offset(recordoffset+1)
            return self._get_string_from_record(recordoffset)
        else:
            # main progress
            record_begin = recordoffset
            record_end = self.img.find(b'\0', record_begin)
            return self.img[record_begin:record_end].decode('gbk')

    def _find_index(self, ip, l, r):
        # Query the index in the index region using dichotomy.
        if r - l <= 1:
            return l
        m = (l + r) // 2
        o = self.indexstart + m * 7
        new_ip = unpack('<I', self.img[o: o+4])[0]
        if ip <= new_ip:
            return self._find_index(ip, l, m)
        else:
            return self._find_index(ip, m, r)

    def _get_record_offset(self, indexoffset):
        # Get the record offset in the index entry by the index offset, which locates the index entry in index region. The record offset locate the record in the db file.
        recordoffset = self.img[indexoffset: indexoffset+3]
        recordoffset = recordoffset + b'\0'
        #print(recordoffset)
        return unpack('<I', recordoffset)[0]

if __name__ == '__main__':
    _localDir=os.path.dirname(__file__)
    _curpath=os.path.normpath(os.path.join(os.getcwd(),_localDir))
    curpath=_curpath
    # Attention to the '\' on Windows or '/' on Linux.
    i = Czip(curpath + '\qqwry.dat')
    print("Test xjtu:")
    [countryinfo, areainfo] = i.get_addr_info('202.117.0.20')

    print(countryinfo, areainfo)
    if len(sys.argv) == 2:
        [countryinfo, areainfo] = i.get_addr_info(sys.argv[1])
        print(sys.argv[1]+': '+countryinfo+areainfo)
