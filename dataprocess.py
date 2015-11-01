import re

class SyslogRecog(object):
    def __init__(self):
        '''
        Interface for recognition of syslog. Recognize the corresponding device file name.
        '''
        self.recog_info = {}
        self.recog_ip_info = {}
        
    def set_driver(self, driver):
        self.driver = driver

    def set_recog_info(self):
        self.recog_info = self.driver.get_recog_info()

    def get_recog_info(self):
        return self.recog_info
    
    def recognize(self, s, recog_info):
        '''
        Return list named header_result_list or tag_result_list.
        >>> recognize(s="<8>Apr  1 14:34:23 SystemMgr: [2015-04-01", recog_info={'firewall_syslog.xml':{'header_re':'re', 'tag_re':'re'}, 'cisco_asa.xml':{'header_re':'re', 'tag_re':'re'},....})
        >>> ["firewall_syslog.xml"]
        ....
        >>> recognize("adsfafd", recog_info)
        >>> None
        '''
        header_result_list = []
        tag_result_list = []
        for logfile_name in recog_info.keys():
            header_tag_re = recog_info[logfile_name]
            header_re = header_tag_re['header_re']
            header_compile = re.compile(header_re)
            header_result = header_compile.search(s)
            if header_result:
                header_result_list.append(logfile_name)
        if len(header_result_list) == 1:
            return header_result_list
        elif len(header_result_list) == 0:
            return None
        else:
            for logfile_name in header_result_list:
                header_tag_re = recog_info[logfile_name]
                tag_re = header_tag_re['tag_re']
                tag_compile = re.compile(tag_re)
                tag_result = tag_compile.search(s)
                if tag_result:
                    tag_result_list.append(logfile_name)
            return tag_result_list

class SyslogParsing(object):
    '''
    Each SyslogParsing represents a device file(*.xml)'s parsing process
    Using a dict to store the instances of SyslogParsing:
    >>> parsing[dev_file_name] = SyslogParsing(dev_file_name)
    >>> parsing[dev_file_name].parse(s, recog_info)
    >>> {'pri':187, 'datetime':'Mar 23 10:21:03', 'facility':'PIX', 'serverity':4,'mnemonic':106023, 'content':'description'}
    '''
    def __init__(self, dev_file_name):
        '''
        Corresponding to a specified device file.
        '''
        self.dev_file_name = dev_file_name
        self.parsing_info = {}
        
    def set_driver(self, driver):
        self.driver = driver

    def set_parsing_info(self):
        self.parsing_info = self.driver.get_parsing_info(self.dev_file_name)

    def get_parsing_info(self):
        return self.parsing_info

    def re_split(self, pattern, s):
        '''
        Capture one string from s, and split s into captrured pattern and the left.
        Notice that we permit ONLY ONE or NONE capturing group!
        >>> re_split('what', 'whats that. whats your name')
        >>> ('what', 's that. whats your name')
        >>> re_split('nothing', 'whats that. whats your name')
        >>> ('', 'whats that. whats your name')
        ...
        Pay attention to add "?:" in the perenthesis wich we don't want to capture.
        >>> re_split('what(?:s)? (that)', 'whats that. whats your name')
        >>> ('that', 'whats . whats your name')
        '''
        prog = re.compile(pattern)
        result = prog.search(s)
        if result:
            groups_len = len(result.groups())
            # groups_len <= 1
            # Using the groups_len to simplify the code.
            s_splited = result.group(groups_len)
            s_left = s[:result.start(groups_len)] + s[result.end(groups_len):]
            return (s_splited, s_left)
        return ('', s)

    def re_not_split(self, patter, s):
        '''
        Because of the difficulty of writing RE expression for re_split(), an alternative is that retaining s.
        >>> re_not_split('what', 'whats that. whats your name')
        >>> ('what', 'whats that. whats your name')
        >>> re_not_split('nothing', 'whats that. whats your name')
        >>> ('', 'whats that. whats your name')
        '''
        pass
        
    def parse(self, s, recog_info):
        '''
        >>> parse('<187>Mar 23 10:21:03 %PIX-4-106023 description', 'cisco_asa.xml', recog_info)
        >>> {'pri':187, 'datetime':'Mar 23 10:21:03', 'facility':'PIX', 'serverity':4,'mnemonic':106023, 'content':'description'}
        '''
        parse_result = {}

        #split syslog into header, tag, content, by invoking re_split.
        header_re = recog_info[self.dev_file_name]['header_re']
        tag_re = recog_info[self.dev_file_name]['tag_re']
        header, s_elimi_header = self.re_split(header_re, s)
        tag, content = self.re_split(tag_re, s_elimi_header)

        # For accelerating
        header_parsing_info = self.parsing_info['header']
        tag_parsing_info = self.parsing_info['tag']
        content_parsing_info = self.parsing_info['content']

        # Parse header portion
        for attr_name in header_parsing_info.keys():
            attr_re = header_parsing_info[attr_name]['re']
            attr, header = self.re_split(attr_re, header)
            parse_result[attr_name] = attr

        # Parse tag portion
        for attr_name in tag_parsing_info.keys():
            attr_re = tag_parsing_info[attr_name]['re']
            attr, tag = self.re_split(attr_re, tag)
            parse_result[attr_name] = attr
        
        # Parse content portion.
        for attr_name in content_parsing_info.keys():
            if content_parsing_info[attr_name]['re'] and not content_parsing_info[attr_name]['upper_attr']:
                attr_re = content_parsing_info[attr_name]['re']
                attr, content = self.re_split(attr_re, content)
                if attr:
                    parse_result[attr_name] = attr
                    self._parse_subobject(content_parsing_info, attr, attr_name, parse_result)
        return parse_result

    def _parse_subobject(self, parsing_info, s, upper_attr_name, parse_result):
        # Traverse the attributes tree(parsing_info), in depth first, preorder way.
        for attr_name in parsing_info.keys():
            if parsing_info[attr_name]['re'] and parsing_info[attr_name]['upper_attr']:
                if parsing_info[attr_name]['upper_attr'] == upper_attr_name:
                    #print(attr_name)
                    attr_re = parsing_info[attr_name]['re']
                    attr, s = self.re_split(attr_re, s)
                    if attr:
                        parse_result[attr_name] = attr
                        self._parse_subobject(parsing_info, attr, attr_name, parse_result)

class SyslogStore(object):
    def __init__(self, dev_file_name):
        '''
        Corresponding to a specified device file.
        '''
        self.dev_file_name = dev_file_name
        self.storage_info = {}
        
    def set_driver(self, driver):
        self.driver = driver

    def set_storage_info(self):
        self.storage_info = self.driver.get_storage_info(self.dev_file_name)

    def get_storage_info(self):
        return self.storage_info

    def store_syslog(self, parsing_result):
        '''
        Store the parsing result into db.
        '''
        store_result = self.driver.store(parsing_result, self.storage_info)
        return store_result


if __name__ == '__main__':
    from datetime import datetime
    from dbm import DBManager
    from datadriver import SyslogDriver
    from random import random 
    DB_NAME = 'icsmonitor'
    dbconfig = {
        'user': 'guest',
        'password': 'guest',
        'host': '127.0.0.1',
        'raise_on_warnings': True,
    }
    db = DBManager()
    db.connect(**dbconfig)
    db.set_db(DB_NAME)
    syslogdriver = SyslogDriver()
    syslogdriver.set_db(db)

    s_cisco1 = '<23>Mar 23 10:21:03 %ASA-4-106023 Deny ICMP reverse path check from 192.168.150.60 to 192.168.2.1 on interface outside'
    s_cisco2 = '''<187>Mar 23 10:21:03 %PIX-4-106023 Deny tcp src outside:192.168.208.63/5535 dst inside:192.168.150.77/256 by access-group "OUTSIDE" [0x5063b82f, 0x0]'''
    s_huacon = '''<13>Apr  1 14:34:23 SystemMgr: [2015-04-01 14:34:23.48][Emerg][User][ISG-A002G][ID!][change]system error, code:1762'''
    
    recog = SyslogRecog()
    recog.set_driver(syslogdriver)
    recog.set_recog_info()
    recog_info = recog.get_recog_info()
    #print(recog_info)
    #dev_file_name, = recog.recognize(s, recog_info)
    #print(dev_file_name)

    dev_file_names = ['cisco_asa.xml', 'firewall_syslog.xml', 'netscreen.xml']
    parsing = {}
    #parsing[dev_file_name] = SyslogParsing(dev_file_name)
    #parsing[dev_file_name].set_driver(syslogdriver)
    #parsing[dev_file_name].set_parsing_info()
    #print(parsing[dev_file_name].get_parsing_info())
    for dev_file_name in dev_file_names:
        parsing[dev_file_name] = SyslogParsing(dev_file_name)
        parsing[dev_file_name].set_driver(syslogdriver)
        parsing[dev_file_name].set_parsing_info()
    before_parsing = datetime.now()
    parse_result_huacon = parsing['firewall_syslog.xml'].parse(s_huacon, recog_info)
    parse_result_cisco1 = parsing['cisco_asa.xml'].parse(s_cisco1, recog_info)
    parse_result_cisco2 = parsing['cisco_asa.xml'].parse(s_cisco2, recog_info)
    arfter_parsing = datetime.now()
    print(s_huacon)
    for attr_name in parse_result_huacon.keys():
        print("    {0}: {1}".format(attr_name, parse_result_huacon[attr_name]))
    print(s_cisco1)
    for attr_name in parse_result_cisco1.keys():
        print("    {0}: {1}".format(attr_name, parse_result_cisco1[attr_name]))
    print(s_cisco2)
    for attr_name in parse_result_cisco2.keys():
        print("    {0}: {1}".format(attr_name, parse_result_cisco2[attr_name]))
    #print(parse_result)
    print("cost: ", arfter_parsing - before_parsing)
    db.disconnect()
