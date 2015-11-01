

select_recog_info = ("select syslog_recognition.dev_file_name, header_re, tag_re from \
    syslog_recognition join device_file on syslog_recognition.dev_file_name =  device_file.dev_file_name")
select_parsing_info = (" SELECT * FROM syslog_attr where dev_file_name=%s order by attr_order")
select_storage_info = (" SELECT attr_name, map FROM syslog_attr where dev_file_name=%s ")
select_subjection = (" SELECT attr_name, upper_attr_name FROM syslog_attr_subjection where dev_file_name=%s")
select_recog_ip_info = (" SELECT ip_addr, dev_file_name FROM ip_dev_file")
insert_standard_attr_template = ( "INSERT INTO standard_attr ({0}) VALUE ({1})" )
insert_ip_dev_file = ( "INSERT INTO ip_dev_file (ip_addr, dev_file_name) VALUE (%s, %s)" )

class SyslogDriver(object):
    '''
    classdocs
    '''
    def __init__(self):
        '''
        Constructor
        '''
        self.db = None

        # Two interfaces are offered to upper layer: recog_info, parsing_info:
        #{'firewall_syslog.xml':{'header_re':'re', 'tag_re':'re'}, 'cisco_asa.xml':{'header_re':'re', 'tag_re':'re'},....}
        #self.recog_info = {}

        #{'header': {datetime:{'re':'\w+', 'map':'occurTime', 'upper_attr':None}, }, 'tag':{}, 'content':{}}
        #self.parsing_info = {}
        
    def set_db(self, db):
        self.db = db
        
    def get_parsing_info(self, dev_file_name):
        '''
        >>> get_parsing_info('cisco_asa.xml')
        >>> {'header': {datetime:{'re':'\w+', 'map':'occurTime'}, }, 'tag':{}, 'content':{}}
        '''
        header_attr = []
        tag_attr = []
        content_attr = []
        header_dict = {}
        tag_dict = {}
        content_dict = {}
        parsing_info = {}
        cursor = self.db.select_table_where(select_parsing_info, (dev_file_name, ))
        for (dev_file_name, attr_name, sql_attr_type, attr_order, field, attr_map, re) in cursor:
            if field == 'header':
                header_attr.append(attr_name)
                header_dict[attr_name] = {'re':re, 'map':attr_map, 'upper_attr':None}
            if field == 'tag':
                tag_attr.append(attr_name)
                tag_dict[attr_name] = {'re':re, 'map':attr_map, 'upper_attr':None}
            if field == 'content':
                content_attr.append(attr_name)
                content_dict[attr_name] = {'re':re, 'map':attr_map, 'upper_attr':None}
        parsing_info['header'] = header_dict
        parsing_info['tag'] = tag_dict
        parsing_info['content'] = content_dict
        self.db.commit()
        cursor = self.db.select_table_where(select_subjection, (dev_file_name, ))
        for (attr_name, upper_attr_name) in cursor:
            for field_name in parsing_info.keys():
                # go easy from three layer loop and comparision.
                try:
                    parsing_info[field_name][attr_name].update({'upper_attr':upper_attr_name})
                except KeyError:
                    continue
        return parsing_info

    def get_all_parsing_info(self):
        '''
        Get all parsing infomation for every device file, return a dict.
        >>> get_all_parsing_info()
        >>> {'cisco_asa.xml': parsing_info, 'netscrenn.xml':parsing_info}
        '''
        pass

    def get_storage_info(self, dev_file_name):
        '''
        Get storage information, a map of attr_name to standard_attr.
        >>> get_storage_info('cisco_asa.xml')
        >>> {'acl_deny': 'msg', 'acl_deny_sip': 'sip', 'content': 'msg', 'serverity': 'oriPriority',...
        '''
        storage_info = {}
        cursor = self.db.select_table_where(select_storage_info, (dev_file_name, ))
        for (attr_name, standard_attr) in cursor:
            storage_info[attr_name] = standard_attr
        return storage_info
    
    def get_recog_info(self):
        '''
        >>> get_recog_info()
        >>> {'firewall_syslog.xml':{'header_re':'re', 'tag_re':'re'}, 'cisco_asa.xml':{'header_re':'re', 'tag_re':'re'},....}
        '''
        recog_info = {}
        cursor = self.db.select_table(select_recog_info)
        for (dev_file_name, header_re, tag_re) in cursor:
            recog_info[dev_file_name] = {'header_re':header_re, 'tag_re':tag_re}
        self.db.commit()
        return recog_info

    def store(self, parsing_result, storage_info):
        '''
        >>> store({'serverity':4, 'icmp_deny_dip': '192.168.2.1'}, {'content': 'msg', 'serverity': 'oriPriority',...})
        >>> True
        '''
        standard_attrs_names = []
        standard_attrs = []
        attr_num = 0
        for attr_name in parsing_result.keys():
            try:
                standard_attr = storage_info[attr_name]
                standard_attrs_names.append(standard_attr)
                standard_attrs.append(parsing_result[attr_name])
                attr_num += 1
            except KeyError:
                print("Couldn't map the attribute: {0}".format(attr_name))
                continue
        # Generate INSERT statement from standard_attrs_names.
        table_format_value = ', '.join(standard_attrs_names)
        table_format_value_s = ', '.join(['%s'] * attr_num)
        insert_standard_attr = insert_standard_attr_template.format(table_format_value, table_format_value_s)
        self.db.insert_table(insert_standard_attr, tuple(standard_attrs))
        return True

class SnmpDriver(object):
    '''
    classdocs
    '''
    def __init__(self):
        '''
        Constructor
        '''
        pass

if __name__ == '__main__':
    from dbm import DBManager
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
    dv = SyslogDriver()
    dv.set_db(db)
    recog_info = dv.get_recog_info()
    #print(recog_info)
    parsing_info = dv.get_parsing_info('cisco_asa.xml')
    for field_name in parsing_info.keys():
        for object_name in parsing_info[field_name].keys():
            print("{0}: {1}".format(object_name, parsing_info[field_name][object_name]))
    storage_info = dv.get_storage_info('cisco_asa.xml')
    print(storage_info)
    storage_result = dv.store({'serverity':4}, storage_info)
    print(storage_result)
    db.disconnect()
    


    
