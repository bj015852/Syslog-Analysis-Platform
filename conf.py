import xml.etree.ElementTree as ET

insert_device=("INSERT INTO device (dev_name) VALUE (%s)")
insert_device_file=("INSERT INTO device_file (dev_file_name, dev_name, dev_file_type) VALUE (%s, %s, %s)")
select_device_file = (" SELECT dev_file_name, dev_name, dev_file_type FROM device_file ")
insert_syslog_attr = ("INSERT INTO syslog_attr (dev_file_name, attr_name, sql_attr_type, attr_order, field, map, re) VALUE (%s, %s, %s, %s, %s, %s, %s)")
insert_snmp_attr = ("INSERT INTO snmp_attr (dev_file_name, attr_name, oid) VALUE (%s, %s, %s)")
insert_syslog_recognition = ("INSERT INTO syslog_recognition (dev_file_name, header_re, tag_re, content_type) VALUE (%s, %s, %s, %s)")
insert_syslog_attr_subjection = ("INSERT INTO syslog_attr_subjection (dev_file_name, attr_name, upper_dev_file_name, upper_attr_name) VALUE (%s, %s, %s, %s)")
update_device_file_logtable_name=("UPDATE device_file SET logtable_name = %s WHERE dev_file_name = %s ")

class Config(object):
    '''
    classdocs
    '''
    def __init__(self):
        '''
        Constructor
        '''
        self.conf = ''
        self.db = None
        
    def set_db(self, db):
        self.db = db
        
    def load_conf(self, conf_file_name):
        '''
        Read conf.xml
        Create table device, device_file
        '''
        self.conf = conf_file_name
        tree_device = ET.parse(self.conf)
        root_device = tree_device.getroot()
        for child in root_device:
            if child.tag == "device":
                device_name = child.attrib['name']
                print("    device: {0}".format(device_name))
                self.db.insert_table(insert_device, (device_name,))
                for subchild in child:
                    if subchild.tag == "file":
                        print("        file:{0}, ".format( subchild.attrib["type"]), end='')
                        print(subchild.text)
                        device_file = subchild.text
                        file_type = subchild.attrib["type"]
                        self.db.insert_table(insert_device_file, (device_file, device_name, file_type))
            self.db.commit()

    def load_dev_file_attr(self):
        '''
        Read *.xml
        Create table syslog_attr
        '''
        cursor = self.db.select_table(select_device_file)
        attr_files = {}
        for (file_name, dev_name, file_type) in cursor:
            attr_files[file_name] = file_type
        for (file_name, file_type) in attr_files.items():
            try:
                print("    Read {0}:".format(file_name))
                tree_attr_file = ET.parse(file_name)
                root_attr_file = tree_attr_file.getroot()
            except FileNotFoundError:
                print("        file {0} is not found!".format(file_name))
            else:
                if file_type == 'syslog':
                    global attr_order
                    attr_order = 0
                    def iter_object(current_root, upper_attr_name, field_layer):
                        '''
                        Traverse the object sub-tree recursively.
                        '''
                        attr_name = ''
                        attr_type = ''
                        attr_re =  None
                        attr_map = None
                        for child in current_root:
                            if child.tag == "name":
                                attr_name = child.text
                            if child.tag == "sql_attr_type":
                                attr_type = child.text
                            if child.tag == "re":
                                attr_re =  child.text
                            if child.tag == "map":
                                attr_map =  child.text
                        field = field_layer.tag
                        if upper_attr_name:
                            # If this node is sub_object, rename the sub_attr
                            new_attr_name = upper_attr_name + '_' + attr_name
                        else:
                            new_attr_name = attr_name
                        global attr_order
                        attr_order += 1
                        self.db.insert_table(insert_syslog_attr, (file_name, new_attr_name, attr_type, attr_order, field, attr_map, attr_re))
                        self.db.commit() # We must commit db immediately or the foreign key will be error.
                        print("        {0}, {1}: {2} \tre: {3}".format(attr_order, field, new_attr_name,  attr_re))
                        if upper_attr_name:
                            # sub_object needs to store the relation between it and its father node.
                            print("             belonged in:", upper_attr_name)
                            self.db.insert_table(insert_syslog_attr_subjection, (file_name, new_attr_name, file_name, upper_attr_name))
                            self.db.commit() # We must commit db immediately or the foreign key will be error.
                        for child in current_root:
                            if child.tag == "object":
                                iter_object(child, new_attr_name, field_layer)
                    for field_layer in root_attr_file:
                        for child in field_layer:
                            if child.tag == "object":
                                iter_object(child, None, field_layer)
                    '''
                    # Read only one layer to read object.
                    for field_layer in root_attr_file:
                        for obj_root in field_layer.iter('object'):
                            attr_re =  None
                            attr_map = None
                            for child in obj_root:
                                if child.tag == "name":
                                    attr_name = child.text
                                if child.tag == "sql_attr_type":
                                    attr_type = child.text
                                if child.tag == "re":
                                    attr_re =  child.text
                                if child.tag == "map":
                                    attr_map =  child.text
                            field = field_layer.tag
                            attr_order += 1
                            self.db.insert_table(insert_syslog_attr, (file_name, attr_name, attr_type, attr_order, field, attr_map, attr_re))
                            print("        {0}: {1}".format(field, attr_name))
                    self.db.commit()
                    '''
                elif file_type == 'snmp':
                    for obj_root in tree_attr_file.iter('object'):
                        for child in obj_root:
                            if child.tag == "name":
                                attr_name = child.text
                            if child.tag == "oid":
                                oid = child.text
                        print("        {0}, oid:{1}".format(attr_name, oid))
                        self.db.insert_table(insert_snmp_attr, (file_name, attr_name, oid))
                        self.db.commit()
                        
    def load_syslog_recognition(self):
        '''
        Read *.xml --> header_re, tag_re, content_type etc.
        Create table syslog_recognition
        '''
        cursor = self.db.select_table(select_device_file)
        attr_files = {}
        for (file_name, dev_name, file_type) in cursor:
            attr_files[file_name] = file_type
        for (file_name, file_type) in attr_files.items():
            try:
                print("    Read {0}:".format(file_name), end="")
                tree_attr_file = ET.parse(file_name)
                root_attr_file = tree_attr_file.getroot()
            except FileNotFoundError:
                print("        file {0} is not found!".format(file_name))
            else:
                if file_type == 'syslog':
                    tag_content_separator = ''
                    for child_first_layer in root_attr_file:
                        for child in child_first_layer:
                            if child.tag == "header_re":		#########we still need to add the header_type and tag_type in order to recog further!!
                                header_re = child.text
                            if child.tag == "tag_re":
                                tag_re = child.text
                            if child.tag == "content_type":
                                content_type = child.text
                            if child.tag == "tag_content_separator":
                                tag_content_separator = child.text
                    if tag_content_separator:
                        self.db.insert_table(insert_syslog_recognition, (file_name, header_re, tag_re+"(?={0})".format(tag_content_separator), content_type))
                    else:
                        self.db.insert_table(insert_syslog_recognition, (file_name, header_re, tag_re, content_type))
                    print("    ok")
                    self.db.commit()

    def create_log_tables(self):
        '''
        Create tables to store each log for each device
        file_name + file_type
        '''
        cursor = self.db.select_table(select_device_file)
        attr_files = {}
        attr_files_belong_dev = {}
        for (file_name, dev_name, file_type) in cursor:
            attr_files_belong_dev[file_name] = dev_name.replace(" ", "_")
            attr_files[file_name] = file_type.replace(" ", "_")
        for (file_name, file_type) in attr_files.items():
            if file_type == "syslog":
                newtable_name = attr_files_belong_dev[file_name]+"_"+attr_files[file_name]
                newtable = self._xml_to_create_statement(file_name, newtable_name)
                self.db.drop_table_than_create(newtable, newtable_name)
                self.db.update_table(update_device_file_logtable_name, (newtable_name, file_name))
                self.db.commit()

    def create_standard_log_tables(self):
        newtable_name = "standard_attr"
        newtable = self._xml_to_create_statement("standard_attr.xml", newtable_name)
        self.db.drop_table_than_create(newtable, newtable_name)
        self.db.commit()

    def _xml_to_create_statement(self, file_name, table_name):
        '''
        >>> conf._xml_to_create_statement('Cisco.xml', 'cisco_syslog')
        >>> 'CREATE TABLE cisco_syslog ( pri smallint, datetime varchar(25), ...) ENGINE=InnoDB'
        '''
        base_statement = ( "create table {0} ( {1} ) ENGINE=InnoDB")
        newtable = base_statement.format(table_name, "{0}")
        attr_list = []
        attr_str = ""
        primary_key = ""
        primary_key_list = []
        tree_attr_file = ET.parse(file_name)
        for obj_root in tree_attr_file.iter('object'):
            attr_txt = ""
            for child in obj_root:
                if child.tag == "name":
                    attr_txt = child.text
                if child.tag == "sql_attr_type":
                    attr_txt = attr_txt + " " + child.text
            attr_list.append(attr_txt)
        attr_str = ", ".join(attr_list)
        for obj_root in tree_attr_file.iter('primarykey'):
            for child in obj_root:
                if child.tag == "name":
                    primary_key_list.append(child.text)
        if primary_key_list:
            primary_key = ", ".join(primary_key_list)
            attr_str = attr_str + " , PRIMARY KEY ({0})".format(primary_key)
        newtable = newtable.format(attr_str)
        return newtable

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
    import dbtables
    db.add_tables(dbtables.TABLES_NAME, dbtables.TABLES)
    db.drop_tables()
    db.create_tables()
    conf = Config()
    conf.set_db(db)
    print ("1.Read conf.xml file and insert to deive_file table:")
    conf.load_conf('conf.xml')
    print("2.Create tables for each device:")
    #conf.create_log_tables()
    print("    ignored")
    print("3.Insert every attribute to syslog_attr or snmp_attr:")
    conf.load_dev_file_attr()
    print("4.Read each xml file to load syslog recognition info:")
    conf.load_syslog_recognition()
    print("5.Read standard_attr.xml:")
    conf.create_standard_log_tables()
    db.disconnect()



    
