TABLES_NAME = []
TABLES = {}
TABLES_NAME.append("device")
TABLES['device']=(
    "create table device ("
    " dev_name 				varchar(30), "
    " PRIMARY KEY (dev_name) "
    ") ENGINE=InnoDB")

TABLES_NAME.append("device_file")
TABLES['device_file']=(
    "create table device_file ("
    " dev_file_name 			varchar(30), "
    " dev_name 				varchar(30), "
    " dev_file_type 			varchar(10), "
    " dev_file_attr_num 	    		int, "
    " logtable_name 			varchar(60),"
    " PRIMARY KEY (dev_file_name), "
    " FOREIGN KEY (dev_name) REFERENCES device(dev_name) ON DELETE CASCADE"
    ") ENGINE=InnoDB")

TABLES_NAME.append("syslog_recognition")
TABLES['syslog_recognition']=(
    "create table syslog_recognition ("
    " dev_file_name 			varchar(30), "
    " header_re 			varchar(100), "
    " tag_re 				varchar(50), "
    " content_type 			varchar(10), "
    " PRIMARY KEY (dev_file_name), "
    " FOREIGN KEY (dev_file_name) REFERENCES device_file(dev_file_name) ON DELETE CASCADE"
    ") ENGINE=InnoDB")

TABLES_NAME.append("syslog_attr")
TABLES['syslog_attr']=(
    "create table syslog_attr ("
    " dev_file_name 			varchar(30), "
    " attr_name 			varchar(40), "
    " sql_attr_type 			varchar(20) NOT NULL, "
    " attr_order 				tinyint, "
    " field    			varchar(9)    check (field in ('header', 'tag', 'content')), "
    " map     			varchar(20), "
    " re 				varchar(200), "
    " PRIMARY KEY (dev_file_name, attr_name), "
    " FOREIGN KEY (dev_file_name) REFERENCES device_file(dev_file_name) ON DELETE CASCADE"
    ") ENGINE=InnoDB")

TABLES_NAME.append("snmp_attr")
TABLES['snmp_attr']=(                    
    "create table snmp_attr ("
    " dev_file_name 			varchar(30), "
    " attr_name 			varchar(40), "
    " oid 					varchar(30), "
    " PRIMARY KEY (dev_file_name, attr_name, oid), "
    " FOREIGN KEY (dev_file_name) REFERENCES device_file(dev_file_name) ON DELETE CASCADE"
    ") ENGINE=InnoDB")

TABLES_NAME.append("syslog_attr_subjection")
TABLES['syslog_attr_subjection']=(
    "create table syslog_attr_subjection ("
    " dev_file_name 			varchar(30), "
    " attr_name 			varchar(40), "
    " upper_dev_file_name  	varchar(30), "
    " upper_attr_name   		varchar(40),  "
    " PRIMARY KEY (dev_file_name, attr_name, upper_dev_file_name, upper_attr_name), "
    " FOREIGN KEY (dev_file_name, attr_name) REFERENCES syslog_attr(dev_file_name, attr_name) ON DELETE CASCADE, "
    " FOREIGN KEY (upper_dev_file_name, upper_attr_name) REFERENCES syslog_attr(dev_file_name, attr_name) ON DELETE CASCADE"
    ") ENGINE=InnoDB")

TABLES_NAME.append("ip")
TABLES['ip']=(
    "create table ip ("
    " ip_addr 			varchar(15), "
    " PRIMARY KEY (ip_addr) "
    ") ENGINE=InnoDB")

TABLES_NAME.append("ip_device")
TABLES['ip_device']=(
    "create table ip_device ("
    " ip_addr 			varchar(15), "
    " dev_name 			varchar(30), "
    " PRIMARY KEY (ip_addr, dev_name), "
    " FOREIGN KEY (ip_addr) REFERENCES ip(ip_addr) ON DELETE CASCADE, "
    " FOREIGN KEY (dev_name) REFERENCES device(dev_name) ON DELETE CASCADE"
    ") ENGINE=InnoDB")



