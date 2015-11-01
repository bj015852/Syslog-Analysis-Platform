import mysql.connector as mysql
from mysql.connector import errorcode

class DBManager(object):
    '''
    classdocs
    '''
    def __init__(self):
        '''
        Constructor
        '''
        self.cursor = None
        self.cnx = None
        self.tables = []
        self.table_names = []
        print("DB initializing...")
        
    def connect(self, *args, **kwargs):
        self.cnx = mysql.connect(**kwargs)
        self.cursor = self.cnx.cursor()
        return (self.cursor, self.cnx)

    def disconnect(self):
        self.cnx.commit()
        self.cursor.close()
        self.cnx.close()
        print("disconnect database")
        
    def set_db(self, db_name = 'icsmonitor'):
        try:
            print("    Connect to DB: {0}".format(db_name))
            self.cnx.database = db_name
        except mysql.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print( "    Wrong name or password." )
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("    Database {0} doesn't exist.".format(db_name))
                print("        Create database {0}".format(db_name) )
                self.create_db(db_name)
            else:
                print(err)
                exit(1)
                
    def create_db(self, db_name = 'icsmonitor'):
        try:
            self.cursor.execute( "CREATE DATABASE {0} DEFAULT CHARACTER SET 'utf8'".format(db_name) )
            self.cnx.commit()
            self.set_db(db_name)
        except mysql.Error as err:
            print("Failing create database: {0}, error: {1}.".format(db_name, err))
            exit(1)
            
    def add_tables(self, table_names, tables):
        self.table_names = table_names
        self.tables = tables
        
    def drop_tables(self):
        for name in reversed(self.table_names):
            try:
                print('    DROP TABLE {0}'.format(name))
                self.cursor.execute( "DROP TABLE {0}".format(name) )
                self.cnx.commit()
            except mysql.Error as err:
                if err.errno == errorcode.ER_BAD_TABLE_ERROR:
                    print("        Table {0} doesn't exit.".format(name))
                    continue
                else:
                    print("error: {0}".format(err))
                    
    def create_tables(self):
        for name in self.table_names:
            try:
                print("    CREATING TABLE {0}: ".format(name), end='')
                self.cursor.execute(self.tables[name])
                self.cnx.commit()
            except mysql.Error as err:
                if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                    print("    already exists.")
                else:
                    print("    No.", err.msg)
            else:
                print(' \tOk.')

    def create_table(self, create_statement):
        try:
            self.cursor.execute(create_statement)
        except mysql.Error as err:
            if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                print("    TABLE already exists")
                exit(0)
            else:
                print(err.msg)
                
    def drop_table_than_create(self, create_statement, table_name):
        '''
        drop a table if it exists and then create it
        '''
        try:
            self.cursor.execute(create_statement)
        except mysql.Error as err:
            if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                try:
                    print('    DROP TABLE {0}'.format(table_name), end='')
                    self.drop_table("DROP TABLE {0}".format(table_name))
                except mysql.Error as err:
                    print("error: {0}".format(err))
                    exit(0)
                else:
                    print("    CREATING TABLE {0}: ".format(table_name))
                    self.create_table(create_statement)
            else:
                print(err.msg)

    def drop_table(self, drop_statement):
        self.cursor.execute(drop_statement)
                
    def insert_table(self, insert_statement, attr_tuple):
        self.cursor.execute(insert_statement, attr_tuple)

    def update_table(self, update_statement, attr_tuple):
        self.cursor.execute(update_statement, attr_tuple)

    def select_table(self, select_statement):
        self.cursor.execute(select_statement)
        return self.cursor

    def select_table_where(self, select_statement, where_clause):
        self.cursor.execute(select_statement, where_clause)
        return self.cursor

    def commit(self):
        self.cnx.commit()


if __name__ == '__main__':
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


    db.disconnect()
