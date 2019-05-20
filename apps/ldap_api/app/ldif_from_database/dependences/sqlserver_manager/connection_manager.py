import sys
import pyodbc
import yaml
import ftplib
from tqdm import tqdm
from time import sleep

class ConnectionManager:
    """Handler of the sql server connection"""

    def __init__(self, config_yml_path):
        with open(config_yml_path, 'r') as stream:
            try:
                self._config_obj = yaml.safe_load(stream)
                self.__connect()
            except yaml.YAMLError:
                perror('Error while parsing the config yml file in ConnectionManager!')

    def __connect(self):
        """Get sql server connection from config file"""

        # try:
        server_addr = self._config_obj['sql_server']['connection_string']['server'][0]

        if server_addr == "":
            perror('Invalid server address in config file!')

        self._connection = pyodbc.connect('Driver={ODBC Driver 13 for SQL Server};'
                                            'Server={'+server_addr+'};'
                                            'Trusted_Connection=yes;',
                                            autocommit=True)
        self._cursor = self._connection.cursor()
        # except Exception:
        #     perror('Error while connecting to the sql server!')

    def restore(self):
        """Restore .bak file to sql server"""
        try:
            bak_source = self._config_obj['sql_server']['restore_query']['bak_source'][0]
            path = 'Assets/'
            filename = 'Nomina.bak'

            ftp = ftplib.FTP("10.6.34.138") 
            ftp.login(user="dirunico", passwd="d1run1c0*") 
            ftp.cwd(path)
            total=ftp.size(filename)
            pbar=tqdm(total=total)
            def progress(data):
                with open(bak_source, 'wb').write as fp:
                    fp.write(data)
                    pbar.update(len(data))
            ftp.retrbinary("RETR " + filename, open(bak_source, 'wb').write, callback)
            ftp.quit()
        except Exception:
            perror('Error while fetching database from ftp!')

        try:
            data_destination = self._config_obj['sql_server']['restore_query']['data_destination'][0]
            logs_destination = self._config_obj['sql_server']['restore_query']['logs_destination'][0]

            if bak_source == "" or data_destination == "" or logs_destination == "":
                perror('Invalid destinations paths in config file!')

            sql = r"""RESTORE DATABASE [Nomina_UH] FROM  DISK = N'""" + bak_source + """' WITH  FILE = 1,
                    MOVE N'AssetsNomina_Data' TO N'""" + data_destination + """',
                    MOVE N'AssetsNomina_Log' TO N'""" + logs_destination + """',
                    NOUNLOAD,  STATS = 5"""

            cursor = self.execute_sql_query(sql)

            # Wait until database restoration completes
            print("Restoring database...")
            spinner = spinning_cursor()
            while cursor.nextset():
                sys.stdout.write(next(spinner))
                sys.stdout.flush()
                sleep(0.1)
                sys.stdout.write('\b')
            print("Database restoration complete!")
        except Exception:
            perror('Error while restoring database!')

    def execute_sql_query(self, sql_query):
        self._cursor.execute(sql_query)
        return self._cursor


def perror(msg, exit_status=1):
    print(msg)
    exit(exit_status)

def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

if __name__ == "__main__":
    connection_handler = ConnectionManager("config.yml")
    connection_handler.restore()
    cursor = connection_handler.execute_sql_query(
        'SELECT * FROM Nomina_UH.dbo.Empleados_Gral')
    print(next(cursor))