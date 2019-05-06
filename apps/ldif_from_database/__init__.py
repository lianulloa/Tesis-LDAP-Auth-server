import yaml
from dependences.sqlserver_manager import ConnectionManager


class LDIFFromSQLServer:
    """Encapsulation for methods wich populate and modify the ldap server
    from a sql server databas."""

    def __init__(self, config_yml_path):
        """Receives the path to the config file"""
        self.connection_handler = ConnectionManager(config_yml_path)
        with open(config_yml_path, 'r') as stream:
            try:
                config_obj = yaml.safe_load(stream)
                self.__workers_schema = config_obj["workers_schema"]
            except yaml.YAMLError:
                perror('Error while parsing the config yml file in LDIFFromSQLServer!')

    def generate_first_time_population(self, restore=False, number_of_rows=0):
        """Generates the ldif file from the database to populate the ldap
        for the first time overriding existing data.
        The optional second parameter defines wheter the database is restored or not.
        The third parameter is for testing and should be ignored."""
        if restore:
            self.connection_handler.restore()
        cursor = self.connection_handler.execute_sql_query(
            'SELECT No_CI, Nombre, Sexo, Apellido_1, Apellido_2, Desc_Cargo, Desc_Direccion '
            'FROM ((Nomina_UH.dbo.Empleados_Gral e '
            'INNER JOIN Nomina_UH.dbo.RH_Cargos g ON g.Id_Cargo = e.Id_Cargo) '
            'INNER JOIN Nomina_UH.dbo.RH_Plantilla_Plazas p '
            'ON g.Id_Cargo = p.Id_Cargo and e.Id_Direccion = p.Id_Direccion) '
            'INNER JOIN Nomina_UH.dbo.RH_Plantilla r '
            'ON r.Id_Direccion = p.Id_Direccion '
            'GROUP BY No_CI, Nombre, Sexo, Apellido_1, Apellido_2, Desc_Cargo, Desc_Direccion')

        with open("./output/workers.ldif", "w+") as f:
            row_number = 1
            uidNumber = 5000
            # Limited count ?
            if number_of_rows > 0:
                rows_left = number_of_rows
                for row in cursor:
                    self.__process_row(row, f, row_number, uidNumber)
                    row_number += 1
                    rows_left -= 1
                    if rows_left == 0:
                        break
                    uidNumber+=1
            else:
                for row in cursor:
                    self.__process_row(row, f, row_number, uidNumber)
                    row_number += 1
                    uidNumber+=1

    def generate_modify_population(self):
        """Generates the ldif file from the database to modify
        the ldap keeping unmodified data untouched."""
        raise NotImplementedError

    def __process_row(self, row, open_file, row_number, uidNumber):
        open_file.write("# Entry %d: \n" % row_number)
        for entry in self.__workers_schema:
            if type(entry[1]) == list:
                open_file.write("%s: %s\n" % (entry[0], ' '.join([str(row[x]) for x in entry[1]])))
            else:
                open_file.write("%s: %s\n" % (entry[0], str(row[entry[1]])))
        
        # Entries outside the database
        open_file.write("%s: %s\n" % ('dn: ', 'Trabajador'))
        open_file.write("%s: %s\n" % ('objectclass: ', 'Trabajador'))
        open_file.write("%s: %s\n" % ('objectclass: ', 'posixAccount'))
        open_file.write("%s: %s\n" % ('objectclass: ', 'shadowAccount'))
        open_file.write("%s: %d\n" % ('uidNumber: ', uidNumber))
        open_file.write("%s: %d\n" % ('gidNumber: ', 10000))
        open_file.write("%s: %s\n" % ('homeDirectory: ', '---------'))
        open_file.write("%s: %d\n" % ('uid: ', uidNumber))
        open_file.write("%s: %s\n" % ('correo: ', '---------'))

        open_file.write("\n")
        pass


def perror(msg, exit_status=1):
    print(msg)
    exit(exit_status)


if __name__ == "__main__":
    handler = LDIFFromSQLServer("config.yml")
    handler.generate_first_time_population(number_of_rows=4)
