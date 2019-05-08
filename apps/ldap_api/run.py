from app import app, config, utils
from pymemcache.client import base

import os
import ldap
# Configuraciones según el entorno
configuration = config.set_environment(os.getenv("LDAP_API_ENVIRONMENT"))

ldap_server = ldap.initialize(configuration.LDAP_SERVER_URI,
                trace_level=utils.DEBUG_LEVEL[configuration.PYTHON_LDAP_DEBUG_LVL])


if __name__ == '__main__':
    students_uidNumber = ldap_server.search_s("ou=Estudiantes,dc=uh,dc=cu", ldap.SCOPE_SUBTREE, "(&(uidNumber=*)(objectclass=Estudiante))",attrlist=['uidNumber'])
    students_uidNumber = [ x[1]['uidNumber'][0] for x in students_uidNumber ]
    students_uidNumber.sort(reverse=True)

    higher = students_uidNumber[0]

    externs_uidNumber = ldap_server.search_s("ou=Externos,dc=uh,dc=cu", ldap.SCOPE_SUBTREE, "(&(uidNumber=*)(objectclass=Externo))",attrlist=['uidNumber'])
    externs_uidNumber = [ x[1]['uidNumber'][0] for x in externs_uidNumber ]
    externs_uidNumber.sort(reverse=True)

    if len(externs_uidNumber) and externs_uidNumber[0] > higher :
        higher = externs_uidNumber[0]

    workers_uidNumber = ldap_server.search_s("ou=Trabajadores,dc=uh,dc=cu", ldap.SCOPE_SUBTREE, "(&(uidNumber=*)(objectclass=Trabajador))",attrlist=['uidNumber'])
    workers_uidNumber = [ x[1]['uidNumber'][0] for x in workers_uidNumber ]
    workers_uidNumber.sort(reverse=True)

    if len(workers_uidNumber) and workers_uidNumber[0] > higher :
        higher = workers_uidNumber[0]

    client = base.Client((configuration.MEMCACHED_HOST, 11211))
    client.set('uidNumberCounter',higher)
    
    app.run(port='5000', host="0.0.0.0")
    