#!/usr/bin/python3

import ldap

dn = 'cn=admin,dc=ldapserver,dc=uh'
pw = 'ericnordelo'

conn = ldap.initialize('ldap://localhost') 
print(conn.bind_s(dn, pw, ldap.AUTH_SIMPLE))