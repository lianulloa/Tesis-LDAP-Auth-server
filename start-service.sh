#!/bin/bash
echo "ENTRYPOINT"
slapadd -v -l /root/ldap/schema/local_schema.ldif -n 0
chown openldap:openldap /etc/ldap/slapd.d/cn\=config/cn\=schema/cn={4}uhaccount.ldif
service slapd start
service apache2 start
/bin/bash