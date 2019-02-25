#!/bin/bash
echo "ENTRYPOINT"
slapadd -v -l /root/ldap/schema/local_schema.ldif -n 0
chown openldap:openldap /etc/ldap/slapd.d/cn\=config/cn\=schema/cn={4}uhaccount.ldif

# ADD GROUP AND USER ORGANIZATIONAL UNITS
slapadd -v -l /root/ldap/schema/ou.ldif

# ADD EXAMPLES USER AND GROUP
slapadd -v -l /root/ldap/schema/user.ldif
slapadd -v -l /root/ldap/schema/groups.ldif

# INSTALL DEPENDENCIES FOR LDAP CLIENT
echo "Now dependencies for ldap client will be installed"
sleep 3
apt update

## INSTALL EXPECT SO I CAN CONFIGURE CLIENT INSTALLATION AUTOMATICALLY
echo "-------------------------------------INSTALLING EXCEPT...----------------------"
sleep 2
apt -y install expect

## CCONFIGURE CLIENT AUTOMATICALLY
echo "-------------------------------------INSTALLING CLIENT...----------------------"
sleep 2
expect /root/ldap/configure-ldap-client-using-expect.sh

sed -i -re 's/passwd:         compat/passwd:         compat ldap/' /etc/nsswitch.conf
sed -i -re 's/group:          compat/group:          compat ldap/' /etc/nsswitch.conf
sed -i -re 's/shadow:         compat/shadow:         compat ldap/' /etc/nsswitch.conf


service slapd start
service apache2 start
service nscd restart

getent passwd user1

/bin/bash