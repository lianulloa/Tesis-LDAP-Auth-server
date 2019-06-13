#!/bin/bash
echo ENTRYPOINT
# IMPORTANT EVERY IMAGE WHICH INHERITS FROM THIS SHOULD EXPORT PORTS 25 , AND 80

# INSTALL DEPENDENCIES FOR LDAP CLIENT
echo Now dependencies for ldap client will be installed
sleep 2
apt update

## INSTALL EXPECT SO I CAN CONFIGURE CLIENT INSTALLATION AUTOMATICALLY
echo -------------INSTALLING EXCEPT...----------------------
sleep 2
apt -y install expect

## CONFIGURE CLIENT AUTOMATICALLY
echo -------------INSTALLING CLIENT...----------------------
sleep 2
expect /root/configure-ldap-client-using-expect.sh

sed -i -re 's/passwd:         compat/passwd:         compat ldap/' /etc/nsswitch.conf
sed -i -re 's/group:          compat/group:          compat ldap/' /etc/nsswitch.conf
sed -i -re 's/shadow:         compat/shadow:         compat ldap/' /etc/nsswitch.conf

# AUTOMATICALLY CREATE HOME DIRECTORY
echo "session required        pam_mkhomedir.so skel=/etc/skel umask=0022"  >> /etc/pam.d/common-session

service nscd restart

echo "before "
getent passwd user1
echo "after"

sed -i -re "s/virtual_alias_maps = hash:\/etc\/postfix\/virtual/virtual_alias_maps = ldap:\/etc\/postfix\/ldap-virtual-alias-maps.cf/" /etc/postfix/main.cf
sed -i -re "s/example.com/grs.uh.cu/" /etc/mailname
postconf -e 'mydestination = grs.uh.cu,estudiantes.matcom.grs.uh.cu,matcom.uh.cu,localhost'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_security_options = '
# postconf -e 'smtpd_sasl_security_options = noanonymous'
postconf -e 'smtpd_sasl_local_domain = $myhostname'
postconf -e 'broken_sasl_auth_clients = yes'
postconf -e 'smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,check_relay_domains'

apt install -y postfix-ldap

newaliases
service postfix restart
postfix reload
service dovecot restart


# Testing connection with database
echo "POSTMAP RESPONSE"
postmap -q user1@estudiantes.matcom.grs.uh.cu ldap:/etc/postfix/ldap-virtual-alias-maps.cf
getent passwd user1

echo "If everything is ok then you can send emails with command line client"
echo "WHEN TESTING, PLEASE REMEMBER TO CREATE USER HOME LOGIN HIM"


# GIVE PERMISSION SO POSTFIX CAN MODIFY /HOME
chown root:groupIX /home
chmod 775 /home

/bin/bash
