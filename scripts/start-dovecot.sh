#!/bin/bash
echo ENTRYPOINT

# INSTALL DEPENDENCIES FOR LDAP CLIENT
echo Now dependencies for ldap client will be installed
sleep 2
apt update

## INSTALL EXPECT SO I CAN CONFIGURE CLIENT INSTALLATION AUTOMATICALLY
echo -------------INSTALLING EXCEPT...----------------------
sleep 2
apt -y install expect

## CCONFIGURE CLIENT AUTOMATICALLY
echo -------------INSTALLING CLIENT...----------------------
sleep 2
expect /root/configure-ldap-client-using-expect.sh

sed -i -re 's/passwd:         compat/passwd:         compat ldap/' /etc/nsswitch.conf
sed -i -re 's/group:          compat/group:          compat ldap/' /etc/nsswitch.conf
sed -i -re 's/shadow:         compat/shadow:         compat ldap/' /etc/nsswitch.conf

echo "session required        pam_mkhomedir.so skel=/etc/skel umask=0022"  >> /etc/pam.d/common-session

service nscd restart

echo "before "
getent passwd user1
echo "after"

/bin/bash
