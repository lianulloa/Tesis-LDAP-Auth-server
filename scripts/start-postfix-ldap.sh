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

sed -i -re "s/virtual_alias_maps = hash:\/etc\/postfix\/virtual/virtual_alias_maps = ldap:\/etc\/postfix\/ldap-virtual-alias-maps.cf/" /etc/postfix/main.cf

# # apt install -y mysql-server
# expect /root/install-mysql-server.sh

# usermod -d /var/lib/mysql/ mysql
# chown -R mysql:mysql /var/lib/mysql

apt install -y postfix-ldap

# postmap /etc/postfix/virtual

# service mysql start
# expect /root/configure-mysql.sh
# # CREATE DATABASE TO HOST ALIASES TO POSIX ACCOUNTS
# expect /root/create-mail-database.sh

# mysql -u root --password=insecurepassword -e "grant all on maildb.* to 'mailuser'@'localhost' identified by 'insecurepassword';"
# mysql -u root --password=insecurepassword -e "flush privileges;"
# mysql -u mailuser --password=insecurepassword maildb -e "create table \`virtual_aliases\` ( \`id\` int(11) not null auto_increment, \`source\` varchar(100) not null, \`destination\` varchar(100) not null, primary key (\`id\`) ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"
# mysql -u mailuser --password=insecurepassword maildb -e "insert into \`maildb\`.\`virtual_aliases\` (\`id\`, \`source\`,\`destination\`) values ('1','root@example.com','root'),('2','user1@example.com', 'user1');"

newaliases
service postfix restart
postfix reload
service dovecot restart


#apt install -y phpmyadmin
# expect /root/configure-phpmyadmin.sh

# Testing connection with database
echo "POSTMAP RESPONSE"
postmap -q user1@example.com ldap:/etc/postfix/ldap-virtual-alias-maps.cf
getent passwd user1

echo "If everything is ok then you can send emails with command line client"
echo "WHEN TESTING, PLEASE REMEMBER TO CREATE USER HOME LOGIN HIM"


/bin/bash
