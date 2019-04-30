set timeout -1
spawn apt -y install libnss-ldap libpam-ldap nscd
expect "LDAP server Uniform Resource Identifier: "
send "ldap://172.17.0.3\r"
expect "Distinguished name of the search base: "
send "dc=uh,dc=cu\r"
expect "LDAP version to use: "
send "1\r"
expect "Make local root Database admin: "
send "yes\r"
expect "Does the LDAP database require login? "
send "no\r"
expect "LDAP account for root: "
send "cn=admin,dc=uh,dc=cu\r"
expect "LDAP root account password: "
send "insecurepassword\r"
interact 

