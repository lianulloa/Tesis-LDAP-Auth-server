set timeout -1

spawn apt -y install slapd ldap-utils
expect "Administrator password: "
send "$env(SERVER_PASSWORD)\r"
expect "Confirm password: "
send "$env(SERVER_PASSWORD)\r"
sleep 15

spawn dpkg-reconfigure slapd
expect "Omit OpenLDAP server configuration?"
send "No\r"
expect "DNS domain name: "
send "$env(SERVER_DOMAIN)\r"
expect "Organization name: "
send "MATCOM\r"
expect "Administrator password: "
send "$env(SERVER_PASSWORD)\r"
expect "Confirm password: "
send "$env(SERVER_PASSWORD)\r"
expect "Database backend to use: "
send "3\r"
expect "Do you want the database to be removed when slapd is purged? "
send "no\r"
expect "Move old database? "
send "yes\r"
expect "Allow LDAPv2 protocol? "
send "no\r"
sleep 2

# spawn apt install -y 
interact 

