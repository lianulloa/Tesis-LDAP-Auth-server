set timeout -1
spawn mysql_secure_installation
expect "Enter password for user root: "
send "insecurepassword\r"
expect "Press y|Y for Yes, any other key for No: "
send "no\r"
expect "Change the password for root ? ((Press y|Y for Yes, any other key for No) :"
send "no\r"
expect "Remove anonymous users? (Press y|Y for Yes, any other key for No) :"
send "y\r"
expect "Disallow root login remotely? (Press y|Y for Yes, any other key for No) :"
send "y\r"
expect "Remove test database and access to it? (Press y|Y for Yes, any other key for No) :"
send "y\r"
expect "Reload privilege tables now? (Press y|Y for Yes, any other key for No) :"
send "y\r"
interact 

