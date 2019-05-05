set timeout -1
spawn apt -y install phpmyadmin
expect "Configure database for phpmyadmin with dbconfig-common? "
send "yes\r"
expect "MySQL application password for phpmyadmin: "
send "insecurepassword\r"
expect "Password confirmation: "
send "insecurepassword\r"
expect "Web server to reconfigure automatically: "
send "1\r"
interact

