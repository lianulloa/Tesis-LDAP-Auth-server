set timeout -1
spawn apt -y install mysql-server
expect "New password for the MySQL \"root\" user: "
send "insecurepassword\r"
expect "Repeat password for the MySQL \"root\" user: "
send "insecurepassword\r"
interact 

