set timeout -1
spawn mysqladmin -u root -p create maildb
expect "Enter password: "
send "insecurepassword\r"
interact 

