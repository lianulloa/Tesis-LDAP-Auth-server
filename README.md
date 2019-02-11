# Set environment

## Installation walk-through

1.	`$ sudo apt-get install slapd ldap-utils`

	Here you have to set the password
	
2. `$dpkg-reconfigure slapd`
   
	- Omit OpenLDAP server configuration? No
	- DNS domain name? ldap.uh.cu
	- Organization name? Matcom
	- Administrator password? < here you can reset password>
	- Database backend? MDB
	- Remove the database when slapd is purged? No
	- Move old database? Yes
	- Allow LDAPv2 protocol? No

## Installing and Configuring the phpLDAPadmin web

1. Install phpLDAPadmin  `$ sudo apt-get install phpldapadmin`
2. Configure phpLDAPadmin
	1. Open configuration file `$ sudo nano /etc/phpldapadmin/config.php`
	2. Set display name for LDAP server( just for notation) `$servers->setValue('server','name','Example LDAP');`
	3. Set base LDAP server domain `$servers->setValue('server','base',array('dc=ldap,dc=uh,dc=cu'));`
	4. Set admin user login-username `$servers->setValue('login', 'bind_id','cn=admin,dc=ldap,dc=uh,dc=cu' );`
	5. Controls the visibility of some phpLDAPadmin warning messages `$config->custom->appearance['hide_template_warning'] = true;`

## Install LDAP Client

1. Install Client `$ sudo apt -y install libnss-ldap libpam-ldap nscd`
2. [Configure](file:///home/lian/Tesis%20Doc/PAM/Configure%20LDAP%20Client%20on%20Ubuntu%2016.04%20_%20Debian%208%20-%20ITzGeek.html)


# Docker Image

## Run image

`$ docker run --rm -it -p 8000:80 m-l/ldap`

## Build image

`$ docker build -t m-l/ldap .`

## Erase Dangling

`$ docker rmi $(docker images -q --filter "dangling=true")`