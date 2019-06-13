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

# THIS IS NEEDED BECAUSE I MIS-CONFIG BASE IMAGE
postconf -e 'recipient_delimiter = +'

postconf -e 'mydestination = grs.uh.cu,estudiantes.matcom.grs.uh.cu,matcom.uh.cu,localhost'
postconf -e 'smtp_tls_security_level = may'
postconf -e 'smtpd_tls_security_level = may'
postconf -e 'smtp_tls_note_starttls_offer = yes'
postconf -e 'smtpd_tls_loglevel = 1'
postconf -e 'smtpd_tls_received_header = yes'
postconf -e 'smtpd_tls_session_cache_timeout = 3600s'
postconf -e 'tls_random_source = dev:/dev/urandom'

postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/auth'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'broken_sasl_auth_clients = yes'
postconf -e 'smtpd_sasl_security_options = noanonymous'
postconf -e 'smtpd_sasl_local_domain = '
postconf -e 'smtpd_sasl_authenticated_header = yes'
postconf -e 'smtpd_client_connection_count_limit = 100'

# Requirements for the HELO statement
postconf -e 'smtpd_helo_restrictions = permit_mynetworks, warn_if_reject reject_non_fqdn_hostname, reject_invalid_hostname, permit'
# Requirements for the sender details
postconf -e 'smtpd_sender_restrictions = permit_sasl_authenticated, permit_mynetworks, warn_if_reject reject_non_fqdn_sender, reject_unknown_sender_domain, reject_unauth_pipelining, permit'
# Requirements for the connecting server
postconf -e 'smtpd_client_restrictions = reject_rbl_client sbl.spamhaus.org, reject_rbl_client blackholes.easynet.nl'
# Requirement for the recipient address. Note that the entry for
# "check_policy_service inet:127.0.0.1:10023" enables Postgrey.
#smtpd_recipient_restrictions = reject_unauth_pipelining, permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, check_policy_service inet:127.0.0.1:10023, permit
postconf -e 'smtpd_data_restrictions = reject_unauth_pipelining'
# This is a new option as of Postfix 2.10, and is required in addition to
# smtpd_recipient_restrictions for things to work properly in this setup.
#smtpd_relay_restrictions = reject_unauth_pipelining, permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, check_policy_service inet:127.0.0.1:10023, permit
postconf -e 'smtpd_relay_restrictions = reject_unauth_pipelining, permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, permit'
postconf -e 'smtpd_helo_required = yes'
postconf -e 'smtpd_recipient_restrictions = reject_unauth_pipelining,permit_mynetworks,permit_sasl_authenticated,reject_non_fqdn_recipient,reject_unknown_recipient_domain,reject_unauth_destination,permit'

postconf -e 'myhostname = grs.uh.cu'
postconf -e 'relayhost = smtp.grs.uh.cu'

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
