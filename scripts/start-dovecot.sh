#!/bin/bash
echo ENTRYPOINT FOR DOVECOT

newaliases
service postfix restart
postfix reload
service dovecot restart

/bin/bash
