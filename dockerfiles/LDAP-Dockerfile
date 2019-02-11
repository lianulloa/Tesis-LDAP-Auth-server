FROM matcom-lian/ubuntu-ldap-phpldapadmin:latest 
MAINTAINER Lian Ulloa l.ulloa@estudiantes.matcom.uh.cu

COPY ./ldif /root/ldap/schema
VOLUME [ "/root/ldap/schema" ]

ENTRYPOINT [ "/root/ldap/start-service.sh" ]

# CMD /bin/bash

COPY ./start-service.sh /root/ldap/
RUN chmod +x /root/ldap/start-service.sh

COPY ./configure-ldap-client-using-expect.sh /root/ldap/
RUN chmod +x /root/ldap/configure-ldap-client-using-expect.sh

# EXPOSE 80 443