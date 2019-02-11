FROM matcom-lian/ubuntu-ldap-phpldapadmin:latest 
MAINTAINER Lian Ulloa l.ulloa@estudiantes.matcom.uh.cu


COPY ./ldif /root/ldap/schema
COPY ./start-service.sh /root/ldap/
RUN chmod +x /root/ldap/start-service.sh

# EXPOSE 80 443
VOLUME [ "/root/ldap/schema" ]

ENTRYPOINT [ "/root/ldap/start-service.sh" ]

# CMD /bin/bash