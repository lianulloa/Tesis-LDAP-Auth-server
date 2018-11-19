FROM matcom-lian/ubuntu-ldap-phpldapadmin:latest 
MAINTAINER Lian Ulloa l.ulloa@estudiantes.matcom.uh.cu


COPY ./ldif /root/ldap/schema
RUN touch /root/ldap/start-service.sh && \
	echo "#!/bin/bash" >> /root/ldap/start-service.sh && \
	echo "service slapd start" >> /root/ldap/start-service.sh && \
	echo "service apache2 start" >> /root/ldap/start-service.sh && \
	echo "/bin/bash" >> /root/ldap/start-service.sh && \
	chmod +x /root/ldap/start-service.sh

# EXPOSE 80 443
VOLUME [ "/root/ldap/schema" ]

ENTRYPOINT [ "/root/ldap/start-service.sh" ]

# CMD /bin/bash