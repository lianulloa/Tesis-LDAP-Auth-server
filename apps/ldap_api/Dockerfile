FROM python:3

ENV APP_DIR /api

VOLUME ${APP_DIR}
WORKDIR ${APP_DIR}

# RUN apt-get update && apt-get install -y apt-transport-https

# RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
# RUN curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

RUN apt-get update && apt-get install -y  libldap2-dev libsasl2-dev mssql-tools unixodbc unixodbc-dev 
# msodbcsql

RUN echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bash_profile
RUN echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc
RUN source ~/.bashrc

# RUN wget https://gallery.technet.microsoft.com/ODBC-Driver-13-for-Ubuntu-b87369f0/file/154097/2/installodbc.sh
# RUN sh installodbc.sh

RUN pip3 install flask \
    flask_restful \
    flask-jsonpify \
    flask-sqlalchemy \
    flask_jwt_extended \
    flask-cors \
    passlib \
    python-ldap \
    pymemcache \
    pyyaml \
    pyodbc \
    tqdm



