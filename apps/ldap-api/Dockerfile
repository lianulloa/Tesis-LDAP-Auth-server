FROM python:3

ENV APP_DIR /api

VOLUME ${APP_DIR}
WORKDIR ${APP_DIR}

RUN apt-get update && apt-get install -y libldap2-dev libsasl2-dev

RUN pip3 install flask \
    flask_restful \
    flask-jsonpify \
    python-ldap



