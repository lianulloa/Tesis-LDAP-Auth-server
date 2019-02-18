class Config(object):
    DEBUG = False
    LDAP_SERVER_URI = ''

class ProductionConfig(Config):
    LDAP_SERVER_URI = 'production'

class DevelopmentConfig(Config):
    DEBUG = True
