
class Config(object):
    LDAP_SERVER_URI = "ldap://10.6.98.57"
    PAGE_COUNT = 20
    MEMCACHED_HOST = '172.20.0.3'

class DevelopmentConfig(Config):
    PYTHON_LDAP_DEBUG_LVL = "METHOD_W_ARGUMENTS_W_RESULTS"
    LOG_FILE_ADDRESS = "log/develop.log"

class ProductionConfig(Config):
    PYTHON_LDAP_DEBUG_LVL = "METHOD_W_ARGUMENTS"
    LOG_FILE_ADDRESS = "log/production.log"

def set_environment(environment):
    if environment == "production":
        return ProductionConfig()
    return DevelopmentConfig()
