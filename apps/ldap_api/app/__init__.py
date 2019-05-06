import os
# import ldap
import json

from flask import Flask, request
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from app import config, utils


# Inicializando la aplicación de flask en modo API
app = Flask(__name__)
api = Api(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'
app.config['JWT_SECRET_KEY'] = 'dfsasdfsdf7sd6f923f98f8asdff6sdftsdffdsfui3fy2fy87dfgtsdfsd8f'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'

db = SQLAlchemy(app)
jwt = JWTManager(app)
cors = CORS(app, resources={r"/*": {"origins": "*", "supports_credentials": True}})


@app.before_first_request
def create_tables():
    db.create_all()


# Configuraciones según el entorno
configuration = config.set_environment(os.getenv("LDAP_API_ENVIRONMENT"))

# Inicializando la estructura pero sin conectarse aún (lazy connect)
# Ver por que no funciona: trace_file=open(configuration.LOG_FILE_ADDRESS,"w+")

# ldap_server = ldap.initialize(configuration.LDAP_SERVER_URI,
#                 trace_level=utils.DEBUG_LEVEL[configuration.PYTHON_LDAP_DEBUG_LVL])


from app import resources

api.add_resource(resources.AllUsers, '/all-registered')
api.add_resource(resources.SecretResource, '/secret')
api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogout, '/logout')
api.add_resource(resources.Users, '/users')
api.add_resource(resources.User, '/users/<string:user_id>')
api.add_resource(resources.Workers, '/trabajadores')
api.add_resource(resources.Worker, '/trabajador/<worker_id>')
api.add_resource(resources.Students, '/students')
api.add_resource(resources.Student, '/students/<student_id>')
api.add_resource(resources.Externs, '/externs')
api.add_resource(resources.Extern, '/externs/<extern_id>')
api.add_resource(resources.Accounts, '/accounts/<account_type>/<account_id>/<action>')