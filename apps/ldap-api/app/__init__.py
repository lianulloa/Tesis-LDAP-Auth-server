import os
import ldap
import json

from flask import Flask, request
from flask_restful import Resource, Api
from flask_jsonpify import jsonify
from app import config, utils

# Inicializando la aplicación de flask en modo API
app = Flask(__name__)
api = Api(app)

# Configuraciones según el entorno
configuration = config.set_environment(os.getenv("LDAP_API_ENVIRONMENT"))

# Inicializando la estructura pero sin conectarse aún (lazy connect)
# Ver por que no funciona: trace_file=open(configuration.LOG_FILE_ADDRESS,"w+")
ldap_server = ldap.initialize(configuration.LDAP_SERVER_URI, 
                             trace_level=utils.DEBUG_LEVEL[configuration.PYTHON_LDAP_DEBUG_LVL])

class Users(Resource):
    def get(self):
        unparsed_args = request.args
        parsed_args = unparsed_args
        args = [ "%s=%s" % (key, parsed_args[key]) for key in parsed_args]
        ldap_search_filter_string = ""
        users_accounts = ldap_server.search_s("ou=usuarios,dc=ldap,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL)
        # TODO: Arreglar este parche para llevar a JSON con las tuplas y los bytes
        users_accounts = str({x[0] : x[1] for x in users_accounts})
        users_accounts = users_accounts.replace("'", '"').replace('b"', '"').replace(' b"', '"').replace(',b"', '"').replace('[b"', '"').replace('\"', '"')
        users_accounts = json.loads(users_accounts)
        return jsonify({'users': users_accounts})

class User(Resource):
    def get(self, user_id):
        users_account = ldap_server.search_s("ou=usuarios,dc=ldap,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, "(cn=%s*)" % user_id)
        users_account = str({x[0] : x[1] for x in users_account})
        users_account = users_account.replace("'", '"').replace('b"', '"').replace(' b"', '"').replace(',b"', '"').replace('[b"', '"').replace('\"', '"')
        users_account = json.loads(users_account)
        return jsonify({'user': users_account})
    
    def post(self, user_id):
        result = {'user_data': []}
        return jsonify(result)

class Workers(Resource):
    def get(self):
        return {'workers': []}

class Worker(Resource):
    def get(self, worker_id):
        result = {'worker_data': []}
        return jsonify(result)

class Students(Resource):
    def get(self):
        return {'students': []}

class Student(Resource):
    def get(self, student_id):
        result = {'student_data': []}
        return jsonify(result)

class Externs(Resource):
    def get(self):
        return {'externs': []}

class Extern(Resource):
    def get(self, extern_id):
        result = {'extern_data': []}
        return jsonify(result)

class Accounts(Resource):
    def patch(self, account_type, account_id, action):
        # Actions = 'activate' : 'deactivate'
        result = {'action_response': []}
        return jsonify(result)

api.add_resource(Users, '/users')
api.add_resource(User, '/users/<string:user_id>')
api.add_resource(Workers, '/workers')
api.add_resource(Worker, '/workers/<worker_id>')
api.add_resource(Students, '/students')
api.add_resource(Student, '/students/<student_id>')
api.add_resource(Externs, '/externs')
api.add_resource(Extern, '/externs/<extern_id>')
api.add_resource(Accounts, '/accounts/<account_type>/<account_id>/<action>')