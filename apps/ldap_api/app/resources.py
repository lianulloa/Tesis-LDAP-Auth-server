from flask_restful import Resource, reqparse
from flask_jsonpify import jsonify
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, 
                                get_jwt_identity, set_access_cookies, unset_jwt_cookies,
                                set_refresh_cookies, get_raw_jwt)
from .models import UserModel
from app import config, utils
from flask import request
import os
import ldap
import json


parser = reqparse.RequestParser()
parser.add_argument('username', help='This field cannot be blank', required=True)
parser.add_argument('password', help='This field cannot be blank', required=True)

# Configuraciones según el entorno
configuration = config.set_environment(os.getenv("LDAP_API_ENVIRONMENT"))

ldap_server = ldap.initialize(configuration.LDAP_SERVER_URI,
                trace_level=utils.DEBUG_LEVEL[configuration.PYTHON_LDAP_DEBUG_LVL])


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}, 403
        
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            resp = jsonify({'registration': True})
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            resp.status_code = 200
            return resp
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'Wrong credentials'}, 403
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])

            resp = jsonify({'login': True})
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            resp.status_code = 200
            return resp
        else:
            return {'message': 'Wrong credentials'}, 403

class UserLogout(Resource):
    def post(self):
        resp = jsonify({'logout': True})
        unset_jwt_cookies(resp)
        resp.status_code = 200
        return resp


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()


class Users(Resource):
    def get(self):
        # # Parseando los argumentos de la url para filtrar
        # unparsed_args = request.args
        # parsed_args = unparsed_args
        # args = ["(%s=%s)" % (key, parsed_args[key]) for key in parsed_args]
        # if len(args) == 0:
        #     ldap_search_filter_string = None
        # elif len(args) == 1:
        #     ldap_search_filter_string = args[0]
        # else:
        #     ldap_search_filter_string = "(&%s)" % "".join(args)
        #
        # users_accounts = ldap_server.search_s("ou=usuarios,dc=ldap,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, ldap_search_filter_string)
        #
        # users_accounts = {x[0] : x[1] for x in users_accounts}
        #
        # users_accounts_json = json.dumps(users_accounts, cls=utils.MyEncoder)
        # return jsonify({'users': json.loads(users_accounts_json)})
        return jsonify({'users': []})


class User(Resource):
    def get(self, user_id):
        # users_account = ldap_server.search_s("ou=usuarios,dc=ldap,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, "(cn=%s*)" % user_id)
        # users_account = {x[0] : x[1] for x in users_account}
        # users_account_json = json.dumps(users_account, cls=utils.MyEncoder)
        # users_account = json.loads(users_account_json)
        # return jsonify({'user': users_account})
        return jsonify({'users': []})

    def post(self, user_id):
        result = {'user_data': []}
        return jsonify(result)


class Workers(Resource):
    @jwt_required
    def get(self):
        workers_account = ldap_server.search_s("ou=Trabajadores,dc=uh,dc=cu", ldap.SCOPE_SUBTREE, "(objectclass=Trabajador)")
        workers_account = [ 
            { 
                "name":x[1]['cn'], 
                "last_name":x[1]['sn'],
                "ci":x[1]['CI'],
                "area":x[1]['Area'],
                "ocupation":x[1]['Cargo']

            }  for x in workers_account]
        workers_account_json = json.dumps(workers_account, cls=utils.MyEncoder)
        workers_account = json.loads(workers_account_json)

        args = request.args
        page = int(args.get('page',1))
        workers_account = workers_account[(page-1)*configuration.PAGE_COUNT:page*configuration.PAGE_COUNT]

        return {'workers': workers_account}


class Worker(Resource):
    def get(self, worker_id):
        result = {'worker_data': []}
        return jsonify(result)


class Students(Resource):
    def get(self):
        students_account = ldap_server.search_s("ou=Estudiantes,dc=uh,dc=cu", ldap.SCOPE_SUBTREE, "(objectclass=Estudiante)")
        students_account = [ 
            { 
                "name":x[1]['cn'], 
                "last_name":x[1]['sn'],
                "ci":x[1]['CI'],

            }  for x in students_account]
        students_account_json = json.dumps(students_account, cls=utils.MyEncoder)
        students_account = json.loads(students_account_json)

        args = request.args
        page = int(args.get('page',1))
        students_account = students_account[(page-1)*configuration.PAGE_COUNT:page*configuration.PAGE_COUNT]

        return {'students': students_account}


class Student(Resource):
    def get(self, student_id):
        result = {'student_data': []}
        return jsonify(result)


class Externs(Resource):
    @jwt_required
    def get(self):
        externs_account = ldap_server.search_s("ou=Externos,dc=uh,dc=cu", ldap.SCOPE_SUBTREE, "(objectclass=Externo)")
        externs_account = [ 
            { 
                "name":x[1]['cn'], 
                "last_name":x[1]['sn'],
                "ci":x[1]['CI'],

            }  for x in externs_account]
        externs_account_json = json.dumps(externs_account, cls=utils.MyEncoder)
        externs_account = json.loads(externs_account_json)

        args = request.args
        page = int(args.get('page',1))
        externs_account = externs_account[(page-1)*configuration.PAGE_COUNT:page*configuration.PAGE_COUNT]

        return {'externs': externs_account}


class Extern(Resource):
    def get(self, extern_id):
        result = {'extern_data': []}
        return jsonify(result)


class Accounts(Resource):
    def patch(self, account_type, account_id, action):
        # Actions = 'activate' : 'deactivate'
        result = {'action_response': []}
        return jsonify(result)
