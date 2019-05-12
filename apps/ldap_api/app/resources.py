from flask_restful import Resource, reqparse
from flask_jsonpify import jsonify
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, 
                                get_jwt_identity, set_access_cookies, unset_jwt_cookies,
                                set_refresh_cookies, get_raw_jwt)
from pymemcache.client import base
from .models import UserModel
from app import config, utils
from flask import request, Response
from ldap import modlist
import crypt
import random
import string
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

ldap_server.simple_bind_s('cn=admin,dc=uh,dc=cu','insecurepassword')


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
        # users_account = ldap_server.search_s("ou=usuarios,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, "(cn=%s*)" % user_id)
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
                "id":x[1]['CI']

            }  for x in externs_account]
        externs_account_json = json.dumps(externs_account, cls=utils.MyEncoder)
        externs_account = json.loads(externs_account_json)

        args = request.args
        page = int(args.get('page',1))
        externs_account = externs_account[(page-1)*configuration.PAGE_COUNT:page*configuration.PAGE_COUNT]

        return {'externs': externs_account}

        # return {'externs': []}

    def post(self):
        data = request.get_json()
        old_login = data.get('old_login')
        can_use_old_login = True

        if old_login:
            extern_account = ldap_server.search_s("ou=Externos,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, "(&(correo=%s)(objectclass=Externo))" % data.get('old_login_email'))
            if len(extern_account):
                can_use_old_login = False
                
        # CREATE ACCOUNT
        ## GENERATE NEW EMAIL
        name = data.get('name')
        last_name = data.get('last_name').lower()
        first_last_name, second_last_name = last_name.split()
        possible_email = name.lower() + '.' +first_last_name + __map_area_to_email_domain__(data.get('area'))

        if can_use_old_login:
            email = data.get('old_login_email')
        else:
            if len(ldap_server.search_s("ou=Externos,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, "(&(correo=%s)(objectclass=Externo))" % possible_email)):
                possible_email = name.lower() + '.' +second_last_name + __map_area_to_email_domain__(data.get('area'))
                if len(ldap_server.search_s("ou=Externos,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, "(&(correo=%s)(objectclass=Externo))" % possible_email)):
                    for i in range(1,1000):
                        possible_email = name.lower() + '.' +second_last_name +str(i) + __map_area_to_email_domain__(data.get('area'))
                        if len(ldap_server.search_s("ou=Externos,dc=uh,dc=cu", ldap.SCOPE_ONELEVEL, "(&(correo=%s)(objectclass=Externo))" % possible_email)):
                            continue
                        email = possible_email
                        break
                else:
                    email = possible_email
            else:
                email = possible_email

        ## GET UIDNUMBERCOUNTER
        try:
            client = base.Client((configuration.MEMCACHED_HOST, 11211))
            uidNumberCounter = int(__translate_byte_types__(client.get('uidNumberCounter')))
        except Exception as e:
            print(e)
            return {"error":"Can't get uidNumberCounter from memcached"}

        dn = 'uid=%s,ou=Externos,dc=uh,dc=cu' % email
        password = '{CRYPT}' + __sha512_crypt__(data.get('password'),500000)
        try:
            created_at = data.get('created_at').split('-')
            created_at = created_at[0] + created_at[1] + created_at[2]
            expires = data.get('expires').encode('utf-8')
            expires = expires[0] + expires[1] + expires[2] 
            modList = modlist.addModlist({
                'CI': [data.get('ci').encode('utf-8')],
                'cn': [name.encode('utf-8')],
                'sn':[last_name.encode('utf-8')],
                'correo':[email.encode('utf-8')],
                'fechadecreacion':[ str(created_at).encode('utf-8') ],
                'fechadebaja':[str(expires).encode('utf-8')],
                'tienecorreo': [b'TRUE'],
                'tieneinternet': [b'TRUE'],
                'tienechat': [b'TRUE'],
                'description':[b'comments'],
                'userpassword':[password.encode('utf-8')],
                'uid':email.encode('utf-8'),
                'objectClass':[b'Externo']
            })
            ldap_server.add_s(dn,modList)
        except Exception as e:
            return {'error':str(e)}

        result = {'extern_data':'success' }
        return jsonify(result)


class Extern(Resource):
    def get(self, extern_id):
        result = {'extern_data': []}
        return jsonify(result)



class Accounts(Resource):
    def patch(self, account_type, account_id, action):
        # Actions = 'activate' : 'deactivate'
        result = {'action_response': []}
        return jsonify(result)


def __map_area_to_email_domain__(area):
    # THIS SHOULD BE DOMAIN FOR DDI
    return "@iris.uh.cu"

def __translate_byte_types__(instance):
    instance_json = json.dumps(instance, cls=utils.MyEncoder)
    return json.loads(instance_json)



def __sha512_crypt__(password, rounds=5000):
    rand = random.SystemRandom()
    salt = ''.join([rand.choice(string.ascii_letters + string.digits)
                    for _ in range(16)])

    prefix = '$6$'
    rounds = max(1000, min(999999999, rounds))
    prefix += 'rounds={0}$'.format(rounds)
    return crypt.crypt(password, prefix + 'abcdefghijklmnop')