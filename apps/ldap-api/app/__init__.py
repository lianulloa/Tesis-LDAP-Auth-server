from flask import Flask, request
from flask_restful import Resource, Api
from flask_jsonpify import jsonify
import os
import ldap
import parser
import utils

app = Flask(__name__)
api = Api(app)

ldap.initialize(os.getenv('LDAP_SERVER_URI'))

class Users(Resource):
    def get(self):
        return {'users': []}

class User(Resource):
    def get(self, user_id):
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
api.add_resource(User, '/users/<int:user_id>')
api.add_resource(Workers, '/workers')
api.add_resource(Worker, '/workers/<worker_id>')
api.add_resource(Students, '/students')
api.add_resource(Student, '/students/<student_id>')
api.add_resource(Externs, '/externs')
api.add_resource(Extern, '/externs/<extern_id>')
api.add_resource(Accounts, '/accounts/<account_type>/<account_id>/<action>')