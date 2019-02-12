from flask import Flask, request
from flask_restful import Resource, Api
from flask_jsonpify import jsonify

app = Flask(__name__)
api = Api(app)

class Employees(Resource):
    def get(self):
        return {'employees': []}

class Employee(Resource):
    def get(self, employee_id):
        result = {'employee_data': []}
        return jsonify(result)
        

api.add_resource(Employees, '/employees')
api.add_resource(Employee, '/employees/<employee_id>')