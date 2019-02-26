
##################################################################
# Variables y constantes de propósito general para uso del API
##################################################################

"""
Nivel de seguimiento de los errores en los logs:
    0 -> No mostrar logs.
    1 -> Mostrar la llamada al método con los argumentos.
    2 -> Mismo que uno pero con los resultados completos.
    9 -> Mostrar el "traceback" del método.
"""
DEBUG_LEVEL = {"NO_LOGGING" : 0, "METHOD_W_ARGUMENTS" : 1, "METHOD_W_ARGUMENTS_W_RESULTS" : 2, "TRACEBACK" : 9}

##################################################################
# Métodos auxiliares para el API
##################################################################

def abort_if_todo_doesnt_exist(todo_id):
    if todo_id not in TODOS:
        abort(404, message="Todo {} doesn't exist".format(todo_id))


import json

class MyEncoder(json.JSONEncoder):
	'''Pass this class to "cls" kwarg of json.dumps method'''
    def default(self,o):
        if type(o) is bytes:
            return o.decode('utf-8')
        else:
            return json.JSONEncoder.default(o)