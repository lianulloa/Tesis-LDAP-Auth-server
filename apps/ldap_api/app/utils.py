
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
AREAS = [
    ['imre.uh.cu', 'Instituto de Ciencia y Tecnología de Materiales'],
    ['fcom.uh.cu', 'Facultad de Comunicación'],
    ['ifal.uh.cu', 'Instituto de Farmacia y Alimentos'],
    ['matcom.uh.cu', 'Facultad de Matemática y Computación'],
    ['dict.uh.cu', 'Dirección de Información Científico Técnica'],
    ['geo.uh.cu', 'Facultad de Geografía'],
    ['instec.uh.cu', 'Instituto Superior de Ciencias y Tecnologías Aplicadas'],
    ['direco.uh.cu', 'Dirección de Comunicación'],
    ['flex.uh.cu', 'Facultad de Lenguas Extranjeras'],
    ['iris.uh.cu', 'Dirección Docente de Informatización'],
    ['fisica.uh.cu', 'Facultad de Física'],
    ['lex.uh.cu', 'Facultad de Derecho'],
    ['psico.uh.cu', 'Facultad de Psicología'],
    ['cedem.uh.cu', 'Centro de Estudios Demográficos'],
    ['cepes.uh.cu', 'Centro de Estudios para el Perfeccionamiento de la Educación Superior'],
    ['flacso.uh.cu', 'Facultad Latinoamericana de Ciencias Sociales'],
    ['ceap.uh.cu', 'Centro de Estudios de Administración Pública'],
    ['ffh.uh.cu', 'Facultad de Filosofía e Historia'],
    ['cehseu.uh.cu', 'Centro de Estudios Hemisféricos y sobre los Estados Unidos'],
    ['jbn.uh.cu', 'Jardín Botánico'],
    ['fcf.uh.cu', 'Facultad de Contabilidad y Finanzas'],
    ['ftur.uh.cu', 'Facultad de Turismo'],
    ['fenhi.uh.cu', 'Facultad de Español para no Hispano Hablantes'],
    ['fbio.uh.cu', 'Facultad de Biología'],
    ['cim.uh.cu', 'Centro de Investigaciones Marinas'],
    ['fq.uh.cu', 'Facultad de Química']
]

##################################################################
# Métodos auxiliares para el API
##################################################################

def abort_if_todo_doesnt_exist(todo_id):
    if todo_id not in TODOS:
        abort(404, message="Todo {} doesn't exist".format(todo_id))

##################################################################
# Clases auxiliares para el API
##################################################################

import json

class MyEncoder(json.JSONEncoder):
    '''Pass this class to "cls" kwarg of json.dumps method'''
    def default(self,o):
        if type(o) is bytes:
            return o.decode('utf-8')
        else:
            return json.JSONEncoder.default(o)