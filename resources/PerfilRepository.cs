using System;
using System.CodeDom;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.Objects;
using System.Data.Objects.DataClasses;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Xml.Serialization;
using Microsoft.CSharp;
using Model.ListStudentIdentificationByFilterService;
using Model.Models;
using System.Web.Services.Description;
using System.Text.RegularExpressions;
using System.Web.Services.Protocols;

using Model.SigenuWebServices;
using Model.FileStudentService;
using Model.EvaluationStudentService;


namespace Model.Repositories
{
    [Flags]
    public enum FiltrosEstudiante
    {
        Todos = 0,
        Personal = 1,
        Docentes = 2,
        Madre = 4,
        Padre = 8,
        Laboral = 16,
        Militar = 32
    }

    public class PerfilRepository
    {
        private readonly userdataexternosEntities externUsersContext;
        private readonly NominaEntities context_uh;
        private readonly MySql_DirectorioUnicoContainer auxiliar_context;
        private FileStudentService.FileStudentService students;
        private EvaluationStudentService.EvaluationStudentService evaluations;
        private ListStudentIdentificationByFilterService.ListStudentIdentificationByFilterService listCIs;

        public PerfilRepository()
        {
            externUsersContext = new userdataexternosEntities();
            context_uh = new NominaEntities();
            context_uh.ObjectMaterialized += OnMaterialize;
            auxiliar_context = new MySql_DirectorioUnicoContainer();
            auxiliar_context.ObjectMaterialized += OnMaterialize;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            ServicePointManager.Expect100Continue = false;
        }

        private static void OnMaterialize(object sender, ObjectMaterializedEventArgs e)
        {
            foreach (
                var fieldInfo in
                    e.Entity.GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance).Where(
                        f => f.FieldType == typeof(string)))
            {
                var propValue = fieldInfo.GetValue(e.Entity);
                if (propValue == null) continue;
                var value = ((string)propValue).Trim();
                fieldInfo.SetValue(e.Entity, fieldInfo.Name.ToLower().StartsWith("_id") ? value.ToLower() : value);
            }
        }

        #region General Auxiliar Methods

        /// <summary>
        /// Aplica el algorito HMACSHA256 a una cadena
        /// </summary>
        /// <param name="message">Cadena a modificar</param>
        /// <param name="key">Llave usada para modificar</param>
        /// <returns>Cadena modificada</returns>
        private static string HMACSHA256(string message, string key)
        {
            var encoding = new ASCIIEncoding();
            var keyByte = encoding.GetBytes(key);
            var hmacsha256 = new HMACSHA256(keyByte);
            var messageBytes = encoding.GetBytes(message);
            return ByteToString(hmacsha256.ComputeHash(messageBytes));
        }

        /// <summary>
        /// Aplica el algorito SHA256 a una cadena
        /// </summary>
        /// <param name="message">Cadena a modificar</param>
        /// <returns>Cadena modificada</returns>
        private static string _SHA256(string message)
        {
            var encoding = new ASCIIEncoding();
            var messageBytes = encoding.GetBytes(message);
            return ByteToString(SHA256.Create().ComputeHash(messageBytes));
        }

        /// <summary>
        /// Convierte un arreglo de bytes en un string
        /// </summary>
        /// <param name="buff">Arreglo a convertir</param>
        /// <returns>Cadena resultante</returns>
        public static string ByteToString(byte[] buff)
        {
            var sbinary = "";
            for (var i = 0; i < buff.Length; i++)
                sbinary += buff[i].ToString("X2"); // hex format
            return (sbinary);
        }

        /// <summary>
        /// Cambia el tamaño de una imágen
        /// </summary>
        /// <param name="MaxWidth">Máximo de ancho en píxeles</param>
        /// <param name="MaxHeight">Máximo de alto en píxeles</param>
        /// <param name="Buffer">Imágen a modificar</param>
        /// <returns>Imágen modificada</returns>
        private static MemoryStream ResizeFromStream(int MaxWidth, int MaxHeight, Stream Buffer)
        {
            int iWidth;
            int iHeight;
            var imgInput = Image.FromStream(Buffer);

            //Determine image format
            var fmtImageFormat = imgInput.RawFormat;

            //get image original width and height
            var intOldWidth = imgInput.Width;
            var intOldHeight = imgInput.Height;
            double dblCoef;

            //If intMaxSide > MaxSideSize Then
            if (intOldWidth > MaxWidth)
            {
                iWidth = MaxWidth;

                dblCoef = MaxWidth / Convert.ToDouble(intOldWidth);

                if (MaxHeight <= Convert.ToInt32(dblCoef * intOldHeight))
                {
                    iHeight = MaxHeight;
                    dblCoef = MaxHeight / Convert.ToDouble(intOldHeight);
                    iWidth = Convert.ToInt32(dblCoef * intOldWidth);
                }
                else
                    iHeight = Convert.ToInt32(dblCoef * intOldHeight);
            }
            else if (intOldHeight > MaxHeight)
            {
                iHeight = MaxHeight;
                dblCoef = MaxHeight / Convert.ToDouble(intOldHeight);
                iWidth = Convert.ToInt32(dblCoef * intOldWidth);
            }
            else
            {
                iWidth = intOldWidth;
                iHeight = intOldHeight;
            }

            //create new bitmap
            var bmpResized = new Bitmap(imgInput, iWidth, iHeight);

            var stream = new MemoryStream();
            bmpResized.Save(stream, fmtImageFormat);

            //release used resources
            imgInput.Dispose();
            bmpResized.Dispose();

            return stream;
        }

        private void InitializeStudentsWS()
        {
            students = new FileStudentService.FileStudentService
                           {
                               Credentials =
                                   new NetworkCredential(
                                   ConfigurationManager.AppSettings["sigenu_user"],
                                   ConfigurationManager.AppSettings["sigenu_pwd"])
                           };
        }

        private void InitializeEvaluationWS()
        {
            evaluations = new EvaluationStudentService.EvaluationStudentService
                              {
                                  Credentials =
                                      new NetworkCredential(
                                      ConfigurationManager.AppSettings
                                          [
                                              "sigenu_user"],
                                      ConfigurationManager.AppSettings
                                          [
                                              "sigenu_pwd"])
                              };
        }

        #endregion

        #region Authentication queries

        #region Auxiliar methods

        /// <summary>
        /// Devuelve el objeto de la tabla userlogon correspondiente al token
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Login del usuario</returns>
        private userlogon GetLogonUser(SecurityToken token)
        {
            var users = auxiliar_context.userlogon.Where(u => u.alias.email == token.Username && u.token == token.Token);
            if (users.Count() != 1)
                throw new UnauthorizedAccessException("Error de seguridad.");
            return users.Single();
        }
        private userlogon GetLogonUserCuote(string username)
        {
            var users = auxiliar_context.userlogon.Where(u => u.alias.email == username);
            return users.First();
        }
        private userlogon GetLogonUserCuotePorLogin(int loginId)
        {
            var users = auxiliar_context.userlogon.Where(u => u.alias.idLogin == loginId);
            return users.First();
        }
        /// <summary>
        /// Devuelve el objeto de la tabla login correspondiente al nombre de usuario
        /// </summary>
        /// <param name="name">Nombre de usuario a buscar</param>
        /// <returns>Objeto login del usuario</returns>
        private login GetLogin(string name)
        {
            var username = name;
            if (username.Contains("/"))
                username = name.Substring(1 + name.LastIndexOf("/"));

            return auxiliar_context.login.FirstOrDefault(l => l.alias.Any(a => a.email == username));
        }

        private login GetLoginTrabajador(string name)
        {
            var username = name;
            if (username.Contains("/"))
                username = name.Substring(1 + name.LastIndexOf("/"));

            
            return auxiliar_context.login.FirstOrDefault(l => l.alias.Any(a => a.email == username) && l.assets > 0);
        }

        private login GetLoginEstudiante(string name)
        {
            var username = name;
            if (username.Contains("/"))
                username = name.Substring(1 + name.LastIndexOf("/"));

            return auxiliar_context.login.FirstOrDefault(l => l.alias.Any(a => a.email == username) && l.assets == 0 );
        }
        /// <summary>
        /// Insertar al usuario como autentificado
        /// </summary>
        /// <param name="username">Email del usuario</param>
        /// <returns>Guid del token de autentificacion</returns>
        private string LogonUser(string username)
        {
            var token = Guid.NewGuid().ToString();
            auxiliar_context.AddTouserlogon(new userlogon
                                                {
                                                    idAlias =
                                                        auxiliar_context.alias.Single(a => a.email == username).idAlias,
                                                    dateissue = DateTime.UtcNow,
                                                    token = token
                                                });
            auxiliar_context.SaveChanges();
            return token;
        }

        #endregion

        public void AddHistory(SecurityToken token, string ip, string sistema, bool autentificarse)
        {
            var alias = auxiliar_context.alias.SingleOrDefault(a => a.email == token.Username);
            if (alias != null)
            {
                var idAlias = alias.idAlias;
                auxiliar_context.AddTouserhistory(new userhistory
                                                      {
                                                          fecha = System.DateTime.UtcNow,
                                                          ip = ip,
                                                          sistema = sistema,
                                                          autentificacion = autentificarse,
                                                          idAlias = idAlias
                                                      });
                auxiliar_context.SaveChanges();
            }
        }

        public void AddHistoryCoute(SecurityInfoToken token, string ip, string sistema, bool autentificarse)
        {
            var alias = auxiliar_context.alias.SingleOrDefault(a => a.email == token.Username);
            if (alias != null)
            {
                var idAlias = alias.idAlias;
                auxiliar_context.AddTouserhistory(new userhistory
                {
                    fecha = System.DateTime.UtcNow,
                    ip = ip,
                    sistema = sistema,
                    autentificacion = autentificarse,
                    idAlias = idAlias
                });
                auxiliar_context.SaveChanges();
            }
        }

        public IEnumerable<UserHistory> GetHistory(SecurityToken token, string email, bool include_other_emails,
                                                   DateTime? init_date, DateTime? end_date, string admin_password)
        {
            if (token == null)
            {
                if (ConfigurationManager.AppSettings["admin"] != admin_password)
                    return null;
            }
            var idLogin = token == null
                              ? auxiliar_context.alias.Single(a => a.email == email).login.idLogin
                              : GetLogin(token).idLogin;
            var emails = (include_other_emails
                              ? auxiliar_context.alias.Where(a => a.idLogin == idLogin)
                              : auxiliar_context.alias.Where(a => a.email == email));
            var history = auxiliar_context.userhistory
                .Where(
                    a =>
                    emails.Any(e => e.idAlias == a.idAlias) && (init_date == null || a.fecha >= init_date) &&
                    (end_date == null || a.fecha <= end_date));
            return history.Select(u => new UserHistory
                                           {
                                               autentificacion = u.autentificacion,
                                               fecha = u.fecha,
                                               correo = u.alias.email,
                                               ip = u.ip,
                                               sistema = u.sistema
                                           });
        }

        /// <summary>
        /// Retorna el tiempo del ultimo acceso del usuario
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Tiempo del ultimo acceso del usuario</returns>
        public long? GetUserTime(SecurityToken token, bool update)
        {
            userlogon user;
            try
            {
                user = GetLogonUser(token);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }

            var date = user.dateissue;
            if (update)
            {
                user.dateissue = DateTime.UtcNow;
                auxiliar_context.SaveChanges();
            }
            TimeSpan seconds = DateTime.UtcNow - date;
            return (long)seconds.TotalSeconds;
        }

        /// <summary>
        /// Devuelve el objeto de la tabla login correspondiente al token
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <param name="update">Indica si se actualiza el tiempo del usuario. Por defecto, true</param>
        /// <returns>Objeto login del usuario</returns>
        public login GetLogin(SecurityToken token, bool update = true)
        {
            var user = GetLogonUser(token);
            var timeout = int.Parse(ConfigurationManager.AppSettings["timeout"]);
            if (DateTime.UtcNow.Subtract(user.dateissue).Minutes > timeout)
                throw new UnauthorizedAccessException(
                    "Se agotó el tiempo de sesión. Por favor, vuelva a entrar sus credenciales.");
            user.dateissue = DateTime.UtcNow;
            auxiliar_context.SaveChanges();

            return auxiliar_context.alias.Where(a => a.email == token.Username).Select(a => a.login).SingleOrDefault();
        }
        public login GetLoginCuote(string username, bool update = true)
        {
            var user = GetLogonUserCuote(username);
            /*var timeout = int.Parse(ConfigurationManager.AppSettings["timeout"]);
            if (DateTime.UtcNow.Subtract(user.dateissue).Minutes > timeout)
                throw new UnauthorizedAccessException(
                    "Se agotó el tiempo de sesión. Por favor, vuelva a entrar sus credenciales.");
            user.dateissue = DateTime.UtcNow;*/
            auxiliar_context.SaveChanges();

            return auxiliar_context.alias.Where(a => a.email == username).Select(a => a.login).SingleOrDefault();
        }
        public login GetLoginCuotePorLogin(int loginId, bool update = true)
        {
            var user = GetLogonUserCuotePorLogin(loginId);
            /*var timeout = int.Parse(ConfigurationManager.AppSettings["timeout"]);
            if (DateTime.UtcNow.Subtract(user.dateissue).Minutes > timeout)
                throw new UnauthorizedAccessException(
                    "Se agotó el tiempo de sesión. Por favor, vuelva a entrar sus credenciales.");
            user.dateissue = DateTime.UtcNow;*/
            auxiliar_context.SaveChanges();

            return auxiliar_context.alias.Where(a => a.idLogin == loginId).Select(a => a.login).SingleOrDefault();
        }

        /// <summary>
        /// Elimina al usuario de la tabla de autentificados
        /// </summary>
        /// <param name="token">Token de autentificación del usuario</param>
        public void LogoutUser(SecurityToken token)
        {
            var user = token.Username;
            if (token.Username.Contains("/"))
                user = token.Username.Substring(1 + token.Username.LastIndexOf("/"));
            var timeout = int.Parse(ConfigurationManager.AppSettings["timeout"]);

            foreach (var userlogon in
                auxiliar_context.userlogon.ToList().Where(
                    userlogon =>
                        (userlogon.alias.email == user && userlogon.token == token.Token) ||
                        DateTime.UtcNow.Subtract(userlogon.dateissue).TotalMinutes > timeout))
                auxiliar_context.userlogon.DeleteObject(userlogon);

            /*foreach (var userlogon in
                auxiliar_context.userlogon.ToList().Where(
                    userlogon =>
                    (userlogon.alias.email == user && userlogon.token == token.Token) ||
                    DateTime.UtcNow.Subtract(userlogon.dateissue).Minutes > timeout))
                auxiliar_context.userlogon.DeleteObject(userlogon);
             * 
             */ 

            auxiliar_context.SaveChanges();
        }

        /// <summary>
        /// Autentifica a un usuario
        /// </summary>
        /// <param name="name">Email del usuario</param>
        /// <param name="password">Contraseña del usuario</param>
        /// <returns>Token de autentificación</returns>
        public SecurityToken Authenticate(string name, string password)
        {
            var person = GetLogin(name);
            if (person == null) return new SecurityToken();
            if (_SHA256(password) != person.password)
                return new SecurityToken();
            var p = new SecurityToken
                        {
                            Username = name,
                            Token = LogonUser(name)
                        };
            return p;
        }

        /// <summary>
        /// Autentifica a un usuario
        /// </summary>
        /// <param name="name">Email del usuario</param>
        /// <param name="password">Contraseña del usuario</param>
        /// <returns>Token de autentificación</returns>
        public SecurityInfoToken AuthenticateCuote(string name, string password)
        {
            var person = GetLogin(name);
            if (person == null) return new SecurityInfoToken();
            if (_SHA256(password) != person.password)
                return new SecurityInfoToken();
            var p = new SecurityInfoToken
            {
                Username = name,
                Token = LogonUser(name),
                LoginId = person.idLogin.ToString()
               
            };
            return p;
        }

        /// <summary>
        /// Autentifica a un usuario
        /// </summary>
        /// <param name="name">Email del usuario</param>
        /// <param name="password">Contraseña del usuario</param>
        /// <returns>Token de autentificación</returns>
        public SecurityInfoToken AuthenticateTrabajador(string name, string password)
        {
            var person = GetLoginTrabajador(name);
            if (person == null) return new SecurityInfoToken();
            if (_SHA256(password) != person.password)
                return new SecurityInfoToken();
            var p = new SecurityInfoToken
            {
                Username = name,
                Token = LogonUser(name),
                LoginId = person.idLogin.ToString()
            };
            return p;
        }

        /// <summary>
        /// Autentifica a un usuario
        /// </summary>
        /// <param name="name">Email del usuario</param>
        /// <param name="password">Contraseña del usuario</param>
        /// <returns>Token de autentificación</returns>
        public SecurityInfoToken AuthenticateEstudiante(string name, string password)
        {
            var person = GetLoginEstudiante(name);
            if (person == null) return new SecurityInfoToken();
            if (_SHA256(password) != person.password)
                return new SecurityInfoToken();
            var p = new SecurityInfoToken
            {
                Username = name,
                Token = LogonUser(name),
                LoginId = person.idLogin.ToString()
            };
            return p;
        }

        #endregion

        #region Data queries

        #region Auxiliar methods

        /// <summary>
        /// Obtiene los datos extras de la persona, almacenados en el directorio y en los sistemas (web services) registrados
        /// </summary>
        /// <param name="idLogin">Llave del usuario</param>
        /// /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Lista de datos adicionales</returns>
        private List<DatosExtra> GetExtraData(int idLogin, SecurityToken token)
        {
            var result = new List<DatosExtra>();
            var extra_data = auxiliar_context.extra_data.Where(e => e.idLogin == idLogin);
            if (extra_data.Count() > 0)
            {
                var dict = JsonFx.Json.JsonReader.Deserialize<KeyValue[]>(extra_data.First().data).ToList();
                result.AddRange(
                    dict.Select(
                        keyValue => new DatosExtra { Dominio = "Perfil", Llave = keyValue.Key, Valor = keyValue.Value }));
            }
            var webservices = auxiliar_context.webservices.Where(ws => ws.idLogin == idLogin);
            foreach (var webService in webservices)
                try
                {
                    var dict = DynamicWSInvocation(webService.url, webService.method, token);
                    result.AddRange(
                        dict.Select(
                            keyValue =>
                            new DatosExtra { Dominio = webService.url, Llave = keyValue.Key, Valor = keyValue.Value }));
                }
                catch (Exception)
                {
                    continue;
                }
            return result;
        }

        /// <summary>
        /// Obtiene los datos extras de la persona almacenados en los sistemas (web services) registrados
        /// </summary>
        /// <param name="url">Url del web s</param>
        /// <param name="method"></param>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Lista de datos adicionales</returns>
        private static IEnumerable<KeyValue> DynamicWSInvocation(string url, string method, SecurityToken token)
        {
            var response = WSInvocation(url, method, token);
            // Analizando la respuesta
            var list = new List<KeyValue>();
            if (response != null)
                if (response.GetType().IsArray)
                    foreach (var item in (object[])response)
                    {
                        var key_value = new KeyValue();
                        var keyProp = item.GetType().GetProperty("campo");
                        var keyField = item.GetType().GetField("campo");
                        var valueProp = item.GetType().GetProperty("valor");
                        var valueField = item.GetType().GetField("valor");
                        if ((keyProp == null && keyField == null) || (valueProp == null && valueField == null))
                            throw new ArgumentException("El objeto de la lista está mal formado.");
                        key_value.Key = keyProp != null
                                            ? (string)keyProp.GetValue(item, null)
                                            : (string)keyField.GetValue(item);
                        key_value.Value = valueProp != null
                                              ? (string)valueProp.GetValue(item, null)
                                              : (string)valueField.GetValue(item);
                        list.Add(key_value);
                    }
            return list;
        }


        /// <summary>
        /// Ejecuta y devuelve el resultado de un web service registrado
        /// </summary>
        /// <param name="url">Url del servicio registrado</param>
        /// <param name="method">Metodo a ejecutar</param>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns></returns>
        private static object WSInvocation(string url, string method, SecurityToken token)
        {
            var uri = new Uri(url);
            var webRequest = WebRequest.Create(uri);
            //incluir la seguridad
            var resp = webRequest.GetResponse();
            var requestStream = resp.GetResponseStream();
            var bytes = new byte[resp.ContentLength];
            if (requestStream == null) return null;
            requestStream.Read(bytes, 0, bytes.Length);
            // Obteniendo el WSDL del web service
            var sd = ServiceDescription.Read(requestStream);
            var sdName = sd.Services[0].Name;
            // Inicializando la descripción del web service
            var servImport = new ServiceDescriptionImporter();
            servImport.AddServiceDescription(sd, String.Empty, String.Empty);
            servImport.ProtocolName = "Soap";
            servImport.CodeGenerationOptions = CodeGenerationOptions.GenerateProperties;
            var nameSpace = new CodeNamespace();
            var codeCompileUnit = new CodeCompileUnit();
            codeCompileUnit.Namespaces.Add(nameSpace);
            // Warnings
            var warnings = servImport.Import(nameSpace, codeCompileUnit);
            if (warnings != 0) return null;
            var stringWriter = new StringWriter(CultureInfo.CurrentCulture);
            var prov = new CSharpCodeProvider();
            prov.GenerateCodeFromNamespace(nameSpace, stringWriter, new CodeGeneratorOptions());
            // Compilando el ensamblado con las referencias necesarias y ejecutando el método del web service
            var assemblyReferences = new[] { "System.Web.Services.dll", "System.Xml.dll" };
            var param = new CompilerParameters(assemblyReferences)
                            {
                                GenerateExecutable = false,
                                GenerateInMemory = true,
                                TreatWarningsAsErrors = false,
                                WarningLevel = 4
                            };
            var results = prov.CompileAssemblyFromDom(param, codeCompileUnit);
            var assembly = results.CompiledAssembly;
            var service = assembly.GetType(sdName);
            var obj = Activator.CreateInstance(service);
            var methodInfo = service.GetMethod(method);
            return methodInfo.Invoke(obj, new object[] { token.Username, token.Token });
        }

        /// <summary>
        /// Devuelve un arbol de areas a partir de un area inicial
        /// </summary>
        /// <param name="child_nodes">Subarbol de root</param>
        /// <param name="root">Area raiz del arbol</param>
        private void SetHierarchy(ref List<Areas> child_nodes, string root)
        {
            var sons = from a in context_uh.RH_Unidades_Organizativas
                       where a.Id_DireccionPadre.ToLower() == root && a.Id_Direccion != root
                       select a;

            foreach (var area in sons)
            {
                var new_tree = new Areas { Id = area.Id_Direccion.ToLower(), Nombre = area.Desc_Direccion };
                var list = new List<Areas>();
                SetHierarchy(ref list, new_tree.Id);
                new_tree.Childs = list;
                child_nodes.Add(new_tree);


            }
        }

        /// <summary>
        /// Obtiene los trabajadores de un conjunto de areas
        /// </summary>
        /// <param name="areas">Areas donde buscar</param>
        /// <param name="assets">Asset donde buscar</param>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Lista de trabajadores</returns>
        private List<Trabajador> GetEmployees(Areas areas, int assets, SecurityToken token)
        {
            var list = (from a in context_uh.Empleados_Gral
                        where a.Id_Direccion.ToLower() == areas.Id.ToLower() && a.Baja == false && a.Assets == assets
                        select a).ToList().Select(e => new Trabajador
                                                           {
                                                               Correos =
                                                                   auxiliar_context.alias.Where(
                                                                       alia =>
                                                                       alia.login.id_empleado == e.Id_Empleado &&
                                                                       alia.login.assets == e.Assets).ToList().Select(
                                                                           alia =>
                                                                           new KeyValue
                                                                               {
                                                                                   Key = alia.idAlias.ToString(),
                                                                                   Value = alia.email
                                                                               }).ToList(),
                                                               DatosAssets = e,
                                                               //DatosExtras =
                                                               //    GetExtraData(
                                                               //        auxiliar_context.login.Single(
                                                               //            l => l.id_empleado == e.Id_Empleado).idLogin, token)
                                                           }).ToList();
            foreach (var child in areas.Childs)
                list.AddRange(GetEmployees(child, assets, token));
            return list;
        }

        #endregion

        /// <summary>
        /// Obtiene todos los datos de una persona
        /// </summary>
        /// <param name="token">Token de autentificación del usuario</param>
        /// <param name="pWidth">Ancho, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <param name="pHeight">Altura, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <returns>Datos de la persona autentificada</returns>
        public Trabajador GetTrabajadorData(SecurityToken token, int pWidth = 16, int pHeight = 16)
        {
            login person;
            try
            {
                person = GetLogin(token);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            var personas =
                context_uh.Empleados_Gral.Where(x => x.Id_Empleado == person.id_empleado && person.assets == x.Assets);
            if (personas.Count() != 1)
                return null;
            var p = personas.First();
            if (p.Foto != null && p.Foto.Length > 0)
                p.Foto = ResizeFromStream(pWidth, pHeight, new MemoryStream(p.Foto.ToArray())).GetBuffer();
            var correos =
                auxiliar_context.alias.Where(a => a.idLogin == person.idLogin).ToList().Select(
                    a => new KeyValue
                             {
                                 Key = a.idAlias.ToString(),
                                 Value = a.email
                             });

            var extraData = GetExtraData(person.idLogin, token);
            

            return new Trabajador { Correos = correos.ToList(), DatosAssets = p, DatosExtras = extraData };
        }

        /// <summary>
        /// Obtiene todos los datos de una persona
        /// </summary>
        /// <param name="username">Token de autentificación del usuario</param>
        /// <param name="pWidth">Ancho, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <param name="pHeight">Altura, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <returns>Datos de la persona autentificada</returns>
        public TrabajadorInfoCuote GetTrabajadorDataCuotePorLogin(int loginId, int pWidth = 16, int pHeight = 16)
        {
            login person;
            try
            {
                person = GetLoginCuotePorLogin(loginId);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            var personas =
                context_uh.Empleados_Gral.Where(x => x.Id_Empleado == person.id_empleado && person.assets == x.Assets);
            if (personas.Count() != 1)
                return null;
            var p = personas.First();
            if (p.Foto != null && p.Foto.Length > 0)
                p.Foto = ResizeFromStream(pWidth, pHeight, new MemoryStream(p.Foto.ToArray())).GetBuffer();
            var correos =
                auxiliar_context.alias.Where(a => a.idLogin == person.idLogin).ToList().Select(
                    a => new KeyValue
                    {
                        Key = a.idAlias.ToString(),
                        Value = a.email
                    });

            var contratos = context_uh.RH_Contratos_Tipos.Where(x => x.Id_Tipo_Contrato == p.Id_Tipo_Contrato && x.Assets == p.Assets);
            var cont = contratos.First();

            var cargos = context_uh.RH_Cargos.Where(x => x.Id_Cargo == p.Id_Cargo && x.Assets == p.Assets);
            var carg = cargos.First();

            var catOcupacionals =
                context_uh.RH_Subcategorias_Ocupacionales.Where(
                    x =>
                    x.Id_Categoria == p.Id_Categoria && x.Id_Subcategoria == p.Id_Subcategoria && x.Assets == p.Assets);

            string docente = "No";
            string catDocente = "Ninguna";
            if (p.Docente)
            {
                docente = "Si";
                /*var catDocentes =
                    context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_DI);
                catDocente = catDocentes.First().Desc_Categoria_DI;*/
            }
            /*else
            {
                if (p.Id_Subcategoria == "15" || p.Id_Subcategoria == "12")
                {
                    var catDocentes =
                        context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_IT);
                    catDocente = catDocentes.First().Desc_Categoria_DI;
                }
            }*/
            if (p.Id_Categoria_DI != null)
            {
                if (p.Id_Categoria_DI != "")
                {
                    int id_cat_DI = int.Parse(p.Id_Categoria_DI);
                    if (id_cat_DI > 0)
                    {
                        var catDocentes =
                        context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_DI);
                        catDocente = catDocentes.First().Desc_Categoria_DI;
                    }
                }
            }
            if (p.Id_Categoria_IT != null)
            {
                if (p.Id_Categoria_IT != "")
                {
                    int id_cat_IT = int.Parse(p.Id_Categoria_IT);
                    if (id_cat_IT > 0)
                    {
                        var catDocentes =
                        context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_IT);
                        catDocente = catDocentes.First().Desc_Categoria_DI;
                    }
                }
            }

            string adiestrado = "No";
            if (cont.Id_Tipo_Contrato == "3") adiestrado = "Si";

            string espPrincipal = "No";
            if (p.Asignacion_por_Cargo_CP) espPrincipal = "Si";

            string cargoTemp = carg.Desc_Cargo.ToLower();
            string cargoCod = carg.Id_Cargo;
            string adminArea = "No";
            if (cargoTemp.IndexOf("jefe") > -1 && ((cargoTemp.IndexOf("departamento") > 0 && (cargoCod == "0002" || cargoCod == "0016")) || (cargoTemp.IndexOf("secc") > 0 && cargoCod == "0019"))) adminArea = "Si";

            //string adminRed = "No";
            // if ( (cargoTemp.IndexOf("tecnico") > -1 && cargoTemp.IndexOf("ciencia") > 0 && cargoTemp.IndexOf("informatica") > 0) || (cargoTemp.IndexOf("especialista") > -1 && cargoTemp.IndexOf("ciencia") > 0 && cargoTemp.IndexOf("informatica") > 0) )adminRed = "Si";

            string catOcupacional = catOcupacionals.First().Desc_Subcategoria.ToLower();

            string tecnicoGeneral = "No";
            if ((catOcupacional.IndexOf("tecnico") > -1 || catOcupacional.IndexOf("técnico") > -1) && cargoTemp.IndexOf("informatica") < 0) tecnicoGeneral = "Si";
            if (cargoCod == "0002" || cargoCod == "0016" || cargoCod == "0019") tecnicoGeneral = "No";

            string tecnicoInformatico = "No";
            if ((catOcupacional.IndexOf("tecnico") > -1 || catOcupacional.IndexOf("técnico") > -1) && cargoTemp.IndexOf("informatica") > 0) tecnicoInformatico = "Si";

            //string especialistaInformatico = "No";
            //if (cargoTemp.IndexOf("especialista") > -1 && cargoTemp.IndexOf("informatica") > 0) especialistaInformatico = "Si";

            
            string cuadro = "No";
            if (p.Id_Categoria == "5") cuadro = "Si";

            // Para determinar si el tipo de contraro final es Determinado, Indeterminado o Adiestramiento.
            var tipoContratoFinal = "";
            if (cont.Id_Tipo_Contrato == "1"
                || cont.Id_Tipo_Contrato == "5"
                )
                tipoContratoFinal = "Indeterminado";
            else
                if (cont.Id_Tipo_Contrato == "3"
                    || cont.Id_Tipo_Contrato == "8"
                    || cont.Id_Tipo_Contrato == "9"
                )
                    tipoContratoFinal = "Adiestramiento";
                else
                    tipoContratoFinal = "Determinado";

            var trab = new TrabajadorInfoCuote
            {
                Id = p.Id_Empleado,
                CatOcupacional = catOcupacionals.First().Desc_Subcategoria,
                Docente = docente,
                CatDocenteInvestigativa = catDocente,
                Cuadro = cuadro,
                Contrato = tipoContratoFinal,//cont.Desc_Tipo_Contrato,
                Cargo = carg.Desc_Cargo,
                Adiestrado = adiestrado,
                EspecialistaPrincipal = espPrincipal,
                AdministradorArea = adminArea,
                Tecnico = tecnicoGeneral,
                TecnicoInformatico = tecnicoInformatico,
                Asset = p.Assets.ToString()
            };
            return trab;

            //var extraData = GetExtraData(person.idLogin, token);
            //var extraData = new List<DatosExtra>();

            // return new Trabajador { Correos = correos.ToList(), DatosAssets = p, DatosExtras = extraData };
        }
        /// <summary>
        /// Obtiene todos los datos de una persona
        /// </summary>
        /// <param name="username">Token de autentificación del usuario</param>
        /// <param name="pWidth">Ancho, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <param name="pHeight">Altura, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <returns>Datos de la persona autentificada</returns>
        public TrabajadorInfoCuote GetTrabajadorDataCuote(string username, int pWidth = 16, int pHeight = 16)
        {   
            login person;
            try
            {
                //person = GetLoginCuote(username);
                person = (from item in auxiliar_context.alias
                                where item.email == username
                                select item.login).ToList().First();
            }
            //catch (UnauthorizedAccessException)
            catch (Exception)
            {
                return new TrabajadorInfoCuote
                {
                    Id = "Error",
                    CatOcupacional = "Error",
                    Docente = "Error",
                    CatDocenteInvestigativa = "Error",
                    Cuadro = "Error",
                    Contrato = "Error",
                    Cargo = "Error",
                    Adiestrado = "Error",
                    EspecialistaPrincipal = "Error",
                    AdministradorArea = "Error",
                    Tecnico = "Error",
                    TecnicoInformatico = "Error",
                    Asset = "Error"
                };

                return null;
            }
            var personas =
                context_uh.Empleados_Gral.Where(x => x.Id_Empleado == person.id_empleado && person.assets == x.Assets);
            if (personas.Count() != 1)
                return null;
            var p = personas.First();
            if (p.Foto != null && p.Foto.Length > 0)
                p.Foto = ResizeFromStream(pWidth, pHeight, new MemoryStream(p.Foto.ToArray())).GetBuffer();
            var correos =
                auxiliar_context.alias.Where(a => a.idLogin == person.idLogin).ToList().Select(
                    a => new KeyValue
                    {
                        Key = a.idAlias.ToString(),
                        Value = a.email
                    });

            var contratos = context_uh.RH_Contratos_Tipos.Where(x => x.Id_Tipo_Contrato == p.Id_Tipo_Contrato && x.Assets == p.Assets);
            var cont = contratos.First();

            var cargos = context_uh.RH_Cargos.Where(x => x.Id_Cargo == p.Id_Cargo && x.Assets == p.Assets);
            var carg = cargos.First();

            var catOcupacionals =
                context_uh.RH_Subcategorias_Ocupacionales.Where(
                    x =>
                    x.Id_Categoria == p.Id_Categoria && x.Id_Subcategoria == p.Id_Subcategoria && x.Assets == p.Assets);

            string docente = "No";
            string catDocente = "Ninguna";
            if (p.Docente)
            {
                docente = "Si";
                /*var catDocentes =
                    context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_DI);
                catDocente = catDocentes.First().Desc_Categoria_DI;*/
            }
            /*else
            {
                if (p.Id_Subcategoria == "15" || p.Id_Subcategoria == "12")
                {
                    var catDocentes =
                        context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_IT);
                    catDocente = catDocentes.First().Desc_Categoria_DI;
                }
            }*/
            if (p.Id_Categoria_DI != null)
            {
                if (p.Id_Categoria_DI != "")
                {
                    int id_cat_DI = int.Parse(p.Id_Categoria_DI);
                    if (id_cat_DI > 0)
                    {
                        var catDocentes =
                        context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_DI);
                        catDocente = catDocentes.First().Desc_Categoria_DI;
                    }
                }
            }
            if (p.Id_Categoria_IT != null)
            {
                if (p.Id_Categoria_IT != "")
                {
                    int id_cat_IT = int.Parse(p.Id_Categoria_IT);
                    if (id_cat_IT > 0)
                    {
                        var catDocentes =
                        context_uh.RH_Categorias_Docente_Invest.Where(x => x.Id_Categoria_DI == p.Id_Categoria_IT);
                        catDocente = catDocentes.First().Desc_Categoria_DI;
                    }
                }
            }

            string adiestrado = "No";
            if (cont.Id_Tipo_Contrato == "3") adiestrado = "Si";

            string espPrincipal = "No";
            if (p.Asignacion_por_Cargo_CP) espPrincipal = "Si";

            string cargoTemp = carg.Desc_Cargo.ToLower();
            string cargoCod = carg.Id_Cargo;
            string adminArea = "No";
            if (cargoTemp.IndexOf("jefe") > -1 && ((cargoTemp.IndexOf("departamento") > 0 && (cargoCod == "0002" || cargoCod == "0016")) || (cargoTemp.IndexOf("secc") > 0 && cargoCod == "0019"))) adminArea = "Si";

            //string adminRed = "No";
            // if ( (cargoTemp.IndexOf("tecnico") > -1 && cargoTemp.IndexOf("ciencia") > 0 && cargoTemp.IndexOf("informatica") > 0) || (cargoTemp.IndexOf("especialista") > -1 && cargoTemp.IndexOf("ciencia") > 0 && cargoTemp.IndexOf("informatica") > 0) )adminRed = "Si";

            string catOcupacional = catOcupacionals.First().Desc_Subcategoria.ToLower();

            string tecnicoGeneral = "No";
            if ((catOcupacional.IndexOf("tecnico") > -1 || catOcupacional.IndexOf("técnico") > -1) && cargoTemp.IndexOf("informatica") < 0) tecnicoGeneral = "Si";
            if (cargoCod == "0002" || cargoCod == "0016" || cargoCod == "0019") tecnicoGeneral = "No";

            string tecnicoInformatico = "No";
            if ((catOcupacional.IndexOf("tecnico") > -1 || catOcupacional.IndexOf("técnico") > -1) && cargoTemp.IndexOf("informatica") > 0) tecnicoInformatico = "Si";

            //string especialistaInformatico = "No";
            //if (cargoTemp.IndexOf("especialista") > -1 && cargoTemp.IndexOf("informatica") > 0) especialistaInformatico = "Si";


            string cuadro = "No";
            if (p.Id_Categoria == "5") cuadro = "Si";


            // Para determinar si el tipo de contraro final es Determinado, Indeterminado o Adiestramiento.
            var tipoContratoFinal = "";
            if (cont.Id_Tipo_Contrato == "1"
                || cont.Id_Tipo_Contrato == "5"
                )
                tipoContratoFinal = "Indeterminado";
            else
                if (cont.Id_Tipo_Contrato == "3"
                    || cont.Id_Tipo_Contrato == "8"
                    || cont.Id_Tipo_Contrato == "9"
                )
                    tipoContratoFinal = "Adiestramiento";
                else
                    tipoContratoFinal = "Determinado";
            

            var trab = new TrabajadorInfoCuote
            {
                Id = p.Id_Empleado,
                CatOcupacional = catOcupacionals.First().Desc_Subcategoria,
                Docente = docente,
                CatDocenteInvestigativa = catDocente,
                Cuadro = cuadro,
                Contrato = tipoContratoFinal,//cont.Desc_Tipo_Contrato,
                Cargo = carg.Desc_Cargo,
                Adiestrado = adiestrado,
                EspecialistaPrincipal = espPrincipal,
                AdministradorArea = adminArea,
                Tecnico = tecnicoGeneral,
                TecnicoInformatico = tecnicoInformatico,
                Asset = p.Assets.ToString()
            };
            return trab;

            //var extraData = GetExtraData(person.idLogin, token);
            //var extraData = new List<DatosExtra>();

           // return new Trabajador { Correos = correos.ToList(), DatosAssets = p, DatosExtras = extraData };
        }

        /// <summary>
        /// Obtiene la(s) plantilla(s) de un área dentro de un asset.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="assets">Asset del Area</param>
        /// <param name="id_area">Id del Area</param>
        /// <param name="subAreas">si subAreas es true incluye las plantillas de las subareas</param>
        /// <returns></returns>
        public List<Plantilla> Plantillas(SecurityToken token, byte assets, string id_area, bool subAreas)
        {
            //login person;
            //try
            //{
            //    person = GetLogin(token);
            //}
            //catch (UnauthorizedAccessException)
            //{
            //    return null;
            //}
            // TODO: chequear que el empleado es jefe o tiene derecho a ver a los trabajadores

            //obteniendo la jerarquia de areas
            var areas = subAreas ? SetHierarchy(id_area).ToList() : new[] { id_area };
            var result = new List<Plantilla>(areas.Count());
            result.AddRange(areas.Select(area => (from plantilla in context_uh.RH_Plantilla_Detalles
                                                  join p in context_uh.Empleados_Gral on
                                                      new { plantilla.Assets, plantilla.Id_Direccion, plantilla.Id_Cargo }
                                                      equals new { p.Assets, p.Id_Direccion, p.Id_Cargo }
                                                  join cargo in context_uh.RH_Cargos on
                                                      new { Key = p.Id_Cargo, Value = p.Assets } equals
                                                      new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                                                  join _area in context_uh.RH_Unidades_Organizativas on
                                                      new { Key = p.Id_Direccion, Value = p.Assets } equals
                                                      new { Key = _area.Id_Direccion, Value = _area.Assets }
                                                  join docenteInvest in context_uh.RH_Categorias_Docente_Invest on
                                                      p.Id_Categoria_DI equals docenteInvest.Id_Categoria_DI into
                                                      docente
                                                  from p_d in docente.DefaultIfEmpty()
                                                  join grado in context_uh.RH_Grados_Cientificos on
                                                      p.Id_Grado_Cientifico equals grado.Id_Grado_Cientifico into grado
                                                  //left join
                                                  from p_g in grado.DefaultIfEmpty()
                                                  //left join
                                                  where plantilla.Id_Direccion == area
                                                  select new Trabajador_Publico
                                                             {
                                                                 Id = p.Id_Empleado,
                                                                 Grado_Cientifico =
                                                                     p_g != null ? p_g.Desc_Grado_Cientifico : null,
                                                                 Assets = p.Assets,
                                                                 Nombres = p.Nombre,
                                                                 Primer_Apellido = p.Apellido_1,
                                                                 Segundo_Apellido = p.Apellido_2,
                                                                 CategoriaDI =
                                                                     p_d != null ? p_d.Desc_Categoria_DI : null,
                                                                 Cargo = cargo.Desc_Cargo,
                                                                 Centro = p.Id_CCosto,
                                                                 Area = _area.Desc_Direccion,
                                                                 Sexo = p.Sexo,
                                                                 Foto = p.Foto
                                                             })).Select(
                                                                 query =>
                                                                 new Plantilla { Trabajadores = query.ToList<Trabajador_Publico>() }));

            return result;
        }

        /// <summary>
        /// Obtiene los detalles de la plantilla de un un área dentro de un asset y si subAreas es true incluye las plantillas de las subareas.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="assets">Asset del Area</param>
        /// <param name="id_area">Id del Area</param>
        /// <param name="subAreas">si subAreas es true incluye las plantillas de las subareas</param>
        /// <returns></returns>
        public List<Plantilla_Area> PlantillaDetalles(SecurityToken token, byte assets, string id_area, bool subAreas)
        {

            //obteniendo la jerarquia de areas
            var areas = subAreas ? SetHierarchy(id_area).ToList() : new[] { id_area };
            return areas.Select(area => new Plantilla_Area
                                            {
                                                Id_Area = area,
                                                Assets = assets,
                                                Cargos = (from plantilla in context_uh.RH_Plantilla_Detalles
                                                          where
                                                              plantilla.Id_Direccion == area &&
                                                              plantilla.Assets == assets
                                                          select new Plantilla_Detalles
                                                                     {
                                                                         Id_Cargo = plantilla.Id_Cargo,
                                                                         Descripcion = plantilla.Desc_Cargo,
                                                                         Aprobadas = plantilla.Aprobadas
                                                                     }).ToList()
                                            }).ToList();
        }

        /// <summary>
        /// Obtiene todos los datos de un estudiante
        /// </summary>
        /// <param name="token">Token de autentificación del usuario</param>
        /// <param name="filter">Filtro de seleccion de los datos del estudiante</param>
        /// <returns>Datos del estudiante autentificado</returns>
        public studentDTO GetEstudianteData(SecurityToken token, FiltrosEstudiante filter)
        {
            try
            {
                var person = GetLogin(token);
                var student = new studentDTO();
                InitializeStudentsWS();

                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var ci = serv.Get_CI_by_SigenuId(person.id_empleado);

                // TODO: Ver como aplicar el filtro
                switch (filter)
                {
                    case FiltrosEstudiante.Personal:
                        {
                            student.personalData =
                                students.getStudentFilePersonalData(new getStudentFilePersonalData { identification = ci }).
                                    Last();

                            break;
                        }
                    case FiltrosEstudiante.Docentes:
                        {
                            student.docentData =
                                students.getStudentFileDocentData(new getStudentFileDocentData { identification = ci }).
                                    Last();
                            break;
                        }
                    case FiltrosEstudiante.Madre:
                        {
                            student.motherData =
                                students.getStudentFileMotherData(new getStudentFileMotherData { identification = ci }).
                                    Last();
                            break;
                        }
                    case FiltrosEstudiante.Padre:
                        {
                            student.fatherData =
                                students.getStudentFileFatherData(new getStudentFileFatherData { identification = ci }).
                                    Last();
                            break;
                        }
                    case FiltrosEstudiante.Laboral:
                        {
                            student.laboralData =
                                students.getStudentFileLaboralData(new getStudentFileLaboralData { identification = ci }).
                                    Last();
                            break;
                        }
                    case FiltrosEstudiante.Militar:
                        {
                            student.militarData =
                                students.getStudentFileMilitarData(new getStudentFileMilitarData { identification = ci }).
                                    Last();
                            break;
                        }
                    default:
                        {
                            student =
                                students.getStudentFileAllData(new getStudentFileAllData { identification = ci }).
                                    Last();
                            break;
                        }
                }

                //student = students.getStudentFileAllData(new getStudentFileAllData { identification = ci }).Last();

                return student;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Obtiene todos los datos de un estudiante
        /// </summary>
        /// <param name="username">Token de autentificación del usuario</param>
        /// <param name="filter">Filtro de seleccion de los datos del estudiante</param>
        /// <returns>Datos del estudiante autentificado</returns>
        public EstudianteInfoCuote GetEstudianteDataCuote22(string username, FiltrosEstudiante filter)
        {
            try
            {
                var person = GetLoginCuote(username);
                var student = new studentDTO();
                InitializeStudentsWS();

                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var ci = serv.Get_CI_by_SigenuId(person.id_empleado);

                // TODO: Ver como aplicar el filtro
                switch (filter)
                {
                    case FiltrosEstudiante.Personal:
                        {
                            student.personalData =
                                students.getStudentFilePersonalData(new getStudentFilePersonalData { identification = ci }).
                                    First();

                            break;
                        }
                    case FiltrosEstudiante.Docentes:
                        {
                            student.docentData =
                                students.getStudentFileDocentData(new getStudentFileDocentData { identification = ci }).
                                    First();
                            break;
                        }
                    case FiltrosEstudiante.Madre:
                        {
                            student.motherData =
                                students.getStudentFileMotherData(new getStudentFileMotherData { identification = ci }).
                                    First();
                            break;
                        }
                    case FiltrosEstudiante.Padre:
                        {
                            student.fatherData =
                                students.getStudentFileFatherData(new getStudentFileFatherData { identification = ci }).
                                    First();
                            break;
                        }
                    case FiltrosEstudiante.Laboral:
                        {
                            student.laboralData =
                                students.getStudentFileLaboralData(new getStudentFileLaboralData { identification = ci }).
                                    First();
                            break;
                        }
                    case FiltrosEstudiante.Militar:
                        {
                            student.militarData =
                                students.getStudentFileMilitarData(new getStudentFileMilitarData { identification = ci }).
                                    First();
                            break;
                        }
                    default:
                        {
                            student =
                                students.getStudentFileAllData(new getStudentFileAllData { identification = ci }).
                                    First();
                            break;
                        }
                }
                var est = new EstudianteInfoCuote
                {
                    Anno = student.docentData.year
                };
                return est;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public string Estudiante(string username)
        {
            //var person = GetLoginCuote(username);

            var person = (from item in auxiliar_context.login
                          join aliase in auxiliar_context.alias on item.idLogin equals aliase.idLogin
                          where aliase.email == username
                          select new {Id = item.id_empleado}).ToList().First();
                    

            InitializeStudentsWS();
            SigenuWebServices.Service serv = new SigenuWebServices.Service();

            var year = serv.Get_Year_by_SigenuId(person.Id);
            var ci = serv.Get_CI_by_SigenuId(person.Id);

            var s = students.getStudentFileAllData(new getStudentFileAllData { identification = ci }).LastOrDefault();

            return s.docentData.courseType;
        }

        /// <summary>
        /// Obtiene todos los datos de un estudiante
        /// </summary>
        /// <param name="username">Token de autentificación del usuario</param>
        /// <param name="filter">Filtro de seleccion de los datos del estudiante</param>
        /// <returns>Datos del estudiante autentificado</returns>
        public EstudianteInfoCuote GetEstudianteDataCuote(string username, FiltrosEstudiante filter)
        {
            try
            {
                var person = (from item in auxiliar_context.login
                              join aliase in auxiliar_context.alias on item.idLogin equals aliase.idLogin
                              where aliase.email == username
                              select new { Id = item.id_empleado }).ToList().First();

                var student = new studentDTO();

                InitializeStudentsWS();
                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var year = serv.Get_Year_by_SigenuId(person.Id);


                var ci = serv.Get_CI_by_SigenuId(person.Id);
                var s = students.getStudentFileAllData(new getStudentFileAllData { identification = ci }).LastOrDefault();

                bool? authorized = null;
                if (s != null)
                    authorized = s.docentData.courseType.Trim() == "Curso Regular Diurno";

                var est = new EstudianteInfoCuote
                {
                    Anno = year.ToString(),
                    AccesoInternet = authorized.ToString()
                };
                return est;
            }
            catch (Exception)
            {
                return null;
            }
        }
        /// <summary>
        /// Obtiene todos los datos de un estudiante
        /// </summary>
        /// <param name="username">Token de autentificación del usuario</param>
        /// <param name="filter">Filtro de seleccion de los datos del estudiante</param>
        /// <returns>Datos del estudiante autentificado</returns>
        public EstudianteInfoCuote GetEstudianteDataCuotePorLogin(int loginId, FiltrosEstudiante filter)
        {

            try
            {
                var person = (from item in auxiliar_context.login
                              join aliase in auxiliar_context.alias on item.idLogin equals aliase.idLogin
                              where aliase.idLogin == loginId
                              select new { Id = item.id_empleado }).ToList().First();

                var student = new studentDTO();

                InitializeStudentsWS();
                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var year = serv.Get_Year_by_SigenuId(person.Id);


                var ci = serv.Get_CI_by_SigenuId(person.Id);
                var s = students.getStudentFileAllData(new getStudentFileAllData { identification = ci }).LastOrDefault();

                bool? authorized = null;
                if (s != null)
                    authorized = s.docentData.courseType.Trim() == "Curso Regular Diurno";

                var est = new EstudianteInfoCuote
                {
                    Anno = year.ToString(),
                    AccesoInternet = authorized.ToString()
                };
                return est;
            }
            catch (Exception)
            {
                return null;
            }
            
            /*
            try
            {
                var person = GetLoginCuotePorLogin(loginId);
                var student = new studentDTO();
                InitializeStudentsWS();

                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var year = serv.Get_Year_by_SigenuId(person.id_empleado);


                var est = new EstudianteInfoCuote
                {
                    Anno = year.ToString()
                };
                return est;
            }
            catch (Exception)
            {
                return null;
            }
          * */
        }
        /// <summary>
        /// Obtiene el identificador del estudiente en sigenu.
        /// </summary>
        /// <param name="token">Token de autentificación del usuario</param>
        public string GetEstudenteIdSigenu(SecurityToken token)
        {
            var person = GetLogin(token);
            return person.id_empleado;
        }

        /// <summary>
        /// Obtiene la foto de la persona
        /// </summary>
        /// <param name="token">Token de autentificación del usuario</param>
        /// <param name="pWidth">Ancho, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <param name="pHeight">Altura, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <returns>Foto de la persona autentificada</returns>
        public byte[] GetFoto(SecurityToken token, int pWidth = 16, int pHeight = 16)
        {
            login person;
            try
            {
                person = GetLogin(token);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            var personas =
                context_uh.Empleados_Gral.Where(x => x.Id_Empleado == person.id_empleado && person.assets == x.Assets);
            if (personas.Count() != 1)
                return null;
            var p = personas.First();
            if (p.Foto != null && p.Foto.Length > 0)
                return ResizeFromStream(pWidth, pHeight, new MemoryStream(p.Foto.ToArray())).GetBuffer();
            return new byte[0];
        }

        /// <summary>
        /// Listado de correos del usuario autentificado
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Lista de llave (id) valor (email) de correos</returns>
        public List<KeyValue> GetEmailsList(SecurityToken token)
        {
            login person;
            try
            {
                person = GetLogin(token);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            return
                person.alias.ToList().Select(a => new KeyValue { Key = a.idAlias.ToString(), Value = a.email }).ToList();
        }

        /// <summary>
        /// Obtiene los trabajadores subordinados
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Lista de trabajadores</returns>
        public List<Trabajador> GetMyEmployees(SecurityToken token)
        {
            login person;
            try
            {
                person = GetLogin(token);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            // TODO: chequear que el empleado es jefe o tiene derecho a ver a los trabajadores
            var boss = from a in context_uh.Empleados_Gral
                       where person.id_empleado == a.Id_Empleado && a.Baja == false && a.Assets == person.assets
                       select a;
            if (boss.Count() != 1)
                return null;

            var cargo = boss.First();

            //obteniendo la jerarquia de areas
            var areas = SetHierarchy(cargo.Id_Direccion);

            //obteniendo los trabajadores que pertenecen a mis (boss) areas
            return GetEmployees(areas, cargo.Assets, token);
        }

        #region Developer

        /// <summary>
        /// Obtiene los trabajadores subordinados
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Lista de trabajadores</returns>
        public List<Trabajador> GetMyEmployees(SecurityToken token, byte assets, string id_direccion)
        {
            //obteniendo la jerarquia de areas
            var areas = SetHierarchy(id_direccion);

            //obteniendo los trabajadores que pertenecen a mis (boss) areas
            return GetEmployees(areas, assets, token);
        }

        #endregion

        /// <summary>
        /// Devuelve una rama de la jerarquía de áreas, tomando id_direccion como raíz por defecto.
        /// </summary>
        /// <param name="id_direccion">Área raíz (Rectorado por defecto)</param>
        /// <returns>Árbol con id_direccion y listado de árboles hijos</returns>
        public Areas SetHierarchy(string id_direccion = "A0000")
        {
            id_direccion = !string.IsNullOrWhiteSpace(id_direccion) ? id_direccion : "A0000";
            if (context_uh.RH_Unidades_Organizativas.Count(u => u.Id_Direccion.ToLower() == id_direccion.ToLower()) == 0 &&
                !string.IsNullOrWhiteSpace(id_direccion))
                return new Areas();
            var area = context_uh.RH_Unidades_Organizativas.First(u => u.Id_Direccion == id_direccion);
            var nodes = new Areas
                            {
                                Id = id_direccion,
                                Nombre = area.Desc_Direccion
                            };
            var list = new List<Areas>();
            SetHierarchy(ref list, nodes.Id);
            nodes.Childs = list;



            return nodes;
        }

        /// <summary>
        /// Devuelve el ARBOL DE DEPENDENCIA para el rectorado; no es la jerarquia de areas del rectorado
        /// </summary>
        /// <returns></returns>
        public Areas AreasRectorado()
        {
            return new Areas()
                           {
                               Id = "A0000",
                               Nombre = "RECTORADO",
                               Childs = new List<Areas>
                                            {
                                                new Areas {Id = "a0010", Nombre = "DEPARTAMENTO DE CUADROS"},
                                                new Areas {Id = "a0030", Nombre = "DEPARTAMENTO JURIDICO"},
                                                new Areas {Id = "a0020", Nombre = "DEPARTAMENTO DE AUDITORIA"},
                                                new Areas {Id = "a1000", Nombre = "RECTORADO SECRETARIA GENERAL",
                                                            Childs = new List<Areas>
                                                                     {
                                                                         new Areas { Id = "a1100", Nombre = "RECTORADO SECRETARIA GENERAL ARCHIVO CENTRAL" }
                                                                     }
                                                    },
                                                new Areas {Id = "a1200", Nombre = "RECTORADO  COMISION PROVlNCIAL DE INGRESO"},
                                                new Areas {Id = "g0000", Nombre = "VICERECTORIA DE ATENCION A LOS RECURSOS HUMANOS"},
                                                new Areas {Id = "c0000", Nombre = "VICERECTORIA  DE ECONOMIA"},
                                                new Areas {Id = "b0000", Nombre = "VICERECTORIA (DOCENTE)",
                                                            Childs = new List<Areas>
                                                                {
                                                                    new Areas { Id = "b0004",Nombre = "DIRECCION DOCENTE METODOLOGICA"}
                                                                }
                                                    },
                                                new Areas { Id = "h0000", Nombre = "VICERECTORIA DE INVESTIGACION Y POSGRADO",
                                                            Childs = new List<Areas>
                                                                     {
                                                                         new Areas{Id = "a4000",Nombre ="CENTRO DE ESTUDIOS DE MIGRACION INTERNACIONAL"},
                                                                         new Areas{Id = "h0010",Nombre ="DEPARTAMENTO DE TRANSFERENCIA DE RESULTADOS DE INVESTIGACION"},
                                                                         new Areas{Id = "h0050",Nombre ="DIRECCION DE CIENCIA Y TECNICA"}
                                                                     }
                                                }
                                            }
                           };
        }

        /// <summary>
        /// Obtiene el promedio del estudiante
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Promedio del estudiante</returns>
        public valueDTO[] GetPuntosPromedio(SecurityToken token)
        {
            try
            {
                var person = GetLogin(token);
                InitializeEvaluationWS();

                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var ci = serv.Get_CI_by_SigenuId(person.id_empleado);

                return
                    evaluations.getStudentEvaluationAverage(new getStudentEvaluationAverage { identification = ci });
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Obtiene los puntos extras del estudiante
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Puntos extras del estudiante</returns>
        public valueDTO[] GetPuntosBonus(SecurityToken token)
        {
            try
            {
                var person = GetLogin(token);
                InitializeEvaluationWS();

                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var ci = serv.Get_CI_by_SigenuId(person.id_empleado);


                return
                    evaluations.getStudentEvaluationBonus(new getStudentEvaluationBonus { identification = ci });
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Obtiene los puntos de premio del estudiante
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <returns>Puntos de premio del estudiante</returns>
        public valueDTO[] GetPuntosExamenPremio(SecurityToken token)
        {
            try
            {
                var person = GetLogin(token);
                InitializeEvaluationWS();

                SigenuWebServices.Service serv = new SigenuWebServices.Service();
                var ci = serv.Get_CI_by_SigenuId(person.id_empleado);

                return
                    evaluations.getStudentEvaluationTotalAwards(new getStudentEvaluationTotalAwards { identification = ci });
            }
            catch
            {
                return null;
            }
        }

        #endregion

        #region Change data queries

        /// <summary>
        /// Cambia la contraseña del usuario
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <param name="password">Contraseña actual del usuario</param>
        /// <param name="newPassword">Contraseña nueva</param>
        /// <returns>Verdadero si se actualizó la contraseña, de otra manera falso</returns>
        public bool ChangePassword(SecurityToken token, string password, string newPassword)
        {
            try
            {
                var person = GetLogin(token);
                if (_SHA256(password) != person.password) return false;
                person.password = _SHA256(newPassword);
                auxiliar_context.SaveChanges();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Guarda al usuario en una tabla temporal hasta la confirmacion
        /// </summary>
        /// <param name="userName">Usuario</param>
        /// <param name="newPassword">Nueva contraseña</param>
        /// <param name="admin_password">Contraseña de administración</param>
        /// <returns>Llave del usuario en la tabla temporal</returns>
        public string ForgottenPassword(string userName, string newPassword, string admin_password)
        {
            if (ConfigurationManager.AppSettings["admin"] != admin_password)
                return Guid.Empty.ToString();

            try
            {
                var person = GetLogin(userName);
                if (person == null)
                    throw new Exception(
                        "El correo no pertenece a ningún usuario registrado. Por favor, verifique su correo, o registrese como nuevo usuario.");
                var key = Guid.NewGuid().ToString();
                var password = _SHA256(newPassword);
                var dirty_user = auxiliar_context.dirtyusers.SingleOrDefault(d => d.idLogin == person.idLogin);
                if (dirty_user != null)
                {
                    dirty_user.dateissue = DateTime.UtcNow;
                    dirty_user.guid = key;
                    dirty_user.password = password;
                }
                else
                {
                    auxiliar_context.dirtyusers.AddObject(new dirtyusers
                                                              {
                                                                  dateissue = DateTime.UtcNow,
                                                                  guid = key,
                                                                  idLogin = person.idLogin,
                                                                  password = password
                                                              });
                }
                auxiliar_context.SaveChanges();
                return key;
            }
            catch (UnauthorizedAccessException)
            {
                return Guid.Empty.ToString();
            }
        }

        /// <summary>
        /// Cambia la contraseña de un usuario cuando se le olvida
        /// </summary>
        /// <param name="key">Llave devuelta en el proceso anterior</param>
        /// <returns>Verdadero si cambio, falso en caso contrario</returns>
        public bool ForgottenPassword(string key)
        {
            var result = false;
            var date = DateTime.UtcNow.Subtract(new TimeSpan(0, 15, 0));
            foreach (var d in auxiliar_context.dirtyusers.Where(u => u.dateissue < date))
                auxiliar_context.dirtyusers.DeleteObject(d);
            var dirtyuser = auxiliar_context.dirtyusers.Single(u => u.guid == key);
            if (dirtyuser != null)
            {
                auxiliar_context.login.Single(l => l.idLogin == dirtyuser.idLogin).password = dirtyuser.password;
                auxiliar_context.dirtyusers.DeleteObject(dirtyuser);
                result = true;
            }
            auxiliar_context.SaveChanges();
            return result;
        }

        /// <summary>
        /// Actualiza los cambios efectuados a los datos extras de la persona en el directorio
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <param name="persona">Datos modificados de la persona</param>
        /// <returns>Verdadero si se actualizó la persona, de otra manera falso</returns>
        public bool Save_Data(SecurityToken token, List<KeyValue> persona)
        {
            try
            {
                var person = GetLogin(token);

                //Datos extras
                if (persona.Count > 0)
                {
                    var jsonData = JsonFx.Json.JsonWriter.Serialize(persona);
                    var extra_data = auxiliar_context.extra_data.Where(e => e.idLogin == person.idLogin);
                    if (extra_data.Count() != 0)
                    {
                        var row = extra_data.First();
                        var dict = JsonFx.Json.JsonReader.Deserialize<KeyValue[]>(row.data);
                        foreach (var data in dict.Where(data => !persona.Exists(e => e.Key == data.Key)))
                            persona.Add(data);
                        jsonData = JsonFx.Json.JsonWriter.Serialize(persona);
                        row.data = jsonData;
                    }
                    else
                        auxiliar_context.AddToextra_data(new extra_data
                                                             {
                                                                 idLogin = person.idLogin,
                                                                 data = jsonData
                                                             });
                }
                auxiliar_context.SaveChanges();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Salva los correos del usuario
        /// </summary>
        /// <param name="token">Token del usuario autentificado</param>
        /// <param name="emails">Correos del usuario</param>
        /// <returns>Verdadero si se salvaron los cambios, falso en caso contrario</returns>
        public bool SaveEmailsList(SecurityToken token, IEnumerable<KeyValue> emails)
        {
            var re = new Regex(".+@(.+\\.)*uh\\.cu$");
            try
            {
                var person = GetLogin(token);
                var alias =
                    auxiliar_context.alias.Where(
                        a => a.login.id_empleado == person.id_empleado && a.login.assets == person.assets);
                var remove = new List<int>();
                foreach (var a in alias)
                {
                    var email = emails.ToList().FirstOrDefault(e => e.Key == a.idAlias.ToString());
                    if (email == null)
                        remove.Add(a.idAlias);
                    else if (email.Value != a.email)
                        if (re.IsMatch(email.Value))
                            a.email = email.Value;
                }
                foreach (var keyValue in emails.Where(e => e.Key == "-1"))
                    auxiliar_context.alias.AddObject(new alias
                                                         {
                                                             email = keyValue.Value,
                                                             idAlias = int.Parse(keyValue.Key),
                                                             idLogin = person.idLogin
                                                         });
                foreach (var alia in remove)
                    auxiliar_context.alias.DeleteObject(auxiliar_context.alias.First(a => a.idAlias == alia));

                auxiliar_context.SaveChanges();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        

        /// <summary>
        /// Almacena a un trabajador en la tabla temporal del sistema en espera de confirmacion.
        /// </summary>
        /// <param name="names">Nombre(s) y/o apellidos</param>
        /// <param name="email">Correo (nombre decimal usuario)</param>
        /// <param name="password">Contrase;a</param>
        /// <param name="ci">Carnet de Identidad</param>
        /// <returns>Llave usada en la confirmacion</returns>
        public string RegisterUser(string names, string email, string password, string ci, string accountType)
        {
            int count;
            if (accountType == "Estudiante")
            {

                #region Registro de estudiantes

                //Ver si hay un estudiante con ese carnet de identidad
                var serv = new SigenuWebServices.Service();
                //var studentssigenu = serv.StudentData(names, null, null, null, null, ci, null);
                var studentssigenu = serv.StudentData(null, null, null, null, null, ci, null);

                if (studentssigenu.Count() == 0)
                    throw new Exception("No Student Found with that data");

                var activeStudents = new List<Student>();
                foreach (var student in studentssigenu)
                {
                    //Si el estudiante es baja, ignorar
                    if (student.status == "Baja")
                    //if (student.docentData.studentStatus == "01")// || student.docentData.academicSituation == )
                        continue;

                    activeStudents.Add(student);
                }

                count = activeStudents.Count;
                if (count == 0)
                    throw new NoUserMatchException(
                        "El nombre o No. de CI que usted envió no se encuentra registrado en el sistema de estudiantes, pase por su secretaría.");
                if (count > 1)
                {
                    //Hay mas de un estudiante con esos datos.
                    throw new DuplicateNameException("El No. de CI que usted ha enviado tiene en recursos humanos a " +
                                                     count +
                                                     " personas con nombre(s) y apellidos como los que nos ha proporcionado");
                }
                //Chequeo de que el correo que entra el estudiante sea el mismo que existe registrado en sigenu
                /*studentssigenu = studentssigenu.Where(e => e.email == email).ToArray();
                 count = studentssigenu.Count();
                 if (count == 0)  //Por si no se encuentra un estudiante con ese correo. 
                     throw new NoEmailMatchException("El correo no se encuentra asociado a ningún estudiante");
                 */

                return CheckNewUser(activeStudents.First().idsigenu, Convert.ToSByte(0), email, password);

                #endregion

            }

            var users = context_uh.Empleados_Gral.Where(w => w.No_CI == ci && w.Baja == false);
            //Buscar un trabajador con esos datos
            count = users.Count();
            if (count == 0)
                throw new NoUserMatchException(
                    "El nombre o No. de CI que usted envió no se encuentra registrado en recursos humanos");

            if (count == 1)
            {
                var person = users.First();
                if (
                    names.Split(new[] { " " }, StringSplitOptions.RemoveEmptyEntries).Count(
                        n =>
                        CompareInfo.GetCompareInfo("es-ES").Compare(n, person.Nombre,
                                                                    CompareOptions.IgnoreNonSpace |
                                                                    CompareOptions.IgnoreCase) == 0 ||
                        CompareInfo.GetCompareInfo("es-ES").Compare(n, person.Apellido_1,
                                                                    CompareOptions.IgnoreNonSpace |
                                                                    CompareOptions.IgnoreCase) == 0 ||
                        CompareInfo.GetCompareInfo("es-ES").Compare(n, person.Apellido_2,
                                                                    CompareOptions.IgnoreNonSpace |
                                                                    CompareOptions.IgnoreCase) == 0) > 0)
                {
                    return CheckNewUser(person.Id_Empleado, Convert.ToSByte(person.Assets), email, password);
                }
                throw new NoUserMatchException(
                    "Su nombre(s) y/o apellidos no coinciden con el nombre(s) y apellidos asociados al No. de CI de recursos humanos");
            }
            var _person =
                users.ToList().Where(
                    t =>
                    names.Split(new[] { " " }, StringSplitOptions.RemoveEmptyEntries).Count(
                        n =>
                        CompareInfo.GetCompareInfo("es-ES").Compare(n, t.Nombre,
                                                                    CompareOptions.IgnoreNonSpace |
                                                                    CompareOptions.IgnoreCase) == 0 ||
                        CompareInfo.GetCompareInfo("es-ES").Compare(n, t.Apellido_1,
                                                                    CompareOptions.IgnoreNonSpace |
                                                                    CompareOptions.IgnoreCase) == 0 ||
                        CompareInfo.GetCompareInfo("es-ES").Compare(n, t.Apellido_2,
                                                                    CompareOptions.IgnoreNonSpace |
                                                                    CompareOptions.IgnoreCase) == 0) > 0);
            count = _person.Count();
            if (count > 1)
            {
                throw new DuplicateNameException(
                    "El No. de CI que ud. ha enviado tiene en recursos humanos a " + count +
                    " personas con nombre(s) y apellidos como los que nos ha proporcionado");
            }
            return CheckNewUser(_person.Single().Id_Empleado, Convert.ToSByte(_person.Single().Assets), email, password);
        }

        /// <summary>
        /// Chequea que el trabajador no este registrado y en caso verdadero, lo inserta en la tabla temporal
        /// </summary>
        /// <param name="id_empleado">Id del trabajador</param>
        /// <param name="assets">Asset del empleado</param>
        /// <param name="email">Correo (nombre de usuario)</param>
        /// <param name="password">Contrase;a</param>
        /// <returns>Llave usada en la confirmacion</returns>
        private string CheckNewUser(string id_empleado, sbyte assets, string email, string password)
        {
            var existing = from l in auxiliar_context.login
                           where l.id_empleado == id_empleado && l.assets == assets
                           select l;
            if (existing.Count() != 0 )
                throw new DuplicateUserException("El usuario ya esta registrado");
    

            //if (auxiliar_context.login.Count(l => (l.id_empleado == id_empleado && l.assets == assets)) > 0)

            var existingMail = from l in auxiliar_context.alias
                               where l.email == email
                               select l;
            if (existingMail.Count() != 0)
                throw new DuplicateEmailException("El correo ya esta registrado");

            //if (auxiliar_context.alias.Count(a => a.email == email) > 0)
                
            var key = Guid.NewGuid().ToString();
            password = _SHA256(password);
            var users = auxiliar_context.dirtyusers.Where(u => u.id_empleado == id_empleado && assets == u.assets);
            if (users.Count() > 0)
            {
                var user = users.First();
                user.dateissue = DateTime.UtcNow;
                user.guid = key;
                user.email = email;
                user.password = password;
            }
            else
            {
                auxiliar_context.dirtyusers.AddObject(new dirtyusers
                                                          {
                                                              dateissue = DateTime.UtcNow,
                                                              guid = key,
                                                              assets = assets,
                                                              id_empleado = id_empleado,
                                                              email = email,
                                                              password = password
                                                          });
            }
            auxiliar_context.SaveChanges();
            return key;
        }

        /// <summary>
        /// Activa a un usuario nuevo
        /// </summary>
        /// <param name="key">Llave devuelta en el proceso anterior</param>
        /// <returns>Verdadero si se activo, falso en caso contrario</returns>
        public SecurityToken RegisterUser(string key)
        {
            //var result = false;
            SecurityToken result = new SecurityToken();
            var date = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0));
            foreach (var d in auxiliar_context.dirtyusers.Where(u => u.dateissue < date))
                auxiliar_context.dirtyusers.DeleteObject(d);
            auxiliar_context.SaveChanges();

            var dirtyuser = auxiliar_context.dirtyusers.Single(u => u.guid == key);
            if (dirtyuser != null)
            {
                auxiliar_context.login.AddObject(new login
                                                     {
                                                         assets = dirtyuser.assets.Value,
                                                         id_empleado = dirtyuser.id_empleado,
                                                         password = dirtyuser.password,
                                                         alias =
                                                             new EntityCollection<alias> { new alias { email = dirtyuser.email } }
                                                     });
                auxiliar_context.dirtyusers.DeleteObject(dirtyuser);
                //result = true;
                auxiliar_context.SaveChanges();
                result = new SecurityToken
                             {
                                 Username = dirtyuser.email,
                                 Token = LogonUser(dirtyuser.email)
                             };
            }

            // return result;
            return result;
        }

        /// <summary>
        /// Elimina un trabajador del sistema
        /// </summary>
        /// <param name="id_empleado"></param>
        /// <param name="assets"></param>
        /// <returns></returns>
        public bool DeleteUser(string id_empleado, sbyte assets)
        {
            try
            {
                var login =
                    auxiliar_context.login.Where(l => l.id_empleado == id_empleado && l.assets == assets).First();
                auxiliar_context.login.DeleteObject(login);
                auxiliar_context.SaveChanges();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #endregion

        #region Search queries

        /// <summary>
        /// Obtiene los datos públicos de una persona a partir de todos o algunos de sus datos
        /// </summary>
        /// <param name="name">Login de la persona buscada</param>
        /// <param name="area">Área de la persona buscada</param>
        /// <param name="centro">Centro o facultad de la universidad</param>
        /// <param name="cat_doc">Categoría docente de la persona buscada</param>
        /// <param name="_cargo">Cargo de la persona buscada</param>
        /// <param name="sub_areas">Si es verdadero, la busqueda por nombre debe verificar que todas las palabras buscadas esten presentes, si falso, basta con que exista una</param>
        /// <param name="pWidth">Ancho, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <param name="pHeight">Alto, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <returns>Datos de la persona buscada</returns>
        public List<Trabajador_Publico> GetPublicTrabajadorData(string name, string area, string centro, string cat_doc,
                                                                string _cargo, string _id_grado_cientifico,
                                                                bool sub_areas, int? pWidth, int? pHeight)
        {
            IQueryable<Empleados_Gral> datos_uh = null;

            if (!string.IsNullOrEmpty(name))
            {
                var names = name.ToUpper().Split(new[] { " " }, StringSplitOptions.RemoveEmptyEntries);

                datos_uh =
                    names.Select(n => context_uh.Empleados_Gral.Where(p => p.Baja == false &&
                                                                           (p.Nombre + " " + p.Apellido_1 + " " +
                                                                            p.Apellido_2).Replace(
                                                                                n, "") !=
                                                                           (p.Nombre + " " + p.Apellido_1 + " " +
                                                                            p.Apellido_2))).
                        Aggregate(datos_uh,
                                  (current, query) =>
                                  current == null
                                      ? query
                                      : current.ToList().Intersect(query, new PersonEqualityComparer()).AsQueryable());
            }
            else
                datos_uh = from p in context_uh.Empleados_Gral where p.Baja == false select p;

            /*return (from p in datos_uh
                    select new Trabajador_Publico
                               { 
                                   Id = "Testing...",
                                   Grado_Cientifico = "Testing...",
                                   Assets = 10,
                                   Nombres = p.Nombre + " " + p.Apellido_1 + " " + p.Apellido_2,
                                   Primer_Apellido = "Testing...",
                                   Segundo_Apellido = "Testing...",
                                   CategoriaDI = "Testing...",
                                   Cargo = "Testing...",
                                   Centro = "Testing...",
                                   Area = "Testing...",
                                   Sexo = "Testing...",
                                   Correos = null,
                                   Foto = null
                               }

                   ).ToList();*/

            var areas = SetHierarchy(area);

            var result = (from p in datos_uh.ToList()
                          join cargo in context_uh.RH_Cargos on new { Key = p.Id_Cargo, Value = p.Assets } equals new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                          join _area in context_uh.RH_Unidades_Organizativas on new { Key = p.Id_Direccion, Value = p.Assets } equals new { Key = _area.Id_Direccion, Value = _area.Assets }
                          join docenteInvest in context_uh.RH_Categorias_Docente_Invest on p.Id_Categoria_DI equals docenteInvest.Id_Categoria_DI into docente
                          from p_d in docente.DefaultIfEmpty()
                          join docenteInvest in context_uh.RH_Categorias_Docente_Invest on p.Id_Categoria_IT equals docenteInvest.Id_Categoria_DI into investigativa
                          //para incluir en los resultados la categoria investigativa
                          from p_i in investigativa.DefaultIfEmpty()
                          join grado in context_uh.RH_Grados_Cientificos on p.Id_Grado_Cientifico equals
                              grado.Id_Grado_Cientifico into grado
                          //left join
                          from p_g in grado.DefaultIfEmpty()
                          //left join
                          where
                              (string.IsNullOrEmpty(area) ||
                               (!sub_areas ? p.Id_Direccion == area : areas.ToList().Contains(p.Id_Direccion))) &&
                              (string.IsNullOrEmpty(_cargo) || p.Id_Cargo == _cargo) &&
                              (string.IsNullOrEmpty(centro) || p.Id_CCosto == centro) &&
                              (string.IsNullOrEmpty(cat_doc) || p.Id_Categoria_DI == cat_doc ||
                               p.Id_Categoria_IT == cat_doc) &&
                              (string.IsNullOrEmpty(_id_grado_cientifico) ||
                               p.Id_Grado_Cientifico == _id_grado_cientifico)
                          select new Trabajador_Publico
                                     {
                                         Id = p.Id_Empleado,
                                         Grado_Cientifico = p_g != null ? p_g.Desc_Grado_Cientifico : null,
                                         Assets = p.Assets,
                                         Nombres = p.Nombre,
                                         Primer_Apellido = p.Apellido_1,
                                         Segundo_Apellido = p.Apellido_2,
                                         CategoriaDI =
                                             p_d != null
                                                 ? p_d.Desc_Categoria_DI
                                                 : (p_i != null ? p_i.Desc_Categoria_DI : null),
                                         Cargo = cargo.Desc_Cargo,
                                         Centro = p.Id_CCosto,
                                         Area = _area.Desc_Direccion,
                                         Sexo = p.Sexo,
                                         Foto = p.Foto
                                     }).ToList();



            var correos = auxiliar_context.login.ToList();

            return (from dato in result
                    join correo in correos on new { Key = dato.Id, Value = dato.Assets.ToString() } equals new { Key = correo.id_empleado, Value = correo.assets.ToString() } into gj
                    from e in gj.DefaultIfEmpty()
                    select new Trabajador_Publico
                               {
                                   Id = dato.Id,
                                   Grado_Cientifico = dato.Grado_Cientifico,
                                   Assets = dato.Assets,
                                   Nombres = dato.Nombres,
                                   Primer_Apellido = dato.Primer_Apellido,
                                   Segundo_Apellido = dato.Segundo_Apellido,
                                   CategoriaDI = dato.CategoriaDI,
                                   Cargo = dato.Cargo,
                                   Centro = dato.Centro,
                                   Area = dato.Area,
                                   Sexo = dato.Sexo,
                                   Correos = e != null
                                                 ? e.alias.ToList().Select(a => a.email).
                                                       ToList()
                                                 : null,
                                   Foto =
                                       dato.Foto != null && dato.Foto.Length > 0 && pWidth.HasValue &&
                                       pHeight.HasValue
                                           ? ResizeFromStream(pWidth.Value, pHeight.Value,
                                                              new MemoryStream(dato.Foto.ToArray()))
                                                 .GetBuffer()
                                           : null
                               }).ToList();
        }

        /// <summary>
        /// Obtiene los datos públicos de una persona a partir de su identificador en Assets
        /// </summary>
        /// <param name="id">Identificador de la persona buscada</param>
        /// <param name="assets">Assets al que pertenece</param>
        /// <param name="pWidth">Ancho, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <param name="pHeight">Alto, en pixeles, de la foto de la persona. Si el valor es nulo, se toma el ancho por defecto</param>
        /// <returns>Datos de la persona buscada</returns>
        public Trabajador_Publico GetPublicTrabajadorData(string id, byte assets, int? pWidth, int? pHeight)
        {
            var datos = (from p in context_uh.Empleados_Gral
                         join cargo in context_uh.RH_Cargos on new { Key = p.Id_Cargo, Value = p.Assets } equals
                             new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                         join area in context_uh.RH_Unidades_Organizativas on
                             new { Key = p.Id_Direccion, Value = p.Assets } equals
                             new { Key = area.Id_Direccion, Value = area.Assets }
                         join docenteInvest in context_uh.RH_Categorias_Docente_Invest on p.Id_Categoria_DI equals
                             docenteInvest.Id_Categoria_DI into docente
                         from p_d in docente.DefaultIfEmpty()
                         join docenteInvest in context_uh.RH_Categorias_Docente_Invest on p.Id_Categoria_IT equals
                             docenteInvest.Id_Categoria_DI into investigativa
                         //para incluir en los resultados la categoria investigativa
                         from p_i in investigativa.DefaultIfEmpty()
                         join grado in context_uh.RH_Grados_Cientificos on p.Id_Grado_Cientifico equals
                             grado.Id_Grado_Cientifico into grado
                         //left join
                         from p_g in grado.DefaultIfEmpty()
                         //left join
                         where p.Id_Empleado == id && p.Assets == assets && p.Baja == false
                         select new Trabajador_Publico
                                    {
                                        Id = p.Id_Empleado.Trim(),
                                        Grado_Cientifico = p_g != null ? p_g.Desc_Grado_Cientifico : null,
                                        Assets = assets,
                                        Nombres = p.Nombre,
                                        Primer_Apellido = p.Apellido_1,
                                        Segundo_Apellido = p.Apellido_2,
                                        CategoriaDI =
                                            p_d != null
                                                ? p_d.Desc_Categoria_DI
                                                : (p_i != null ? p_i.Desc_Categoria_DI : null),
                                        Cargo = cargo.Desc_Cargo,
                                        Centro = p.Id_CCosto.Trim(),
                                        Area = area.Desc_Direccion,
                                        Sexo = p.Sexo,
                                        Foto = p.Foto
                                    }).FirstOrDefault();
            if (datos == null)
                return null;
            datos.Correos =
                auxiliar_context.alias.Where(a => a.login.id_empleado == datos.Id && a.login.assets == datos.Assets).
                    Select(a => a.email).ToList();
            datos.Foto = datos.Foto != null && datos.Foto.Length > 0 && pWidth.HasValue && pHeight.HasValue
                             ? ResizeFromStream(pWidth.Value, pHeight.Value, new MemoryStream(datos.Foto.ToArray())).
                                   GetBuffer()
                             : null;
            return datos;
        }

        public List<Trabajador_Publico> GetPublicTrabajadorData(byte assets, int? pWidth, int? pHeight)
        {
            var catsDI = (from categoria in context_uh.RH_Categorias_Docente_Invest
                          select new { Cat_DI = categoria.Id_Categoria_DI , Cat_Desc = categoria.Desc_Categoria_DI}
                          ).ToList();

            var cats = catsDI.ToDictionary(p => p.Cat_DI, p => p.Cat_Desc);


            var datos = (from p in context_uh.Empleados_Gral
                         join grado in context_uh.RH_Grados_Cientificos
                             on p.Id_Grado_Cientifico equals grado.Id_Grado_Cientifico
                             into _grado  //left join
                         from g in _grado.DefaultIfEmpty()
                         join cargo in context_uh.RH_Cargos
                             on new { Key = p.Id_Cargo, Value = p.Assets } equals
                             new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                             into _cargo  //left join
                         from c in _cargo.DefaultIfEmpty()

                         /*join categoria in context_uh.RH_Categorias_Docente_Invest
                              on p.Id_Categoria_DI equals categoria.Id_Categoria_DI
                              into _categoria
                         from d in _categoria.DefaultIfEmpty()*/

                         where p.Assets == assets && p.Baja == false
                         select
                             new Trabajador_Publico
                                 {
                                     Id = p.Id_Empleado.Trim(),
                                     Grado_Cientifico = g != null ? g.Desc_Grado_Cientifico : null,
                                     Assets = assets,
                                     Nombres = p.Nombre,
                                     Primer_Apellido = p.Apellido_1,
                                     Segundo_Apellido = p.Apellido_2,
                                     CategoriaDI =
                                         (p.Id_Categoria_DI == null || p.Id_Categoria_DI == "" ||
                                          p.Id_Categoria_DI == "0")
                                             ? p.Id_Categoria_IT
                                             : /*d.Desc_Categoria_DI,//*/p.Id_Categoria_DI,
                                     //para incluir en los resultados la categoria investigativa
                                     Cargo = c.Desc_Cargo,
                                     Centro = p.Id_CCosto.Trim(),
                                     Area = p.Id_Direccion.Trim(),
                                     Sexo = p.Sexo,
                                     Foto = p.Foto,
                                     No_CI = p.No_CI,
                                     Cuadro = 
                                              p.Id_Categoria == "5"
                                              ? true
                                              : false,
                                     Color_Piel =
                                         p.Color_Piel == 1
                                             ? "B"
                                             : (p.Color_Piel == 2
                                                    ? "N"
                                                    : (p.Color_Piel == 3 ? "M" : (p.Color_Piel == 4 ? "A" : ""))),
                                     Militancia =
                                         p.Militancia == 1
                                             ? "UJC"
                                             : (p.Militancia == 2 ? "PCC" : (p.Militancia == 3 ? "UJC,PCC" : ""))
                                 }).ToList();

            var correos = auxiliar_context.login.Where(l => l.assets == assets).ToList();

            return (from dato in datos
                    join correo in correos on new { Key = dato.Id, Value = dato.Assets.ToString() } equals
                        new { Key = correo.id_empleado, Value = correo.assets.ToString() } into gj
                    from e in gj.DefaultIfEmpty()
                    select new Trabajador_Publico
                               {
                                   Id = dato.Id,
                                   Grado_Cientifico = dato.Grado_Cientifico,
                                   Assets = assets,
                                   Nombres = dato.Nombres,
                                   Primer_Apellido = dato.Primer_Apellido,
                                   Segundo_Apellido = dato.Segundo_Apellido,
                                   CategoriaDI = dato.CategoriaDI,
                                   Cargo = dato.Cargo,
                                   Centro = dato.Centro,
                                   Area = dato.Area,
                                   Sexo = dato.Sexo,
                                   No_CI = dato.No_CI,
                                   Color_Piel = dato.Color_Piel,
                                   Cuadro = dato.Cuadro,
                                   Militancia = dato.Militancia,
                                   Correos = e != null
                                                 ? e.alias.ToList().Select(a => a.email).
                                                       ToList()
                                                 : null,
                                   Foto =
                                       dato.Foto != null && dato.Foto.Length > 0 && pWidth.HasValue &&
                                       pHeight.HasValue
                                           ? ResizeFromStream(pWidth.Value, pHeight.Value,
                                                              new MemoryStream(dato.Foto.ToArray())).
                                                 GetBuffer()
                                           : null

                               }).ToList();
        }

        public List<Trabajador> SearchWorkers(SecurityToken token, Dictionary<string, string> fields)
        {
            if (HMACSHA256(ConfigurationManager.AppSettings["admin"], token.Token).ToLower() != token.Username.ToLower())
                return null;
            var response = new List<Trabajador>();
            foreach (var keyValue in fields)
            {
                if (typeof(Empleados_Gral).GetProperty(keyValue.Key) != null)
                {
                    response.AddRange(
                        context_uh.Empleados_Gral.ToList().Where(
                            p =>
                            p.GetType().GetProperty(keyValue.Key).GetValue(p, null).ToString() ==
                            keyValue.Value).Select(
                                p =>
                                new Trabajador
                                    {
                                        DatosAssets = p
                                    }));
                }
                else
                {
                    response.AddRange(
                        auxiliar_context.extra_data.Where(
                            e =>
                            GetExtraData(e.idLogin, token).Count(
                                i => i.Llave == keyValue.Key && i.Valor == keyValue.Value.ToString()) > 0).Select(
                                    e =>
                                    new Trabajador
                                        {
                                            DatosAssets =
                                                context_uh.Empleados_Gral.First(
                                                    d => d.Id_Empleado == e.login.id_empleado),
                                            DatosExtras = GetExtraData(e.idLogin, token),
                                            Correos =
                                                auxiliar_context.alias.Where(
                                                    a =>
                                                    a.login.id_empleado == e.login.id_empleado &&
                                                    a.login.assets == e.login.assets).
                                                ToList().
                                                Select(
                                                    a =>
                                                    new KeyValue { Key = a.idAlias.ToString(), Value = a.email })
                                                .ToList()
                                        }));
                }
            }
            return response;
        }

        public string[] GetPublicEstudianteData(string idFaculty, string idCareer, string year, string idGroup)
        {

            if (!string.IsNullOrWhiteSpace(idFaculty) && string.IsNullOrWhiteSpace(idCareer) &&
                string.IsNullOrWhiteSpace(year) && string.IsNullOrWhiteSpace(idGroup))
            {
                var serv = new SigenuWebServices.Service();
                var studentsCI = serv.StudentsByFaculty(idFaculty).Select(e => e.ci).ToArray();
                return studentsCI;
            }
            else
            {
                listCIs = new ListStudentIdentificationByFilterService.ListStudentIdentificationByFilterService
                              {
                                  Credentials
                                      =
                                      new NetworkCredential
                                      (ConfigurationManager
                                           .
                                           AppSettings
                                           [
                                               "sigenu_user"
                                           ],
                                       ConfigurationManager
                                           .
                                           AppSettings
                                           [
                                               "sigenu_pwd"
                                           ])
                              };
                var cis =
                    listCIs.getListStudentIdentificationByLoadFilter(new getListStudentIdentificationByLoadFilter
                                                                         {
                                                                             studentPageFilterVO =
                                                                                 new studentPageFilterVO
                                                                                     {
                                                                                         idFaculty = idFaculty,
                                                                                         idCareer = idCareer,
                                                                                         idYear = year,
                                                                                         idGroup = idGroup,
                                                                                         idStudentStatus = "02"
                                                                                     }
                                                                         });
                return cis;
            }
        }

        public Estudiante_Publico GetPublicEstudianteData(string ci)
        {   
            InitializeStudentsWS();
            var studentsCollection = students.getStudentFileAllData(new getStudentFileAllData { identification = ci });
            
            foreach (var student in studentsCollection)
            {
                if (student.docentData.studentStatus == "01")
                    continue;

                return new Estudiante_Publico
                {
                    CI = ci,
                    Año = student.docentData.year,
                    Carrera = student.docentData.career,
                    Correo = null,
                    Facultad = student.docentData.faculty,
                    Grupo = student.docentData.group,
                    Nombres = student.personalData.name,
                    Pais = student.personalData.country,
                    Primer_Apellido = student.personalData.middleName,
                    Segundo_Apellido = student.personalData.lastName,
                    Sexo = student.personalData.sex
                };

            }

            return new Estudiante_Publico();

            //student.docentData.studentStatus
            
             
        }

        public List<Estudiante_Publico> GetPublicEstudianteData(string names, string idFaculty, string idCareer,
                                                                string year, string idGroup)
        {
            var serv = new SigenuWebServices.Service();
            var students = serv.StudentData(names, idFaculty, idCareer, year, idGroup, null, null);
            return students.Select(e => new Estudiante_Publico
                                            {
                                                Nombres = e.name,
                                                Primer_Apellido = e.middle_name,
                                                Segundo_Apellido = e.last_name,
                                                Facultad = e.faculty,
                                                Carrera = e.career,
                                                Año = e.grade,
                                                Grupo = e.group,
                                                Correo = e.email,
                                                Pais = e.country
                                            }).ToList();
        }

        public List<studentDTO> SearchStudents(SecurityToken token, string ci)
        {
            if (HMACSHA256(ConfigurationManager.AppSettings["admin"], token.Token).ToLower() != token.Username.ToLower())
                return null;
            InitializeStudentsWS();
            var response = students.getStudentFileAllData(new getStudentFileAllData { identification = ci }).ToList();
            return response;
        }

        #endregion

        #region Simple queries

        /// <summary>
        /// Municipios
        /// </summary>
        /// <param name="municipio">Municipio</param>
        /// <param name="provincia">Provincia</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> Municipios(string municipio, string provincia)
        {
            var mun = context_uh.RH_Municipios;
            return from c in mun
                   where
                       (string.IsNullOrEmpty(provincia) || c.Id_Provincia == provincia) &&
                       (string.IsNullOrEmpty(municipio) || c.Id_Municipio == municipio)
                   orderby c.Desc_Municipio
                   select new KeyValue { Key = c.Id_Municipio, Value = c.Desc_Municipio };
        }

        /// <summary>
        /// Profesiones
        /// </summary>
        /// <param name="idProfesion">Profesion</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> Profesiones(string idProfesion)
        {
            var profesiones = context_uh.RH_Profesiones;
            return from c in profesiones
                   where string.IsNullOrEmpty(idProfesion) || c.Id_Profesion == idProfesion
                   orderby c.Desc_Profesion
                   select new KeyValue { Key = c.Id_Profesion, Value = c.Desc_Profesion };
        }

        /// <summary>
        /// Nivel_Escolaridad
        /// </summary>
        /// <param name="idNivelEscolar">Nivel Escolar</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> Nivel_Escolaridad(string idNivelEscolar)
        {
            var nivel_escolar = context_uh.RH_Niveles_Escolaridad;
            return from c in nivel_escolar
                   where string.IsNullOrEmpty(idNivelEscolar) || c.Id_Nivel_Escolaridad == idNivelEscolar
                   orderby c.Desc_Nivel_Escolaridad
                   select new KeyValue { Key = c.Id_Nivel_Escolaridad, Value = c.Desc_Nivel_Escolaridad };
        }

        /// <summary>
        /// Area_Universitaria
        /// </summary>
        /// <param name="idArea">Área Universitaria</param>
        /// <param name="assets">Assets donde buscar</param>
        /// <param name="categoria">Categoria: 1-Rectorado, 2-Vicerrectorias, 3-Facultades, 4-Direcciones, 5-Centros, 6-Departamentos, 7-Filiales</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> Area_Universitaria(string idArea, byte assets, int[] categoria)
        {
            var category = categoria.Select(c => c.ToString()).ToList();
            var areas = context_uh.RH_Unidades_Organizativas;
            return from c in areas
                   where (string.IsNullOrEmpty(idArea) || c.Id_Direccion == idArea)
                         && (assets == 0 || assets == c.Assets) &&
                         (category.Count() == 0 || category.Any(e => e == c.Nota))
                   orderby c.Desc_Direccion
                   select
                       new KeyValue
                           {
                               Key = c.Id_Direccion,
                               Value =
                                   (c.Assets == 1
                                        ? "UH: "
                                        : (c.Assets == 2 ? "IFAL: " : (c.Assets == 3 ? "UPA: " : "JBN: "))) +
                                   c.Desc_Direccion
                           };
        }

        /// <summary>
        /// Cargos
        /// </summary>
        /// <param name="idCargo">Cargo</param>
        /// <param name="assets">Assets donde buscar</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> Cargo(string idCargo, byte assets)
        {
            var cargos = context_uh.RH_Cargos;
            return from c in cargos
                   where (string.IsNullOrEmpty(idCargo) || c.Id_Cargo == idCargo)
                         && (assets == 0 || assets == c.Assets)
                   orderby c.Desc_Cargo
                   select
                       new KeyValue
                           {
                               Key = c.Id_Cargo,
                               Value =
                                   (c.Assets == 1
                                        ? "UH: "
                                        : (c.Assets == 2 ? "IFAL: " : (c.Assets == 3 ? "UPA: " : "JBN: "))) +
                                   c.Desc_Cargo
                           };
        }

        /// <summary>
        /// Cargos con Descripcion y Categoria
        /// </summary>
        /// <param name="idCargo">Cargo</param>
        /// <param name="assets">Assets donde buscar</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<CargoDetalles> CargosDetalles(string idCargo, byte assets)
        {
            var cargos = context_uh.RH_Cargos;
            return from c in cargos
                   where (string.IsNullOrEmpty(idCargo) || c.Id_Cargo == idCargo)
                         && (assets == 0 || assets == c.Assets)
                   orderby c.Desc_Cargo
                   select
                       new CargoDetalles
                           {
                               Id_Cargo = c.Id_Cargo,
                               Desc_Cargo =
                                   (c.Assets == 1
                                        ? "UH: "
                                        : (c.Assets == 2 ? "IFAL: " : (c.Assets == 3 ? "UPA: " : "JBN: "))) +
                                   c.Desc_Cargo,
                               Desc_Categoria = c.Desc_Categoria
                           };
        }

        /// <summary>
        /// Categorias Docentes e Investigativas
        /// </summary>
        /// <param name="idCategoria">Categoria Docente Investigativa</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> Categoria_DI(string idCategoria)
        {
            var cat_di = context_uh.RH_Categorias_Docente_Invest;
            return from c in cat_di
                   where string.IsNullOrEmpty(idCategoria) || c.Id_Categoria_DI == idCategoria
                   orderby c.Desc_Categoria_DI
                   select new KeyValue { Key = c.Id_Categoria_DI, Value = c.Desc_Categoria_DI };
        }

        /// <summary>
        /// Provincias
        /// </summary>
        /// <param name="provincia">Provincia</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> Provincias(string provincia)
        {
            var provincias = context_uh.RH_Provincias;
            return from c in provincias
                   where string.IsNullOrEmpty(provincia) || c.Id_Provincia == provincia
                   orderby c.Desc_Provincia
                   select new KeyValue { Key = c.Id_Provincia, Value = c.Desc_Provincia };
        }

        /// <summary>
        /// Grado cientifico
        /// </summary>
        /// <param name="provincia">grado cientifico</param>
        /// <returns>Listado con {id,valor}</returns>
        public IEnumerable<KeyValue> GradosCientificos(string id_grado)
        {
            var provincias = context_uh.RH_Grados_Cientificos;
            return from c in provincias
                   where string.IsNullOrEmpty(id_grado) || c.Id_Grado_Cientifico == id_grado
                   orderby c.Desc_Grado_Cientifico
                   select new KeyValue { Key = c.Id_Grado_Cientifico, Value = c.Desc_Grado_Cientifico };
        }

        /// <summary>
        /// Obtiene la provincia a la que pertenece el municipio
        /// </summary>
        /// <param name="municipio">Municipio</param>
        /// <returns></returns>
        public string GetProvincia(string municipio)
        {
            return (from p in context_uh.RH_Provincias
                    join m in context_uh.RH_Municipios on p.Id_Provincia equals m.Id_Provincia
                    where m.Id_Municipio == municipio
                    select p.Id_Provincia).FirstOrDefault();
        }

        public List<Calendario> Calendarios()
        {
            return context_uh.RH_Calendarios.AsEnumerable().Select(
                e =>
                new Calendario
                    {
                        Month = e.Mes,
                        Year = e.Ano,
                        Dias =
                            new List<bool>
                                {
                                    e.D1,
                                    e.D2,
                                    e.D3,
                                    e.D4,
                                    e.D5,
                                    e.D6,
                                    e.D7,
                                    e.D8,
                                    e.D9,
                                    e.D10,
                                    e.D11,
                                    e.D12,
                                    e.D13,
                                    e.D14,
                                    e.D15,
                                    e.D16,
                                    e.D17,
                                    e.D18,
                                    e.D19,
                                    e.D20,
                                    e.D21,
                                    e.D22,
                                    e.D23,
                                    e.D24,
                                    e.D25,
                                    e.D26,
                                    e.D27,
                                    e.D28,
                                    e.D29,
                                    e.D30,
                                    e.D31
                                }
                    }).ToList();
        }

        public Calendario Calendar(int month, int year)
        {
            var calendar = context_uh.RH_Calendarios.FirstOrDefault(e => e.Mes == month && e.Ano == year);
            return new Calendario
                       {
                           Month = calendar.Mes,
                           Year = calendar.Ano,
                           Dias =
                               new List<bool>
                                   {
                                       calendar.D1,
                                       calendar.D2,
                                       calendar.D3,
                                       calendar.D4,
                                       calendar.D5,
                                       calendar.D6,
                                       calendar.D7,
                                       calendar.D8,
                                       calendar.D9,
                                       calendar.D10,
                                       calendar.D11,
                                       calendar.D12,
                                       calendar.D13,
                                       calendar.D14,
                                       calendar.D15,
                                       calendar.D16,
                                       calendar.D17,
                                       calendar.D18,
                                       calendar.D19,
                                       calendar.D20,
                                       calendar.D21,
                                       calendar.D22,
                                       calendar.D23,
                                       calendar.D24,
                                       calendar.D25,
                                       calendar.D26,
                                       calendar.D27,
                                       calendar.D28,
                                       calendar.D29,
                                       calendar.D30,
                                       calendar.D31
                                   }
                       };
        }

        public List<ClaveAusencia> Claves_Ausencias()
        {
            return context_uh.RH_Claves_Ausencias.Select(
                e => new ClaveAusencia { Desc_Clave = e.Desc_Clave, Id_Clave = e.Id_Clave }).ToList();
        }

        #endregion

        public IEnumerable<Trabajador_Baja> BajasPorArea(SecurityToken _token, byte assets, string id_area,
                                                         bool subAreas)
        {
            var areas = subAreas ? SetHierarchy(id_area).ToList() : new[] { id_area };
            List<Trabajador_Baja> result = new List<Trabajador_Baja>();

            foreach (var area in areas)
            {

                var temp = from p in context_uh.Empleados_Gral
                           join grado in context_uh.RH_Grados_Cientificos on p.Id_Grado_Cientifico equals
                               grado.Id_Grado_Cientifico
                               //left join
                               into _grado
                           from g in _grado.DefaultIfEmpty()

                           join cargo in context_uh.RH_Cargos on
                               new { Key = p.Id_Cargo, Value = p.Assets } equals
                               new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                               //left join
                               into pgc
                           from p_g in pgc.DefaultIfEmpty()

                           join baja in context_uh.RH_Causas_Bajas on
                               new { Key = p.Assets, Value = p.Id_CausaBaja }
                               equals new { Key = baja.Assets, Value = baja.Id_CausaBaja }
                               //left join
                               into _baja
                           from b in _baja.DefaultIfEmpty()

                           where p.Assets == assets && p.Id_Direccion == id_area && p.Baja == true
                           select new Trabajador_Baja
                                      {
                                          DatosAsset = new Trabajador_Publico
                                                           {
                                                               Id = p.Id_Empleado.Trim(),
                                                               Grado_Cientifico =
                                                                   p_g != null ? g.Desc_Grado_Cientifico : null,
                                                               Assets = p.Assets,
                                                               Nombres = p.Nombre,
                                                               Primer_Apellido = p.Apellido_1,
                                                               Segundo_Apellido = p.Apellido_2,
                                                               CategoriaDI =
                                                                   (p.Id_Categoria_DI == null || p.Id_Categoria_DI == "" ||
                                                                    p.Id_Categoria_DI == "0")
                                                                       ? p.Id_Categoria_IT
                                                                       : p.Id_Categoria_DI,
                                                               //para incluir en los resultados la categoria investigativa
                                                               Cargo = p_g.Desc_Cargo,
                                                               Centro = p.Id_CCosto.Trim(),
                                                               Area = p.Id_Direccion.Trim(),
                                                               Sexo = p.Sexo,
                                                               Foto = p.Foto,
                                                               No_CI = p.No_CI,
                                                               Color_Piel =
                                                                   p.Color_Piel == 1
                                                                       ? "B"
                                                                       : (p.Color_Piel == 2
                                                                              ? "N"
                                                                              : (p.Color_Piel == 3
                                                                                     ? "M"
                                                                                     : (p.Color_Piel == 4 ? "A" : ""))),
                                                               Militancia =
                                                                   p.Militancia == 1
                                                                       ? "UJC"
                                                                       : (p.Militancia == 2
                                                                              ? "PCC"
                                                                              : (p.Militancia == 3 ? "UJC,PCC" : ""))
                                                           },
                                          InfoBaja = new Baja
                                                         {
                                                             Desc_CausaBaja = b.Desc_CausaBaja,
                                                             Fecha_Baja = p.Fecha_Baja
                                                         }

                                      };
                result.AddRange(temp);
            }
            return result;
        }

        public IEnumerable<Trabajador_Baja> BajasPorFecha(SecurityToken _token, byte assets, DateTime inicio,
                                                          DateTime fin)
        {
            return from p in context_uh.Empleados_Gral
                   join grado in context_uh.RH_Grados_Cientificos on p.Id_Grado_Cientifico equals
                       grado.Id_Grado_Cientifico
                       //left join
                       into _grado
                   from g in _grado.DefaultIfEmpty()

                   join cargo in context_uh.RH_Cargos on
                       new { Key = p.Id_Cargo, Value = p.Assets } equals
                       new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                       //left join
                       into pgc
                   from p_g in pgc.DefaultIfEmpty()

                   join baja in context_uh.RH_Causas_Bajas on
                       new { Key = p.Assets, Value = p.Id_CausaBaja }
                       equals new { Key = baja.Assets, Value = baja.Id_CausaBaja }
                       //left join
                       into _baja
                   from b in _baja.DefaultIfEmpty()

                   where p.Assets == assets && p.Baja == true && inicio <= p.Fecha_Baja && p.Fecha_Baja <= fin
                   select new Trabajador_Baja
                              {
                                  DatosAsset = new Trabajador_Publico
                                                   {
                                                       Id = p.Id_Empleado.Trim(),
                                                       Grado_Cientifico = p_g != null ? g.Desc_Grado_Cientifico : null,
                                                       Assets = p.Assets,
                                                       Nombres = p.Nombre,
                                                       Primer_Apellido = p.Apellido_1,
                                                       Segundo_Apellido = p.Apellido_2,
                                                       CategoriaDI =
                                                           (p.Id_Categoria_DI == null || p.Id_Categoria_DI == "" ||
                                                            p.Id_Categoria_DI == "0")
                                                               ? p.Id_Categoria_IT
                                                               : p.Id_Categoria_DI,
                                                       //para incluir en los resultados la categoria investigativa
                                                       Cargo = p_g.Desc_Cargo,
                                                       Centro = p.Id_CCosto.Trim(),
                                                       Area = p.Id_Direccion.Trim(),
                                                       Sexo = p.Sexo,
                                                       Foto = p.Foto,
                                                       No_CI = p.No_CI,
                                                       Color_Piel =
                                                           p.Color_Piel == 1
                                                               ? "B"
                                                               : (p.Color_Piel == 2
                                                                      ? "N"
                                                                      : (p.Color_Piel == 3
                                                                             ? "M"
                                                                             : (p.Color_Piel == 4 ? "A" : ""))),
                                                       Militancia =
                                                           p.Militancia == 1
                                                               ? "UJC"
                                                               : (p.Militancia == 2
                                                                      ? "PCC"
                                                                      : (p.Militancia == 3 ? "UJC,PCC" : ""))
                                                   },
                                  InfoBaja = new Baja
                                                 {
                                                     Desc_CausaBaja = b.Desc_CausaBaja,
                                                     Fecha_Baja = p.Fecha_Baja
                                                 }
                              };
        }


        public List<Trabajador_Publico_Ext> GetPublicTrabajadorExtData(string name, string area, string centro,
                                                                       string cat_doc, string _cargo,
                                                                       string _id_grado_cientifico, bool sub_areas,
                                                                       int? pWidth, int? pHeight)
        {
            IQueryable<Empleados_Gral> datos_uh = null;

            if (!string.IsNullOrEmpty(name))
            {
                var names = name.ToUpper().Split(new[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                datos_uh =
                    names.Select(n => context_uh.Empleados_Gral.Where(p => p.Baja == false &&
                                                                           (p.Nombre + " " + p.Apellido_1 + " " +
                                                                            p.Apellido_2).Replace(
                                                                                n, "") !=
                                                                           (p.Nombre + " " + p.Apellido_1 + " " +
                                                                            p.Apellido_2))).
                        Aggregate(datos_uh,
                                  (current, query) =>
                                  current == null
                                      ? query
                                      : current.ToList().Intersect(query, new PersonEqualityComparer()).AsQueryable());
            }
            else
                datos_uh = from p in context_uh.Empleados_Gral where p.Baja == false select p;

            var areas = SetHierarchy(area);

            var result = (from p in datos_uh.ToList()
                          join cargo in context_uh.RH_Cargos on new { Key = p.Id_Cargo, Value = p.Assets } equals
                              new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                          join _area in context_uh.RH_Unidades_Organizativas on
                              new { Key = p.Id_Direccion, Value = p.Assets } equals
                              new { Key = _area.Id_Direccion, Value = _area.Assets }
                          join docenteInvest in context_uh.RH_Categorias_Docente_Invest on p.Id_Categoria_DI equals
                              docenteInvest.Id_Categoria_DI into docente
                          from p_d in docente.DefaultIfEmpty()
                          join docenteInvest in context_uh.RH_Categorias_Docente_Invest on p.Id_Categoria_IT equals
                              docenteInvest.Id_Categoria_DI into investigativa
                          //para incluir en los resultados la categoria investigativa
                          from p_i in investigativa.DefaultIfEmpty()
                          join grado in context_uh.RH_Grados_Cientificos on p.Id_Grado_Cientifico equals
                              grado.Id_Grado_Cientifico into grado
                          //left join
                          from p_g in grado.DefaultIfEmpty()
                          //left join
                          where
                              (string.IsNullOrEmpty(area) ||
                               (!sub_areas ? p.Id_Direccion == area : areas.ToList().Contains(p.Id_Direccion))) &&
                              (string.IsNullOrEmpty(_cargo) || p.Id_Cargo == _cargo) &&
                              (string.IsNullOrEmpty(centro) || p.Id_CCosto == centro) &&
                              (string.IsNullOrEmpty(cat_doc) || p.Id_Categoria_DI == cat_doc ||
                               p.Id_Categoria_IT == cat_doc) &&
                              (string.IsNullOrEmpty(_id_grado_cientifico) ||
                               p.Id_Grado_Cientifico == _id_grado_cientifico)
                          select new Trabajador_Publico_Ext
                                     {
                                         Id = p.Id_Empleado,
                                         Grado_Cientifico = p_g != null ? p_g.Desc_Grado_Cientifico : null,
                                         Assets = p.Assets,
                                         Nombres = p.Nombre,
                                         Primer_Apellido = p.Apellido_1,
                                         Segundo_Apellido = p.Apellido_2,
                                         CategoriaDI =
                                             p_d != null
                                                 ? p_d.Desc_Categoria_DI
                                                 : (p_i != null ? p_i.Desc_Categoria_DI : null),
                                         Cargo = cargo.Desc_Cargo,
                                         Centro = p.Id_CCosto,
                                         Area = _area.Desc_Direccion,
                                         Sexo = p.Sexo,
                                         Foto = p.Foto,
                                         Color_Piel = p.Color_Piel == 1
                                                          ? "B"
                                                          : (p.Color_Piel == 2
                                                                 ? "N"
                                                                 : (p.Color_Piel == 3
                                                                        ? "M"
                                                                        : (p.Color_Piel == 4 ? "A" : ""))),
                                         ColorPelo =
                                             p.Color_Pelo == 1
                                                 ? "Negro"
                                                 : (p.Color_Pelo == 2
                                                        ? "Rubio"
                                                        : (p.Color_Pelo == 3
                                                               ? "Castaño"
                                                               : (p.Color_Pelo == 4
                                                                      ? "Rojiso"
                                                                      : (p.Color_Pelo == 5 ? "Canoso" : "")))),
                                         DireccionParticular = p.Direccion,
                                         Estatura = (float)p.Estatura,
                                         FechaNacimiento = p.Fecha_Nacimiento,
                                         Militancia = p.Militancia == 1
                                                          ? "UJC"
                                                          : (p.Militancia == 2
                                                                 ? "PCC"
                                                                 : (p.Militancia == 3 ? "UJC,PCC" : "")),
                                         IdCargo = p.Id_Cargo,
                                         No_CI = p.No_CI,
                                         NombreMadre = p.Nombre_Madre,
                                         NombrePadre = p.Nombre_Padre,
                                         TelefonoParticular = p.Telefono_Particular
                                     }).ToList();

            var correos = auxiliar_context.login.ToList();

            return (from dato in result
                    join correo in correos on new { Key = dato.Id, Value = dato.Assets.ToString() } equals
                        new { Key = correo.id_empleado, Value = correo.assets.ToString() } into gj
                    from e in gj.DefaultIfEmpty()
                    select new Trabajador_Publico_Ext
                               {
                                   Id = dato.Id,
                                   Grado_Cientifico = dato.Grado_Cientifico,
                                   Assets = dato.Assets,
                                   Nombres = dato.Nombres,
                                   Primer_Apellido = dato.Primer_Apellido,
                                   Segundo_Apellido = dato.Segundo_Apellido,
                                   CategoriaDI = dato.CategoriaDI,
                                   Cargo = dato.Cargo,
                                   Centro = dato.Centro,
                                   Area = dato.Area,
                                   Sexo = dato.Sexo,
                                   Correos = e != null
                                                 ? e.alias.ToList().Select(a => a.email).
                                                       ToList()
                                                 : null,
                                   Foto =
                                       dato.Foto != null && dato.Foto.Length > 0 && pWidth.HasValue &&
                                       pHeight.HasValue
                                           ? ResizeFromStream(pWidth.Value, pHeight.Value,
                                                              new MemoryStream(dato.Foto.ToArray()))
                                                 .GetBuffer()
                                           : null,
                                   Color_Piel = dato.Color_Piel,
                                   ColorPelo = dato.ColorPelo,
                                   DireccionParticular = dato.DireccionParticular,
                                   Estatura = dato.Estatura,
                                   FechaNacimiento = dato.FechaNacimiento,
                                   IdCargo = dato.IdCargo,
                                   Militancia = dato.Militancia,
                                   No_CI = dato.No_CI,
                                   NombreMadre = dato.NombreMadre,
                                   NombrePadre = dato.NombrePadre,
                                   TelefonoParticular = dato.TelefonoParticular,
                               }).ToList();

        }

        public List<UsuarioExterno> GetUsuariosExternos(string names)
        {
            List<personaexterna> externos;
            if (!string.IsNullOrWhiteSpace(names))
            {
                var namesSplited = names.ToUpperInvariant().Split(new[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                externos =
                    namesSplited.AsQueryable().SelectMany(
                        n =>
                        externUsersContext.personaexternas.Where(
                            pe =>
                            pe.Apellido_1.ToUpper().Contains(n) || pe.Apellido_2.ToUpper().Contains(n) ||
                            pe.Nombre.ToUpper().Contains(n))).ToList();
            }
            else
                externos = externUsersContext.personaexternas.ToList();
            var correos = auxiliar_context.login;
            return (from dato in externos
                    join correo in correos on new { Key = dato.id, Value = "5" } equals
                        new { Key = correo.id_empleado, Value = correo.assets.ToString(CultureInfo.InvariantCulture) }
                        into gj
                    from e in gj.DefaultIfEmpty()
                    select new UsuarioExterno
                               {
                                   Emails = e != null
                                                ? e.alias.ToList().Select(a => a.email).
                                                      ToList()
                                                : null,
                                   Id = dato.id,
                                   NoCI = dato.No_CI,
                                   Nombre = dato.Nombre,
                                   PrimerApellido = dato.Apellido_1,
                                   SegundoApellido = dato.Apellido_2,
                               }).ToList();

        }

        public ExternUserWrapper GetUsuarioExterno(SecurityToken token)
        {
            login person;
            try
            {
                person = GetLogin(token);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            var personas =
                externUsersContext.personaexternas.Where(x => x.id == person.id_empleado && person.assets == 5);
            if (personas.Count() != 1)
                return null;
            var p = personas.First();
            var correos =
                auxiliar_context.alias.Where(a => a.idLogin == person.idLogin).ToList().Select(
                    a => new KeyValue
                    {
                        Key = a.idAlias.ToString(),
                        Value = a.email
                    });

            var extraData = GetExtraData(person.idLogin, token);

            return new ExternUserWrapper { Correos = correos.ToList(), DatosPersonales = p, DatosExtras = extraData };
        }



        public List<User> BuscarUsuariosPorLogin(string login, string idArea)
        {
            var logins = auxiliar_context.login.Where(l => l.alias.Any(a => a.email.StartsWith(login))).ToList();
            var workerLogins = logins.Where(l => l.assets != 0);
            var toReturn = new List<User>();

            var aux =
                workerLogins.SelectMany(
                    l =>
                    context_uh.Empleados_Gral.Where(e => e.Id_Empleado == l.id_empleado && e.Id_Direccion == idArea)).
                    ToList().
                    Select(w => new User { Id = w.Id_Empleado, Asset = w.Assets });
            toReturn.AddRange(aux);

            var studentLogins = logins.Where(l => l.assets == 0);
            var serv = new SigenuWebServices.Service();
            var area = serv.MapeoAreas("idasset", idArea).FirstOrDefault();
            if (area != null)
            {
                var sigenuStudents = serv.StudentsByFaculty(area.idsigenu);
                toReturn.AddRange(
                    sigenuStudents.Where(s => studentLogins.Any(e => e.id_empleado == s.idsigenu)).
                        Select(s => new User
                                        {
                                            Id = s.idsigenu,
                                            Asset = 0
                                        }));
            }
            return toReturn;
        }

        public bool AddUser(string ci, string email, string password)
        {
            var filter = (from item in context_uh.Empleados_Gral
                         where (item.No_CI == ci && item.Baja == false)
                         select item).ToList();

            if (filter.Count > 0)
                throw new Exception("Ya existe un usuario en la BD con esos datos, y que no es baja.");

            var user = (from item in context_uh.Empleados_Gral
                        where (item.No_CI == ci && item.Baja)
                        select new
                                   {
                                       ID = item.Id_Empleado,
                                       Assets = item.Assets
                                   })
                .ToList().Last();

            var key = CheckNewUser(user.ID, (sbyte)user.Assets, email, password);
            RegisterUser(key);
            return true;
        }

        public List<Trabajador_Publico> GetPublicTrabajadorData_v2(byte assets, int? pWidth, int? pHeight)
        {
            var catsDI = (from categoria in context_uh.RH_Categorias_Docente_Invest
                          select new { Cat_DI = categoria.Id_Categoria_DI, Cat_Desc = categoria.Desc_Categoria_DI }
                          ).ToList();

            var cats = catsDI.ToDictionary(p => p.Cat_DI, p => p.Cat_Desc);


            var datos = (from p in context_uh.Empleados_Gral
                         join grado in context_uh.RH_Grados_Cientificos
                             on p.Id_Grado_Cientifico equals grado.Id_Grado_Cientifico
                             into _grado  //left join
                         from g in _grado.DefaultIfEmpty()
                         join cargo in context_uh.RH_Cargos
                             on new { Key = p.Id_Cargo, Value = p.Assets } equals
                             new { Key = cargo.Id_Cargo, Value = cargo.Assets }
                             into _cargo  //left join
                         from c in _cargo.DefaultIfEmpty()

                         join categoria in context_uh.RH_Categorias_Docente_Invest
                              on p.Id_Categoria_DI equals categoria.Id_Categoria_DI
                              into _categoria
                         from d in _categoria.DefaultIfEmpty()

                         where p.Assets == assets && p.Baja == false
                         select
                             new Trabajador_Publico
                             {
                                 Id = p.Id_Empleado.Trim(),
                                 Grado_Cientifico = g != null ? g.Desc_Grado_Cientifico : null,
                                 Assets = assets,
                                 Nombres = p.Nombre,
                                 Primer_Apellido = p.Apellido_1,
                                 Segundo_Apellido = p.Apellido_2,
                                 CategoriaDI =
                                     (p.Id_Categoria_DI == null || p.Id_Categoria_DI == "" ||
                                      p.Id_Categoria_DI == "0")
                                         ? p.Id_Categoria_IT
                                         : d.Desc_Categoria_DI,//p.Id_Categoria_DI,
                                 //para incluir en los resultados la categoria investigativa
                                 Cargo = c.Desc_Cargo,
                                 Centro = p.Id_CCosto.Trim(),
                                 Area = p.Id_Direccion.Trim(),
                                 Sexo = p.Sexo,
                                 Foto = p.Foto,
                                 No_CI = p.No_CI,
                                 Cuadro =
                                          p.Id_Categoria == "5"
                                          ? true
                                          : false,
                                 Color_Piel =
                                     p.Color_Piel == 1
                                         ? "B"
                                         : (p.Color_Piel == 2
                                                ? "N"
                                                : (p.Color_Piel == 3 ? "M" : (p.Color_Piel == 4 ? "A" : ""))),
                                 Militancia =
                                     p.Militancia == 1
                                         ? "UJC"
                                         : (p.Militancia == 2 ? "PCC" : (p.Militancia == 3 ? "UJC,PCC" : ""))
                             }).ToList();

            var correos = auxiliar_context.login.Where(l => l.assets == assets).ToList();

            return (from dato in datos
                    join correo in correos on new { Key = dato.Id, Value = dato.Assets.ToString() } equals
                        new { Key = correo.id_empleado, Value = correo.assets.ToString() } into gj
                    from e in gj.DefaultIfEmpty()
                    select new Trabajador_Publico
                    {
                        Id = dato.Id,
                        Grado_Cientifico = dato.Grado_Cientifico,
                        Assets = assets,
                        Nombres = dato.Nombres,
                        Primer_Apellido = dato.Primer_Apellido,
                        Segundo_Apellido = dato.Segundo_Apellido,
                        CategoriaDI = dato.CategoriaDI,
                        Cargo = dato.Cargo,
                        Centro = dato.Centro,
                        Area = dato.Area,
                        Sexo = dato.Sexo,
                        No_CI = dato.No_CI,
                        Color_Piel = dato.Color_Piel,
                        Cuadro = dato.Cuadro,
                        Militancia = dato.Militancia,
                        Correos = e != null
                                      ? e.alias.ToList().Select(a => a.email).
                                            ToList()
                                      : null,
                        Foto =
                            dato.Foto != null && dato.Foto.Length > 0 && pWidth.HasValue &&
                            pHeight.HasValue
                                ? ResizeFromStream(pWidth.Value, pHeight.Value,
                                                   new MemoryStream(dato.Foto.ToArray())).
                                      GetBuffer()
                                : null

                    }).ToList();
        }
        
    }




    public class KeyValue
    {
        public string Key { get; set; }
        public string Value { get; set; }
    }

    public struct WorkerStruct
    {
        public string Id { get; set; }
        public sbyte Assets { get; set; }
        public string Username { get; set; }
        public string Token { get; set; }
    }

    public class DatosExtra
    {
        public string Dominio { get; set; }
        public string Llave { get; set; }
        public string Valor { get; set; }
    }

    public class SecurityToken : SoapHeader
    {
        public string Username { get; set; }
        public string Token { get; set; }
    }

    public class TrabajadorInfoCuote
    {
        public string Id { get; set; }
        public string CatOcupacional { get; set; }
        public string Docente { get; set; }
        public string CatDocenteInvestigativa { get; set; }
        public string Contrato { get; set; }
        public string Cargo { get; set; }
        public string Adiestrado { get; set; }
        public string AdministradorArea { get; set; }
        public string AdministradorRed { get; set; }
        public string Tecnico { get; set; }
        public string TecnicoInformatico { get; set; }
        public string EspecialistaPrincipal { get; set; }
        public string Cuadro { get; set; }
        public string Asset { get; set; }
    }
    public class EstudianteInfoCuote
    {
        public string Anno { get; set; }
        public string AccesoInternet { get; set; }
    }
    public class SecurityInfoToken : SoapHeader
    {
        public string Username { get; set; }
        public string Token { get; set; }
        public string LoginId { get; set; }
    }

    public struct Areas
    {
        public string Id { get; set; }
        public string Nombre { get; set; }
        public List<Areas> Childs { get; set; }


        public IEnumerable<string> ToList()
        {
            var list = new List<string> { Id };
            foreach (var child in Childs)
                list.AddRange(child.ToList());
            return list;
        }




    }

    public class PersonEqualityComparer : IEqualityComparer<Empleados_Gral>
    {
        public bool Equals(Empleados_Gral x, Empleados_Gral y)
        {
            return x.Id_Empleado == y.Id_Empleado;
        }

        public int GetHashCode(Empleados_Gral obj)
        {
            return base.GetHashCode();
        }
    }

    public class DuplicateUserException : Exception
    {
        public DuplicateUserException(string message)
            : base(message)
        {
        }
    }

    public class DuplicateEmailException : Exception
    {
        public DuplicateEmailException(string message)
            : base(message)
        {
        }
    }

    public class NoUserMatchException : Exception
    {
        public NoUserMatchException(string message)
            : base(message)
        {
        }
    }

    public class NoEmailMatchException : Exception
    {
        public NoEmailMatchException(string message)
            : base(message)
        {
        }
    }
}

