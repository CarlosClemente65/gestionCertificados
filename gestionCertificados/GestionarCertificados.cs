using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Windows;
using Newtonsoft.Json;


namespace GestionCertificadosDigitales
{
    public class CertificadosSalida
    {
        //Clase que engloba las propiedades de los certificados
        public List<PropiedadesCertificadosSalida> propiedadesCertificadoSalida { get; set; }

        public CertificadosSalida()
        {
            propiedadesCertificadoSalida = new List<PropiedadesCertificadosSalida>();
        }
    }
    public class PropiedadesCertificadosSalida
    {
        //Clase que representa las propiedades de los certificados que necesitamos
        //Se ponen como propiedades del Json con una letra para facilitar la lectura en la salida

        [JsonProperty("A")]
        public string nifCertificado { get; set; }

        [JsonProperty("B")]
        public string titularCertificado { get; set; }

        [JsonProperty("C")]
        public string serieCertificado { get; set; }

        private DateTime _fechaEmision;

        [JsonProperty("D")]
        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTime fechaEmision
        {
            get => _fechaEmision.Date;
            set => _fechaEmision = value.Date;
        }

        private DateTime _fechaValidez;

        [JsonProperty("E")]
        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTime fechaValidez
        {
            get => _fechaValidez.Date;
            set => _fechaValidez = value.Date;
        }

        [JsonProperty("F")]
        public string nifRepresentante { get; set; }

        [JsonProperty("G")]
        public string nombreRepresentante { get; set; }

        [JsonProperty("H")]
        public string nombreCertificado { get; set; }

        [JsonProperty("I")]
        public string huellaCertificado { get; set; }

        [JsonProperty("J")]
        public string passwordCertificado { get; set; }

        public PropiedadesCertificadosSalida()
        {
            nifCertificado = string.Empty;
            titularCertificado = string.Empty;
            serieCertificado = string.Empty;
            fechaEmision = DateTime.MinValue;
            fechaValidez = DateTime.MinValue;
            nifRepresentante = string.Empty;
            nombreRepresentante = string.Empty;
            nombreCertificado = string.Empty;
            passwordCertificado = string.Empty;
            huellaCertificado = string.Empty;
        }
    }

    public class Certificados
    {
        //Clase que engloba las propiedades de los certificados
        public List<PropiedadesCertificados> propiedadesCertificado { get; set; }

        public Certificados()
        {
            propiedadesCertificado = new List<PropiedadesCertificados>();
        }
    }
    public class PropiedadesCertificados
    {
        //Clase que representa las propiedades de los certificados que se reciben de la libreria dse_utilescert

        public string nifCertificado { get; set; }

        public string titularCertificado { get; set; }

        public string serieCertificado { get; set; }

        private DateTime _fechaEmision;

        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTime fechaEmision
        {
            get => _fechaEmision.Date;
            set => _fechaEmision = value.Date;
        }

        private DateTime _fechaValidez;

        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTime fechaValidez
        {
            get => _fechaValidez.Date;
            set => _fechaValidez = value.Date;
        }

        public string nifRepresentante { get; set; }

        public string nombreRepresentante { get; set; }

        public string nombreCertificado { get; set; }

        public string huellaCertificado { get; set; }

        public string passwordCertificado { get; set; }

        public PropiedadesCertificados()
        {
            nifCertificado = string.Empty;
            titularCertificado = string.Empty;
            serieCertificado = string.Empty;
            fechaEmision = DateTime.MinValue;
            fechaValidez = DateTime.MinValue;
            nifRepresentante = string.Empty;
            nombreRepresentante = string.Empty;
            nombreCertificado = string.Empty;
            passwordCertificado = string.Empty;
            huellaCertificado = string.Empty;
        }
    }

    public class CustomDateTimeConverter : JsonConverter
    {
        // Define que este convertidor se aplicará a propiedades de tipo DateTime (necesario para tratar bien las fechas del json que se recibe)
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(DateTime);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            //Modifica la escritura del Json para formatear las fechas como 'dd/mm/yyyy'
            if (value is DateTime dateTime)
            {
                writer.WriteValue(dateTime.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture));
            }
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            //Modifica la lectura del Json para formatear las fechas como 'dd/mm/yyyy'
            string dateString = (string)reader.Value;

            // Verificamos si el valor es nulo o vacío
            if (string.IsNullOrWhiteSpace(dateString))
                return DateTime.MinValue;

            // Convertir la cadena de fecha a DateTime
            return DateTime.ParseExact(dateString, "dd/MM/yyyy", CultureInfo.InvariantCulture);
        }
    }


    public class GestionarCertificados
    {
        //Clase que engloba la gestion de certificados

        private List<X509Certificate2> certificadosDigitales = new List<X509Certificate2>(); //Lista que contiene los certificados digitales
        private Certificados datosCertificados = new Certificados(); //Lista que contiene las propiedades de los certificados


        /// <summary>
        /// Proceso de lectura de los certificados instalados en el almacen del usuario, para poder usarlos en otros metodos
        /// </summary>
        public void cargarCertificadosAlmacen()
        {
            //Se chequea si ya se ha cargado la lista de certificados para no hacerlo de nuevo
            if (certificadosDigitales.Count == 0)
            {
                //Metodo para cargar los certificados del almacen de windows
                X509Store almacen = new X509Store(StoreLocation.CurrentUser);
                almacen.Open(OpenFlags.ReadOnly);
                foreach (X509Certificate2 certificado in almacen.Certificates)
                {
                    //Solo se cargan los certificados no caducados
                    if (certificado.NotAfter >= DateTime.Now)
                    {
                        certificadosDigitales.Add(certificado);
                    }
                }
                almacen.Close();

                // Graba las propiedades de los certificados en la clase ListaCertificados
                foreach (X509Certificate2 certificado in certificadosDigitales)
                {
                    if (certificado.Subject.Contains("SERIALNUMBER")) //Deben tener esto para que sean de persona fisica o juridica
                    {
                        //En el Subject estan todos los datos del certificado
                        string datosSubject = certificado.Subject;
                        PropiedadesCertificados propiedadesCertificado = new PropiedadesCertificados
                        {
                            serieCertificado = certificado.SerialNumber,
                            fechaValidez = certificado.NotAfter,
                            fechaEmision = certificado.NotBefore,
                            huellaCertificado = certificado.Thumbprint.ToString()
                        };
                        obtenerDatosSubject(datosSubject, propiedadesCertificado);
                        datosCertificados.propiedadesCertificado.Add(propiedadesCertificado);
                    }
                }
            }
        }

        /// <summary>
        /// Permite obtener las propiedades de los certificados que estan almacenadas en el campo 'Subject'
        /// </summary>
        /// <param name="subject">Contenido del subject del certificado digital</param>
        /// <param name="propiedadesCertificado">Propiedades del certificado que ya se han procesado en la carga de certificados</param>
        public void obtenerDatosSubject(string subject, PropiedadesCertificados propiedadesCertificado)
        {
            //Carga los datos del certificado en las propiedades de la clase
            bool juridica = false;
            if (subject.Contains("2.5.4.97")) juridica = true;
            string nombrePF = string.Empty; ;
            string apellidoPF = string.Empty;
            string nombrePJ = string.Empty;
            string nombreRepresentante = string.Empty;
            string apellidoRepresentante = string.Empty;
            string nifCertificado = string.Empty;
            string patronNif = @"\b(?=(?:\w*[A-Z]){1,2})(?=(?:\w*\d){2,})\w{9}\b"; //Patron de NIF

            string[] partes = subject.Split(',');
            foreach (string parte in partes)
            {
                string[] elementos = parte.Trim().Split('=');
                string elemento = string.Empty;
                string valor = string.Empty;
                if (elementos.Length == 2)
                {
                    elemento = elementos[0];
                    valor = elementos[1];
                }

                switch (elemento)
                {
                    case "G": //Nombre del titular del certificado o del representante si es juridica
                        if (juridica)
                        {
                            nombreRepresentante = valor;
                        }
                        else
                        {
                            nombrePF = valor;
                        }
                        break;

                    case "SN": //Apellido del titular del certificado o del representante si es juridica
                        if (juridica)
                        {
                            apellidoRepresentante = valor;
                        }
                        else
                        {
                            apellidoPF = valor;
                        }
                        break;

                    case "SERIALNUMBER": //NIF del titular del certificado o del representante si es juridica
                        Match buscaNif = Regex.Match(valor, patronNif);
                        if (buscaNif.Success)
                        {
                            if (juridica)
                            {
                                propiedadesCertificado.nifRepresentante = buscaNif.Value;
                            }
                            else
                            {
                                nifCertificado = buscaNif.Value;
                            }
                        }
                        break;

                    case "O": //Nombre de la sociedad
                        nombrePJ = valor;
                        break;

                    case "OID.2.5.4.97": //NIF de la sociedad
                        Match buscaCIF = Regex.Match(valor, patronNif);
                        if (buscaCIF.Success)
                        {
                            nifCertificado = buscaCIF.Value;
                        }
                        break;

                    case "CN": //Nombre certificado
                        propiedadesCertificado.nombreCertificado = valor;
                        break;
                }

                if (string.IsNullOrEmpty(propiedadesCertificado.nifCertificado)) propiedadesCertificado.nifCertificado = nifCertificado;
                if (string.IsNullOrEmpty(propiedadesCertificado.titularCertificado) || string.IsNullOrEmpty(propiedadesCertificado.nombreRepresentante))
                {
                    if (juridica)
                    {
                        propiedadesCertificado.titularCertificado = nombrePJ;
                        if (!string.IsNullOrEmpty(nombreRepresentante))
                        {
                            propiedadesCertificado.nombreRepresentante = apellidoRepresentante + " " + nombreRepresentante;
                        }
                    }
                    else
                    {
                        propiedadesCertificado.titularCertificado = apellidoPF + " " + nombrePF;
                    }
                }
            }
        }

        /// <summary>
        /// Obtiene el numero de serie de un certificado buscando en el numero de serie, NIF o nombre del titular
        /// </summary>
        /// <param name="textoBusqueda">Texto a buscar</param>
        /// <returns>Numero de serie del certificado encontrado o un texto vacio en caso contrario</returns>
        public string buscarCertificado(string textoBusqueda)
        {
            //Nota: aunque se devuelve el nº de serie, se puede hacer la busqueda por ese campo para controlar si existe el certificado)

            string resultadoBusqueda = string.Empty;
            var buscaCertificado = datosCertificados.propiedadesCertificado.Find(cert =>
                cert.nifCertificado.Contains(textoBusqueda) ||
                cert.titularCertificado.Contains(textoBusqueda) ||
                cert.serieCertificado.Contains(textoBusqueda)
                );
            if (buscaCertificado != null)
            {
                resultadoBusqueda = buscaCertificado.serieCertificado;
            }

            return resultadoBusqueda;
        }

        /// <summary>
        /// Obtiene una relacion de los certificados con sus propiedades 
        /// </summary>
        /// <returns>Lista de certificados y sus propiedades</returns>
        public List<PropiedadesCertificados> relacionCertificados()
        {
            //Devuelve la lista con los datos de los certificados
            return datosCertificados.propiedadesCertificado;
        }


        /// <summary>
        /// Obtiene una relacion de los certificados ordenados por el campo y orden especificado
        /// </summary>
        /// <param name="campoOrdenacion">Campo por el que se va a ordenar la lista (utiliza el enum 'CampoOrdenacion')</param>
        /// <param name="ascendente">'True' para ascendente, 'False' para descendente</param>
        /// <returns>Lista de certificados ordenada</returns>
        public List<PropiedadesCertificados> ordenarCertificados(nombresPropiedades campoOrdenacion, bool ascendente)
        {
            List<PropiedadesCertificados> certificados = datosCertificados.propiedadesCertificado;
            if (certificados == null || certificados.Count == 0)
            {
                //Evita que se produzca una excepcion si no hay certificados cargados en la lista
                return datosCertificados.propiedadesCertificado;
            }

            switch (campoOrdenacion)
            {
                case nombresPropiedades.nifCertificado:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.nifCertificado).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.nifCertificado).ToList());
                    }
                    break;

                case nombresPropiedades.titularCertificado:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.titularCertificado).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.titularCertificado).ToList());
                    }
                    break;

                case nombresPropiedades.fechaValidez:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.fechaValidez).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.fechaValidez).ToList());
                    }
                    break;

                case nombresPropiedades.fechaEmision:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.fechaEmision).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.fechaEmision).ToList());
                    }
                    break;

                case nombresPropiedades.nifRepresentante:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.nifRepresentante).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.nifRepresentante).ToList());
                    }
                    break;

                case nombresPropiedades.nombreRepresentante:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.nombreRepresentante).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.nombreRepresentante).ToList());
                    }
                    break;

                case nombresPropiedades.nombreCertificado:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.nombreCertificado).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.nombreCertificado).ToList());
                    }
                    break;

                case nombresPropiedades.serieCertificado:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.serieCertificado).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.serieCertificado).ToList());
                    }
                    break;

                case nombresPropiedades.huellaCertificado:
                    if (ascendente)
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderBy(certificado => certificado.huellaCertificado).ToList());
                    }
                    else
                    {
                        certificados = new List<PropiedadesCertificados>(certificados.OrderByDescending(certificado => certificado.huellaCertificado).ToList());
                    }
                    break;

            }
            return certificados;

        }

        /// <summary>
        /// Obtiene una relacion de certificados filtrada por el campo 'titularCertificado' segun el texto pasado
        /// </summary>
        /// <param name="filtro">Texto a buscar</param>
        /// <returns>Lista de certificados filtrada</returns>
        public List<PropiedadesCertificados> filtrarCertificadosNombre(string filtro)
        {
            List<PropiedadesCertificados> certificados = datosCertificados.propiedadesCertificado;
            if (!string.IsNullOrEmpty(filtro))
            {
                filtro = filtro.ToUpper();
                certificados = new List<PropiedadesCertificados>(certificados.FindAll(certificado => certificado.titularCertificado.ToUpper().Contains(filtro)));
            }
            return certificados;
        }


        /// <summary>
        /// Obtiene una relacion de certificados filtrada por el campo 'nifCertificado' segun el texto pasado
        /// </summary>
        /// <param name="filtro">Texto a buscar</param>
        /// <returns>Lista de certificados filtrada</returns>
        public List<PropiedadesCertificados> filtrarCertificadosNif(string filtro)
        {
            List<PropiedadesCertificados> certificados = datosCertificados.propiedadesCertificado;
            if (!string.IsNullOrEmpty(filtro))
            {
                filtro = filtro.ToUpper();
                certificados = new List<PropiedadesCertificados>(certificados.FindAll(certificado => certificado.nifCertificado.ToUpper().Contains(filtro)));
            }
            return certificados;
        }


        /// <summary>
        /// Permite leer las propiedades de un certificado pasado como fichero
        /// </summary>
        /// <param name="fichero">Ruta del fichero a leer</param>
        /// <param name="password">Contraseña del certificado (necesaria para acceder a los datos)</param>
        /// <returns>Serie del certificado, OK si la lectura es correcta o errores que se han producido, ademas de un true o false con el resultado de la lectura</returns>
        public (string, bool) leerCertificado(string fichero, string password)
        {
            //Se devuelve un mensaje con un OK o el error al leer el fichero, y un true o false.
            string mensaje = string.Empty;
            bool respuesta = false;

            //Como se pasa el certificado como fichero, se borran los certificados que hay en la lista para que solo aparezca el que se ha pasado
            if (certificadosDigitales.Count > 0)
            {
                certificadosDigitales.Clear();
                datosCertificados.propiedadesCertificado.Clear();
            }

            try
            {
                X509Certificate2 certificado = new X509Certificate2(fichero, password, X509KeyStorageFlags.Exportable);
                certificadosDigitales.Add(certificado);
                // Graba las propiedades del certificado en la clase certificadosInfo
                foreach (X509Certificate2 cert in certificadosDigitales)
                {
                    if (cert.Subject.Contains("SERIALNUMBER")) //Deben tener esto para que sean de persona fisica o juridica
                    {
                        //En el Subject estan todos los datos del certificado
                        string datosSubject = cert.Subject;
                        PropiedadesCertificados propiedadesCertificado = new PropiedadesCertificados
                        {
                            fechaValidez = cert.NotAfter,
                            fechaEmision = certificado.NotBefore,
                            serieCertificado = cert.SerialNumber,
                            huellaCertificado = cert.Thumbprint.ToString(),
                            passwordCertificado = password
                        };
                        obtenerDatosSubject(datosSubject, propiedadesCertificado);
                        datosCertificados.propiedadesCertificado.Add(propiedadesCertificado);
                    }
                }
                mensaje = "OK";
                respuesta = true;
                return (mensaje, respuesta);
            }

            catch (Exception ex)
            {
                mensaje = $"No se ha podido leer el certificado. {ex.Message}";
                respuesta = false;
                return (mensaje, respuesta);
            }
        }


        /// <summary>
        ///Permite obtener las propiedades de los certificados para poder exportarlos a un fichero 
        /// </summary>
        /// <param name="exportaDiagram">True para que el formato lleve letras en vez de nombres de propiedades, false para no modificarlo</param>
        /// <returns>Texto con formato Json con las propiedades de los certificados, 'true' si se han podido obtener los datos o 'false' en caso contrario</returns>
        public (string, bool) exportarPropiedadesCertificados(bool exportaDiagram)
        {
            try
            {
                // Serializar la lista de ficheros a JSON
                JsonSerializerSettings opciones = new JsonSerializerSettings
                {
                    Formatting = Formatting.Indented, // Aplica indentación
                    StringEscapeHandling = StringEscapeHandling.EscapeHtml, // Evita caracteres especiales
                    DateFormatString = "dd/MM/yyyy" //Formato de fecha
                };

                string jsonSalida = JsonConvert.SerializeObject(datosCertificados, opciones);

                if (exportaDiagram)
                {
                    jsonSalida = ajusteDiagram(jsonSalida);
                }

                return (jsonSalida, true);
            }

            catch (Exception ex)
            {
                string mensaje = $"No se ha podido grabar los datos de los certificados. {ex.Message}";
                return (mensaje, false);
            }
        }


        /// <summary>
        /// Permite exportar un certificado digital en base64
        /// </summary>
        /// <param name="ruta">Ruta del fichero que se quiere pasar a base64</param>
        /// <param name="password">Contraseña del certificado digital</param>
        /// <returns>Cadena de caracteres en base64 que representa el certificado digital, o mensaje de error si no se ha podido convertir, asi como un true o false con el resultado de la conversion</returns>
        public (string, bool) exportaCertificadoB64(string ruta, string password)
        {
            //Permite exportar un certificado pasado desde un fichero a base64. Se pasa la ruta de ubicacion del fichero con el certificado y el password (necesario para acceder a los datos)
            try
            {
                X509Certificate2 certificado = new X509Certificate2(ruta, password, X509KeyStorageFlags.Exportable);

                // Obtener los datos en formato binario (byte array) del certificado
                byte[] datosCertificado = certificado.Export(X509ContentType.Pfx, password);

                // Convertir los datos a Base64
                string certificadoBase64 = Convert.ToBase64String(datosCertificado);

                return (certificadoBase64, true);
            }
            catch (Exception ex)
            {
                string mensaje = $"No se ha podido leer el certificado. {ex.Message}";
                return (mensaje, false);
            }

        }


        /// <summary>
        /// Obtiene un certificado digital segun el numero de serie pasado
        /// </summary>
        /// <param name="serieCertificado">Numero de serie del certificado a obtener</param>
        /// <returns>Certificado digital</returns>
        public (X509Certificate2, bool) exportaCertificadoDigital(string serieCertificado)
        {
            //Devuelve el certificado digital que tenga el numero de serie se haya pasado por parametro; si no lo encuentra devuelve null
            bool respuesta = false;

            X509Certificate2 certificado = certificadosDigitales.Find(cert => cert.SerialNumber.Equals(serieCertificado, StringComparison.OrdinalIgnoreCase));
            if (certificado != null)
            {
                respuesta = true;
            }
            return (certificado, respuesta);

        }

        /// <summary>
        /// Obtiene el valor de una propiedad del certificado. Solo devuelve el valor si hay un unico certificado leido
        /// </summary>
        /// <param name="nombrePropiedad">Nombre de la propiedad a consultar (utiliza el enum 'CampoOrdenacion')</param>
        /// <returns>Valor almacenado en la propiedad</returns>
        public string consultaPropiedades(nombresPropiedades nombrePropiedad)
        {
            string valorPropiedad = string.Empty;

            //Solo se devuelve el valor de la propiedad si hay un solo certificado
            if (datosCertificados.propiedadesCertificado.Count == 1)
            {
                foreach (var certificado in datosCertificados.propiedadesCertificado)
                {
                    PropertyInfo propiedad = certificado.GetType().GetProperty(nombrePropiedad.ToString());
                    if (propiedad != null)
                    {
                        valorPropiedad = propiedad.GetValue(certificado).ToString();
                    }
                }
            }

            return valorPropiedad;
        }

        /// <summary>
        /// Lista de nombres de propiedades de certificados
        /// </summary>
        public enum nombresPropiedades
        {
            nifCertificado,
            titularCertificado,
            serieCertificado,
            fechaEmision,
            fechaValidez,
            nifRepresentante,
            nombreRepresentante,
            nombreCertificado,
            huellaCertificado
        }

        /// <summary>
        /// Ajusta el json recibido a la salida que esperamos con letras en vez de nombres de propiedades
        /// </summary>
        /// <param name="json"></param>
        /// <returns>El json recibido formateando la propiedades con letras de la A a la J</returns>
        public string ajusteDiagram(string json)
        {
            //Ajusta el json recibido a la salida que esperamos con letras en vez de nombres de propiedades
            // Deserializar el JSON en la clase original
            var certificadosEntrada = JsonConvert.DeserializeObject<Certificados>(json);

            var certificadosSalida = new CertificadosSalida();

            // Mapear las propiedades
            foreach (var propiedad in certificadosEntrada.propiedadesCertificado)
            {
                var propiedadSalida = new PropiedadesCertificadosSalida
                {
                    nifCertificado = propiedad.nifCertificado,
                    titularCertificado = propiedad.titularCertificado,
                    serieCertificado = propiedad.serieCertificado,
                    fechaEmision = propiedad.fechaEmision,
                    fechaValidez = propiedad.fechaValidez,
                    nifRepresentante = propiedad.nifRepresentante,
                    nombreRepresentante = propiedad.nombreRepresentante,
                    nombreCertificado = propiedad.nombreCertificado,
                    huellaCertificado = propiedad.huellaCertificado,
                    passwordCertificado = propiedad.passwordCertificado
                };

                certificadosSalida.propiedadesCertificadoSalida.Add(propiedadSalida);
            }

            JsonSerializerSettings opciones = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented, // Aplica indentación
                StringEscapeHandling = StringEscapeHandling.EscapeHtml, // Evita caracteres especiales
                //DateFormatString = "dd/MM/yyyy" //Formato de fecha
            };
            string jsonSalida = JsonConvert.SerializeObject(certificadosSalida, opciones);

            //Elimina los espacios antes de cada linea
            jsonSalida = string.Join(Environment.NewLine, jsonSalida.Split(new[] { Environment.NewLine }, StringSplitOptions.None).Select(linea => linea.TrimStart()));

            return jsonSalida;

        }
    }

}