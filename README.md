# dse_certificados v1.1.0
## Programa para la gestión de certificados digitales

### Desarrollado por Carlos Clemente (09-2024)

### Control de versiones
- Version 1.0.0 - Primera version funcional
<br>

### Descripcion:
- Permite la gestion de los certificados digitales instalados en el almacen del usuario
- Funciones disponibles:
	- Lectura y almacenamiento de los certificados digitales del equipo junto con sus propiedades para su utilizacion posterior.
	- Busqueda de un certificado por el numero de serie, NIF o nombre del titular del certificado.
	- Obtener una lista con los certificados leidos.
	- Obtener una lista ordenada de los certificados leidos, segun el campo pasado por parametro.
	- Obtener una lista filtrada por nombre de los certificados leidos
	- Obtener una lista filtrada por nif del titular del certificado de los certificados leidos
	- Lectura y almacenamiento de un certificado digital en fichero pasado por parametro.
	- Exportar en formato Json las propiedades de los certificados procesados.
	- Exportar un certificado digital en formato 'base64' pasado desde un fichero como parametro
	- Exportar un certificado digital en formato .pfx segun el numero de serie pasado por parametro.	

