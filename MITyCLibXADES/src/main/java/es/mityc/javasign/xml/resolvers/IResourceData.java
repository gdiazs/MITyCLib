/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES".
 *
 * Licencia con arreglo a la EUPL, Versión 1.1 o –en cuanto sean aprobadas por la Comisión Europea– versiones posteriores de la EUPL (la Licencia);
 * Solo podrá usarse esta obra si se respeta la Licencia.
 *
 * Puede obtenerse una copia de la Licencia en:
 *
 * http://joinup.ec.europa.eu/software/page/eupl/licence-eupl
 *
 * Salvo cuando lo exija la legislación aplicable o se acuerde por escrito, el programa distribuido con arreglo a la Licencia se distribuye «TAL CUAL»,
 * SIN GARANTÍAS NI CONDICIONES DE NINGÚN TIPO, ni expresas ni implícitas.
 * Véase la Licencia en el idioma concreto que rige los permisos y limitaciones que establece la Licencia.
 */
package es.mityc.javasign.xml.resolvers;

/**
 * Este interfaz permite la obtención de información referente a recursos de la firma (disponible en nodos Reference).
 * 
 */
public interface IResourceData {

	/**
	 * Obtiene acceso a la información del elemento indicado.
	 *  
	 * @param name Nombre del elemento del que se quiere obtener acceso
	 * @param baseURI Ruta base del elemento
	 * @return Objeto del tipo InputStream o byte[] que da acceso a los datos del elemento
	 * @throws ResourceDataException lanzada cuando no se puede acceder a la información por alguna razón
	 */
	public Object getAccess(String name, String baseURI) throws ResourceDataException;
	
	/**
	 * Indica si esta implementación puede acceder a la información indicada
	 * 
	 * @param name Nombre del elemento
	 * @param baseURI Ruta base del elemento
	 * @return <code>true<code> si puede acceder, <code>false</code> en otro caso
	 */
	public boolean canAccess(String name, String baseURI);

}
