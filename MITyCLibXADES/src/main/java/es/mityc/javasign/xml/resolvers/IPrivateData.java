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
 * Este interfaz permite la obtención del hash de información para ser firmada que permanece privada a la librería de firma.
 * 
 */
public interface IPrivateData {
	
	/**
	 * Obtiene el digest del elemento utilizando el algoritmo de hashing indicado.
	 *  
	 * @param name Nombre del elemento del que se quiere calcular el hashing
	 * @param baseURI Ruta base del elemento
	 * @param algName Nombre del algoritmo de hashing
	 * @return Digest calculado de la información privada
	 * @throws ResourceDataException lanzada cuando no se puede acceder a la información por alguna razón
	 */
	public byte[] getDigest(String name, String baseURI, String algName) throws ResourceDataException;
	
	/**
	 * Indica si esta implementación puede acceder a la información indicada para calcular su digest
	 * 
	 * @param name Nombre del elemento
	 * @param baseURI Ruta base del elemento
	 * @return <code>true<code> si puede calcular su digest, <code>false</code> en otro caso
	 */
	public boolean canDigest(String name, String baseURI);

}
