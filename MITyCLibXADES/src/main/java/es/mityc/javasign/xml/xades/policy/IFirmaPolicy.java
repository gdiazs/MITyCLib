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
package es.mityc.javasign.xml.xades.policy;

import org.w3c.dom.Element;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;

/**
 * Interfaz que han de implementar las clases que añadan policies que gestiona el manager de policies.
 * 
 * Además los escritores de policies deben tener un constructor por defecto sin parámetros.
 *
 */
public interface IFirmaPolicy {
	
	/**
	 * Este método deberá encargarse escribir la policy.
	 * 
	 * @param signNode nodo raíz (de firma) de la firma en la que se quiere escribir la política
	 * @param namespaceDS Namespace de xmlDSig
	 * @param namespaceXAdES namespace de XAdES
	 * @param schema esquema de XAdEs
	 * 
	 * @throws lanza una excepción si no puede escribir la policy.
	 */
	public void writePolicyNode(Element signNode, String namespaceDS, String namespaceXAdES, XAdESSchemas schema) throws PolicyException;


}
