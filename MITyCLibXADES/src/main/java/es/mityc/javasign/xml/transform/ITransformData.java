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
package es.mityc.javasign.xml.transform;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * <p>Interfaz que deben cumplir los generadores de la información de apoyo de las transformdas.</p>
 * 
 */
public interface ITransformData {
	
	/**
	 * <p>Devuelve un listado de nodos de información necesaria para la transformada.</p>
	 * @param doc Documento donde se incrustan los nodos
	 * @return Listado de nodos de información, <code>null</code> si no hay nodos que añadir
	 */
	NodeList getExtraData(Document doc);

}
