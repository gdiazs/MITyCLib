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

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * <p>Indica un conjunto de transformadas XPath.</p>
 * 
 */
public class XPathTransformData implements ITransformData {
	
	private List<String> paths = new ArrayList<String>();
	
	/**
	 * <p>Incluye el path indicado para la transformada.</p>
	 * @param path
	 */
	public void addPath(String path) {
		paths.add(path);
	}

	/**
	 * @see es.mityc.javasign.xml.transform.ITransformData#getExtraData(org.w3c.dom.Document))
	 */
	public NodeList getExtraData(Document doc) {
		SimpleNodeList nl = null;
		if (paths.size() > 0) {
			nl = new SimpleNodeList();
			for (String path : paths) {
				Element pathElement = doc.createElementNS(ConstantesXADES.SCHEMA_DSIG, "ds:XPath");
				pathElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", ConstantesXADES.SCHEMA_DSIG);
				pathElement.setTextContent(path);
				nl.addNode(pathElement);
			}
		}
		return nl;
	}
}
