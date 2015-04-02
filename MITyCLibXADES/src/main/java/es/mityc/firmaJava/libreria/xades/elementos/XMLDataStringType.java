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
package es.mityc.firmaJava.libreria.xades.elementos;

import org.apache.commons.lang.StringEscapeUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.utilidades.Utilidades;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class XMLDataStringType extends AbstractXMLElement {
	
	protected String value;

	/**
	 * 
	 */
	public XMLDataStringType(String value) {
		this.value = value;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	public void addContent(Element element) throws InvalidInfoNodeException {
		if (value == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo XMLDataStringType");
		element.setTextContent(Utilidades.escapeXML(value));
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof XMLDataStringType) {
			XMLDataStringType xdst = (XMLDataStringType)obj;
			if (value.equals(xdst))
				return true;
		} else if (obj instanceof String) {
			String data = (String) obj;
			if (value.equals(data))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		Node node = getFirstNonvoidNode(element);
		if ((node != null) && (node.getNodeType() != Node.TEXT_NODE)) {
			throw new InvalidInfoNodeException("Nodo xsd:string no contiene CDATA como primer valor");
		}
		
		if (node == null) {
			this.value = new String("");
		} else {
			this.value = node.getNodeValue();
			if (this.value == null) {
				throw new InvalidInfoNodeException("Contenido de valor de xsd:string vacío");
			}
			this.value = StringEscapeUtils.unescapeXml(this.value);
		}
	}

	/**
	 * @return the value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(String value) {
		this.value = value;
	}

}
