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

import java.net.URI;
import java.net.URISyntaxException;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class XMLDataURIType extends AbstractXMLElement {
	
	protected URI value;

	/**
	 * 
	 */
	public XMLDataURIType(URI value) {
		this.value = value;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	public void addContent(Element element) throws InvalidInfoNodeException {
		if (value == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo XMLDataURIType");
		
		element.setTextContent(value.toString());
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof XMLDataURIType) {
			if (value.equals(((XMLDataURIType)obj).value))
				return true;
		} else if (obj instanceof URI) {
			if (value.equals(obj))
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
		if (node == null) {
		    return;
		}
		if (node.getNodeType() != Node.TEXT_NODE)
			throw new InvalidInfoNodeException("Nodo xsd:anyURI no contiene CDATA como primer valor");

		URI uri;
		
		String data = node.getNodeValue();
		if (data == null)
			throw new InvalidInfoNodeException("No hay URI en nodo xsd:anyURI");
		
		try {
			// FIX: Cambia los espacios por %20 para evitar problemas con la clase URI
			data = data.replace(" ", "%20");
			uri = new URI(data);
		} catch (URISyntaxException ex) {
			throw new InvalidInfoNodeException("URI malformada en nodo xsd:anyURI", ex);
		}
		
		this.value = uri;
	}

	/**
	 * @return the value
	 */
	public URI getValue() {
		return value;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(URI value) {
		this.value = value;
	}
	
}
