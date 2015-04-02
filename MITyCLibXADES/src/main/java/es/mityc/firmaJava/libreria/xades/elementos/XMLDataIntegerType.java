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

import java.math.BigInteger;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

public class XMLDataIntegerType extends AbstractXMLElement {
	
	protected BigInteger value;

	/**
	 * 
	 */
	public XMLDataIntegerType(BigInteger value) {
		this.value = value;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	public void addContent(Element element) throws InvalidInfoNodeException {
		if (value == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo XMLDataStringType");
		element.setTextContent(value.toString());
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof XMLDataIntegerType) {
			XMLDataIntegerType xdst = (XMLDataIntegerType) obj;
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
		if (node.getNodeType() != Node.TEXT_NODE)
			throw new InvalidInfoNodeException("Nodo xsd:string no contiene CDATA como primer valor");

		try {
			String strvalue = node.getNodeValue();
			if (strvalue == null)
				throw new InvalidInfoNodeException("Contenido de valor de xsd.string vacío");
			this.value = new BigInteger(strvalue);
		} catch (NumberFormatException ex) {
			throw new InvalidInfoNodeException("Contenido de valor de xsd.integer no numérico");
		}
		
	}

	/**
	 * @return the value
	 */
	public BigInteger getValue() {
		return value;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(BigInteger value) {
		this.value = value;
	}

}
