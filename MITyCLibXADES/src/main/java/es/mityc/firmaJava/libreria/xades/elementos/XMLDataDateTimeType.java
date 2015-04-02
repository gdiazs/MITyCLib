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

import java.util.Date;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.utilidades.UtilidadFechas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class XMLDataDateTimeType extends AbstractXMLElement {
	
	protected Date value;

	/**
	 * 
	 */
	public XMLDataDateTimeType(Date value) {
		this.value = value;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	public void addContent(Element element) throws InvalidInfoNodeException {
		if (value == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo DateTimeType");
		
		element.setTextContent(UtilidadFechas.formatFechaXML(value));
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof XMLDataDateTimeType) {
			if (value.equals(((XMLDataDateTimeType)obj).value))
				return true;
		} else if (obj instanceof Date) {
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
		if ((node == null) || (node.getNodeType() != Node.TEXT_NODE))
			throw new InvalidInfoNodeException("Nodo xsd:string no contiene CDATA como primer valor");

		String value = node.getNodeValue();
		if (value != null) 
			this.value = UtilidadFechas.parseaFechaXML(value);
		
		if (this.value == null)
			throw new InvalidInfoNodeException("Contenido de valor de xsd.string vacío");
	}

	/**
	 * @return the value
	 */
	public Date getValue() {
		return value;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(Date value) {
		this.value = value;
	}
	
}
