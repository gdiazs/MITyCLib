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
/**
 * 
 */
package es.mityc.firmaJava.libreria.xades.elementos.xades;

import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.XMLDataDateTimeType;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * 
 *
 */
public class AbstractXadesDateElement extends AbstractXADESElement {

	private XMLDataDateTimeType data;
	private String nameElement;


	public AbstractXadesDateElement(XAdESSchemas schema, String nameElement, Date data) {
		super(schema);
		this.nameElement = nameElement;
		this.data = new XMLDataDateTimeType(data);
	}

	/**
	 * @param namespaceXAdES
	 * @param namespaceXDSig
	 * @param schema
	 */
	public AbstractXadesDateElement(XAdESSchemas schema, String nameElement) {
		super(schema);
		this.nameElement = nameElement;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		if (data == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir elemento " + nameElement);
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + nameElement);
		data.addContent(res);
		return res;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.AbstractXADESElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXAdES);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof AbstractXadesDateElement) {
			AbstractXadesDateElement desc = (AbstractXadesDateElement) obj;
			if ((nameElement.equals(desc.nameElement)) && (data.equals(desc.data)))
				return true;
		}
		else
			return data.equals(obj);
		return false;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), nameElement);
		data = new XMLDataDateTimeType(null);
		data.load(element);
	}
	
	public void setValue(Date value) {
		if (data == null)
			data = new XMLDataDateTimeType(value);
		else
			data.setValue(value);
	}
	
	public Date getValue() {
		if (data != null)
			return data.getValue();
		return null;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), schema.getSchemaUri(), nameElement);
	}

}
