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
package es.mityc.firmaJava.libreria.xades.elementos.xmldsig;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.elementos.XMLDataStringType;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class AbstractXDSigStringElement extends AbstractXDsigElement {

	private XMLDataStringType data;
	private String nameElement;


	public AbstractXDSigStringElement(String nameElement, String data) {
		super();
		this.nameElement = nameElement;
		this.data = new XMLDataStringType(data);
	}

	/**
	 * @param namespaceXDSig
	 * @param schema
	 */
	public AbstractXDSigStringElement(String nameElement) {
		super();
		this.nameElement = nameElement;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		if (data == null) {
			throw new InvalidInfoNodeException("Información insuficiente para escribir elemento " + nameElement);
		}
		Element res = doc.createElementNS(ConstantesXADES.SCHEMA_DSIG, namespaceXDsig + ":" + nameElement);
		data.addContent(res);
		return res;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXDsig) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXDsig);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof AbstractXDSigStringElement) {
			AbstractXDSigStringElement desc = (AbstractXDSigStringElement) obj;
			if ((nameElement.equals(desc.nameElement)) && (data.equals(desc.data))) {
				return true;
			}
		} else {
			return data.equals(obj);
		}
		return false;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, ConstantesXADES.SCHEMA_DSIG, nameElement);
		data = new XMLDataStringType(null);
		data.load(element);
	}
	
	public void setValue(String value) {
		if (data == null) {
			data = new XMLDataStringType(value);
		} else {
			data.setValue(value);
		}
	}
	
	public String getValue() {
		if (data != null) {
			return data.getValue();
		}
		return null;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), ConstantesXADES.SCHEMA_DSIG, nameElement);
	}

}
