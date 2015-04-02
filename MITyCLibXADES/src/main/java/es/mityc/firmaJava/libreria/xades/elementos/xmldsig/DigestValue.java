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
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * 
 * TODO: incluir metodo para devolver y aceptar el resultado en binario (codificar/decodificar base64)
 */
public class DigestValue extends AbstractXDsigElement {

	private String value;
	
	public DigestValue() {
		super();
	}

	/**
	 * @param namespaceXDSig
	 */
	public DigestValue(String value) {
		super();
		setValue(value);
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
		if (this.value != null)
			this.value = this.value.replace(" ", "").replace("\n", "").replace("\r", "");
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		if (value == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir elemento DigestValue");
		Element res = doc.createElementNS(ConstantesXADES.SCHEMA_DSIG, namespaceXDsig + ":" + ConstantesXADES.DIGEST_VALUE);
		res.setTextContent(value);
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
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DigestValue) {
			DigestValue huella = (DigestValue) obj;
			if (value.equals(huella.value))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE);
		
		Node node = getFirstNonvoidNode(element);
		if ((node == null) || (node.getNodeType() != Node.TEXT_NODE))
			throw new InvalidInfoNodeException("Nodo DigestValue no contiene CDATA como primer valor");

		this.value = node.getNodeValue();
		if (this.value == null)
			throw new InvalidInfoNodeException("Contenido de valor de digest vacío");
		this.value = this.value.replace(" ", "").replace("\n", "").replace("\r", "");
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE);
	}

}
