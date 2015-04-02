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
 * Elemento DigestMethod (rfc 3275 4.3.3.5).
 *  
 */
public class DigestMethod extends AbstractXDsigElement {
	
	// TODO: tratarlo como URI y no como String
	private String algorithm;

	/**
	 * @param namespaceXDSig
	 */
	public DigestMethod(String algorithm) {
		super();
		this.algorithm = algorithm;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		if (algorithm == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir elemento DigestMethod");
		Element res = doc.createElementNS(ConstantesXADES.SCHEMA_DSIG, namespaceXDsig + ":" + ConstantesXADES.DIGEST_METHOD);
		res.setAttributeNS(null, ConstantesXADES.ALGORITHM, algorithm);
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
		if (obj instanceof DigestMethod) {
			DigestMethod method = (DigestMethod) obj;
			if (algorithm.equals(method.algorithm))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD);
		if (!element.hasAttribute(ConstantesXADES.ALGORITHM))
			throw new InvalidInfoNodeException("Atributo requerido no presente" + ConstantesXADES.ALGORITHM);
		this.algorithm = element.getAttribute(ConstantesXADES.ALGORITHM);
	}

	/**
	 * @return the algorithm
	 */
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * @param algorithm the algorithm to set
	 */
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD);
	}

}
