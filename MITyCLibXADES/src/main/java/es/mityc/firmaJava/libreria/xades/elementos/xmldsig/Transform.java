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
 */
public class Transform extends TransformType {

	/**
	 * @param namespaceXDSig
	 * @param algorithm
	 */
	public Transform(String algorithm) {
		super(algorithm);
	}
	
	/**
	 * @param namespaceXDSig
	 */
	public Transform() {
		super();
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.TransformType#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.TRANSFORM);
		super.load(element);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.TransformType#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.TRANSFORM);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		Element res = doc.createElementNS(ConstantesXADES.SCHEMA_DSIG, namespaceXDsig + ":" + ConstantesXADES.TRANSFORM);
		super.addContent(res, namespaceXDsig);
		return res;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXDsig) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXDsig);
	}
	
}
