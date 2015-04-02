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

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public abstract class TransformType extends AbstractXDsigElement {

	// TODO: tratarlo como URI
	private String algorithm;
	private NodeList extraNodes;

	/**
	 * @param namespaceXDSig
	 */
	public TransformType(String algorithm) {
		super();
		this.algorithm = algorithm;
	}
	
	public TransformType() {
		super();
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof TransformType) {
			TransformType method = (TransformType) obj;
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
		if (!element.hasAttribute(ConstantesXADES.ALGORITHM))
			throw new InvalidInfoNodeException("Atributo requerido no presente" + ConstantesXADES.ALGORITHM);
		this.algorithm = element.getAttribute(ConstantesXADES.ALGORITHM);
		
		// carga los hijos
		extraNodes = element.getChildNodes();
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
	
	public NodeList getExtraNodes() {
		return extraNodes;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (algorithm == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo TransformType");
		element.setAttributeNS(null, ConstantesXADES.ALGORITHM, algorithm);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#addContent(org.w3c.dom.Element, java.lang.String)
	 */
	@Override
	public void addContent(Element element, String namespaceXDsig) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXDsig);
	}
	
}
