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
package es.mityc.firmaJava.libreria.xades.elementos.xades;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class SignaturePolicyIdentifierType extends AbstractXADESElement {
	
	private SignaturePolicyImplied signaturePolicyImplied;
	private SignaturePolicyId signaturePolicyId;

	/**
	 * @param schema
	 */
	public SignaturePolicyIdentifierType(XAdESSchemas schema) {
		super(schema);
	}
	
	public SignaturePolicyIdentifierType(XAdESSchemas schema, boolean isImplied) {
		super(schema);
		if (isImplied)
			signaturePolicyImplied = new SignaturePolicyImplied(schema);
		else
			signaturePolicyId = new SignaturePolicyId(schema);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.AbstractXADESElement#addContent(org.w3c.dom.Element, java.lang.String, java.lang.String)
	 */
	@Override
	public void addContent(Element element, String namespaceXAdES, String namespaceXDsig) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES, namespaceXDsig);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (isImplied()) {
			element.appendChild(signaturePolicyImplied.createElement(element.getOwnerDocument(), namespaceXAdES));
		} else {
			if (signaturePolicyId == null)
				throw new InvalidInfoNodeException("Información insuficiente para escribir nodo SignaturePolicyId");
			element.appendChild(signaturePolicyId.createElement(element.getOwnerDocument(), namespaceXDsig, namespaceXAdES));
		}
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SignaturePolicyIdentifierType) {
			SignaturePolicyIdentifierType spit = (SignaturePolicyIdentifierType) obj;
			if (isImplied()) {
				if (spit.isImplied())
					return true;
			}
			else {
				if ((signaturePolicyId == null) || (spit.isImplied()))
					return false;
				else if (signaturePolicyId.equals(spit.signaturePolicyId))
					return true;
			}
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		// Nodo SignaturePolicyImplied o SignaturePolicyId
		Node node = getFirstNonvoidNode(element);
		SignaturePolicyImplied spi = new SignaturePolicyImplied(schema);
		if (spi.isThisNode(node)) {
			spi.load((Element)node);
			signaturePolicyImplied = spi;
		} else {
			SignaturePolicyId spid = new SignaturePolicyId(schema);
			spid.load((Element)node);
			signaturePolicyId = spid;
		}
		if (UtilidadTratarNodo.getNextElementSibling(node, true) != null)
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdentifierType debe tener un único hijo");
	}

	/**
	 * @return the signaturePolicyImplied
	 */
	public SignaturePolicyImplied getSignaturePolicyImplied() {
		return signaturePolicyImplied;
	}

	/**
	 * @param signaturePolicyImplied the signaturePolicyImplied to set
	 */
	public void setSignaturePolicyImplied() {
		this.signaturePolicyImplied = new SignaturePolicyImplied(schema);
		this.signaturePolicyId = null;
	}

	/**
	 * @return the signaturePolicyId
	 */
	public SignaturePolicyId getSignaturePolicyId() {
		return signaturePolicyId;
	}

	/**
	 * @param signaturePolicyId the signaturePolicyId to set
	 */
	public void setSignaturePolicyId(SignaturePolicyId signaturePolicyId) {
		this.signaturePolicyId = signaturePolicyId;
		this.signaturePolicyId = null;
	}

	public boolean isImplied() {
		if (signaturePolicyImplied != null)
			return true;
		return false;
	}
}
