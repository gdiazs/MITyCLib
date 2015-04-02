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

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.xmldsig.Transforms;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class SignaturePolicyIdType extends AbstractXADESElement {
	
	private SigPolicyId sigPolicyId;
	private Transforms transforms;
	private SigPolicyHash sigPolicyHash;
	private SigPolicyQualifiers sigPolicyQualifiers;

	/**
	 * @param schema
	 */
	public SignaturePolicyIdType(XAdESSchemas schema) {
		super(schema);
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
		if ((sigPolicyId == null) || (sigPolicyHash == null))
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo SignaturePolicyIdType");
		
		element.appendChild(sigPolicyId.createElement(element.getOwnerDocument(), namespaceXAdES));
		
		if (transforms != null) {
			element.appendChild(transforms.createElement(element.getOwnerDocument(), namespaceXDsig));
		}
		
		element.appendChild(sigPolicyHash.createElement(element.getOwnerDocument(), namespaceXDsig, namespaceXAdES));
		
		if (sigPolicyQualifiers != null) {
			element.appendChild(sigPolicyQualifiers.createElement(element.getOwnerDocument(), namespaceXAdES));
		}
	}
	

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SignaturePolicyIdType) {
			SignaturePolicyIdType spit = (SignaturePolicyIdType) obj;
			if ((sigPolicyId == null) || (spit.sigPolicyId == null) ||
				(sigPolicyHash == null) || (spit.sigPolicyHash == null))
				return false;
			if (((transforms == null) && (spit.transforms != null)) ||
				(transforms != null) && (spit.transforms == null))
				return false;
			if (((sigPolicyQualifiers == null) && (spit.sigPolicyQualifiers != null)) ||
				(sigPolicyQualifiers != null) && (spit.sigPolicyQualifiers == null))
				return false;
			if ((transforms != null) && (spit.transforms != null) &&
				(!transforms.equals(spit.transforms)))
				return false;
			if (!sigPolicyId.equals(spit.sigPolicyId))
				return false;
			if (!sigPolicyHash.equals(spit.sigPolicyHash))
				return false;
			if ((sigPolicyQualifiers != null) && (spit.sigPolicyQualifiers != null) &&
				(!sigPolicyQualifiers.equals(spit.sigPolicyQualifiers)))
				return false;
			return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		// Nodo SigPolicyId
		Node node = getFirstNonvoidNode(element);
		
		SigPolicyId sigPolicyId = new SigPolicyId(schema);
		if (!sigPolicyId.isThisNode(node))
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdType no tiene hijo SigPolicyId");
		sigPolicyId.load((Element)node);
		
		// Comprueba si el siguiente nodo es de transformadas
		node = getNextNonvoidNode(node);
		Transforms transforms = new Transforms();
		if (transforms.isThisNode(node))
			transforms.load((Element)node);
		else
			transforms = null;
		
		// Nodo SigPolicyHash
		if (node == null)
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdType no tiene hijo SigPolicyId");
		if (transforms != null)
			node = getNextNonvoidNode(node);
		SigPolicyHash sigPolicyHash = new SigPolicyHash(schema);
		if (!sigPolicyHash.isThisNode(node))
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdType no tiene hijo SigPolicyHash");
		sigPolicyHash.load((Element)node);
		node = getNextNonvoidNode(node);
		
		// nodo SigPolicyQualifiers
		SigPolicyQualifiers sigPolicyQualifiers = null;
		if (node != null) {
			sigPolicyQualifiers = new SigPolicyQualifiers(schema);
			if (!sigPolicyQualifiers.isThisNode(node))
				throw new InvalidInfoNodeException("Nodo SigPolicyQualifiers esperado como hijo de SignaturePolicyIdType");
			sigPolicyQualifiers.load((Element)node);
		}
		
		this.sigPolicyId = sigPolicyId;
		this.transforms = transforms;
		this.sigPolicyHash = sigPolicyHash;
		this.sigPolicyQualifiers = sigPolicyQualifiers;
	}

	/**
	 * @return the sigPolicyId
	 */
	public SigPolicyId getSigPolicyId() {
		return sigPolicyId;
	}

	/**
	 * @param sigPolicyId the sigPolicyId to set
	 */
	public void setSigPolicyId(SigPolicyId sigPolicyId) {
		this.sigPolicyId = sigPolicyId;
	}

	/**
	 * @return the transforms
	 */
	public Transforms getTransforms() {
		return transforms;
	}

	/**
	 * @param transforms the transforms to set
	 */
	public void setTransforms(Transforms transforms) {
		this.transforms = transforms;
	}

	/**
	 * @return the sigPolicyHash
	 */
	public SigPolicyHash getSigPolicyHash() {
		return sigPolicyHash;
	}

	/**
	 * @param sigPolicyHash the sigPolicyHash to set
	 */
	public void setSigPolicyHash(SigPolicyHash sigPolicyHash) {
		this.sigPolicyHash = sigPolicyHash;
	}

	public SigPolicyQualifiers getSigPolicyQualifiers() {
		return sigPolicyQualifiers;
	}

	public void setSigPolicyQualifiers(SigPolicyQualifiers sigPolicyQualifiers) {
		this.sigPolicyQualifiers = sigPolicyQualifiers;
	}
	
}
