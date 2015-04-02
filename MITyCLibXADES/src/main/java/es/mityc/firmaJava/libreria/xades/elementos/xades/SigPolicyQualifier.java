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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;
import es.mityc.javasign.xml.xades.policy.PolicyException;

/**
 */
public class SigPolicyQualifier extends AbstractXADESElement {
	
	private IPolicyQualifier qualifier;
	

	/**
	 * @param schema
	 */
	public SigPolicyQualifier(XAdESSchemas schema) {
		super(schema);
	}

	public SigPolicyQualifier(XAdESSchemas schema, IPolicyQualifier qualifier) {
		super(schema);
		this.qualifier = qualifier;
	}
	
	public IPolicyQualifier getQualifier() {
		return qualifier;
	}

	public void setQualifier(IPolicyQualifier qualifier) {
		this.qualifier = qualifier;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SigPolicyQualifier) {
			SigPolicyQualifier comp = (SigPolicyQualifier) obj;
			if (qualifier == null) {
				if (comp.qualifier != null)
					return false;
				else return true;
			}
			if (qualifier.equals(comp.qualifier))
				return true;
		}
		return false;
	}
	
	@Override
	public Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXAdES);
	}
	
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + ConstantesXADES.XADES_TAG_SIG_POLICY_QUALIFIER);
		super.addContent(res, namespaceXAdES);
		return res;
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (qualifier == null)
			throw new InvalidInfoNodeException("Nodo SigPolicyQualifier sin contenido");
		try {
			Node node = qualifier.createPolicyQualifierContent(element.getOwnerDocument());
			element.appendChild(node);
		} catch (PolicyException ex) {
			throw new InvalidInfoNodeException("Error creando contenido de nodo SigPolicyQualifier", ex);
		}
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), ConstantesXADES.XADES_TAG_SIG_POLICY_QUALIFIER);

		// TODO: tratar con nodos desconocidos (mediante el tipo del nodo y el namespace
		Node node = getFirstNonvoidNode(element);
		if (node.getNodeType() != Node.ELEMENT_NODE)
			throw new InvalidInfoNodeException("Contenido de nodo SigPolicyQualifier desconocido");
		
		SPURI spuri = new SPURI(schema);
		if (spuri.isThisNode(node)) {
			spuri.load((Element)node);
			qualifier = spuri;
		}
		else {
			SPUserNotice userNotice = new SPUserNotice(schema);
			if (userNotice.isThisNode(node)) {
				userNotice.load((Element)node);
				qualifier = userNotice;
			}
			else
				throw new InvalidInfoNodeException("Contenido de nodo SigPolicyQualifier desconocido");
		}
		if ((node != null) && (getNextNonvoidNode(node) != null))
				throw new InvalidInfoNodeException("Contenido de nodo SigPolicyQualifier desconocido");
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), schema.getSchemaUri(), ConstantesXADES.XADES_TAG_SIG_POLICY_QUALIFIER);
	}


}
