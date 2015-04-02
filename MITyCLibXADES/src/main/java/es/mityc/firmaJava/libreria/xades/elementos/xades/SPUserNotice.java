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
public class SPUserNotice extends SPUserNoticeType implements IPolicyQualifier {

	/**
	 * @param schema
	 */
	public SPUserNotice(XAdESSchemas schema) {
		super(schema);
	}

	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), ConstantesXADES.XADES_TAG_SP_USER_NOTICE);
		super.load(element);
	}
	
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), schema.getSchemaUri(), ConstantesXADES.XADES_TAG_SP_USER_NOTICE);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.AbstractXADESElement#createElement(org.w3c.dom.Document, java.lang.String, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXAdES);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.SignaturePolicyIdType#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + ConstantesXADES.XADES_TAG_SP_USER_NOTICE);
		super.addContent(res, namespaceXAdES);
		return res;
	}

	public Node createPolicyQualifierContent(Document doc) throws PolicyException {
		Element el = null;
		try {
			if (getNamespaceXAdES() != null)
				el = createElement(doc, namespaceXAdES);
			else
				throw new PolicyException("No se ha indicado qualifier para nodo SPUserNotice");
		} catch (InvalidInfoNodeException ex) {
			throw new PolicyException(ex);
		}
		return el;
	}

	public void loadPolicyQualifierContent(Element element) throws PolicyException {
		try {
			load(element);
		} catch (InvalidInfoNodeException ex) {
			throw new PolicyException(ex);
		}
	}

}
