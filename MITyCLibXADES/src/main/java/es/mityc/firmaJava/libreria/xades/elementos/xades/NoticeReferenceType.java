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

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class NoticeReferenceType extends AbstractXADESElement {
	
	private Organization organization;
	private NoticeNumbers noticeNumbers;

	/**
	 * @param schema
	 */
	public NoticeReferenceType(XAdESSchemas schema) {
		super(schema);
	}
	
	public NoticeReferenceType(XAdESSchemas schema, String organization, int[] numbers) {
		super(schema);
		this.organization = new Organization(schema, organization);
		this.noticeNumbers = new NoticeNumbers(schema, numbers);
	}
	
	public Organization getOrganization() {
		return organization;
	}

	public void setOrganization(Organization organization) {
		this.organization = organization;
	}
	
	public void setOrganization(String organization) {
		this.organization = new Organization(schema, organization);
	}

	public NoticeNumbers getNoticeNumbers() {
		return noticeNumbers;
	}

	public void setNoticeNumbers(NoticeNumbers noticeNumbers) {
		this.noticeNumbers = noticeNumbers;
	}
	
	public void setNoticeNumbers(int[] noticeNumbers) {
		this.noticeNumbers = new NoticeNumbers(schema, noticeNumbers);
	}
	
	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof NoticeReferenceType) {
			NoticeReferenceType cvt = (NoticeReferenceType) obj;
			if ((organization == null) || (noticeNumbers == null))
				return false;
			if (!organization.equals(cvt.organization))
				return false;
			if (!noticeNumbers.equals(cvt.noticeNumbers))
				return false;
			return true;
		}
		return false;
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((organization == null) || (noticeNumbers == null))
			throw new InvalidInfoNodeException("Nodo NoticeReferenceType no tiene suficiente información");
		
		element.appendChild(organization.createElement(element.getOwnerDocument(), namespaceXAdES));
		element.appendChild(noticeNumbers.createElement(element.getOwnerDocument(), namespaceXAdES));
	}

	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		Node node = getFirstNonvoidNode(element);
		if ((node == null) || (node.getNodeType() != Node.ELEMENT_NODE))
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de NoticeReferenceType");
		Element child = (Element)node;
		
		Organization org = new Organization(schema);
		org.load(child);
		
		node = getNextNonvoidNode(child);
		if ((node == null) || (node.getNodeType() != Node.ELEMENT_NODE))
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de NoticeReferenceType");
		child = (Element)node;
		NoticeNumbers nn = new NoticeNumbers(schema);
		nn.load(child);
		
		this.organization = org;
		this.noticeNumbers = nn;
	}

}
