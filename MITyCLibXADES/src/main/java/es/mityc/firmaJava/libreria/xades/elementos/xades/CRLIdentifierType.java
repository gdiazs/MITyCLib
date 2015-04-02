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

import java.math.BigInteger;
import java.util.Date;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class CRLIdentifierType extends AbstractXADESElement {
	
	private Issuer issuer;
	private IssueTime issueTime;
	private Number number;
	private String uri;

	/**
	 * @param schema
	 */
	public CRLIdentifierType(XAdESSchemas schema, String issuer, Date issueTime, BigInteger number, String URI) {
		super(schema);
		if (issuer != null)
			this.issuer = new Issuer(schema, issuer);
		if (issueTime != null)
			this.issueTime = new IssueTime(schema, issueTime);
		if (number != null)
			this.number = new Number(schema, number);
		if (URI != null)
			this.uri = URI;
	}
	
	public CRLIdentifierType(XAdESSchemas schema) {
		super(schema);
	}
	
	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}
	
	public Issuer getIssuer() {
		return issuer;
	}

	public void setIssuer(Issuer issuer) {
		this.issuer = issuer;
	}

	public IssueTime getIssueTime() {
		return issueTime;
	}

	public void setIssueTime(IssueTime issueTime) {
		this.issueTime = issueTime;
	}

	public Number getNumber() {
		return number;
	}

	public void setNumber(Number number) {
		this.number = number;
	}

	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((issuer == null) || (issueTime == null))
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo CRLIdentifierType");
		
		element.appendChild(issuer.createElement(element.getOwnerDocument(), namespaceXAdES));
		element.appendChild(issueTime.createElement(element.getOwnerDocument(), namespaceXAdES));
		
		if (number != null)
			element.appendChild(number.createElement(element.getOwnerDocument(), namespaceXAdES));

		if (uri != null)
			element.setAttributeNS(null, ConstantesXADES.URI_MAYUS, uri);

	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CRLIdentifierType) {
			CRLIdentifierType crl = (CRLIdentifierType) obj;
			if ((issuer == null) || (issueTime == null))
				return false;
			if (!issuer.equals(crl.getIssuer()))
				return false;
			if (issueTime.equals(crl.getIssueTime()))
				return false;
			// TODO: completar
		}
		return false;
	}

	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		// Recupera los atributos
		if (element.hasAttribute(ConstantesXADES.URI_MAYUS))
			this.uri = element.getAttribute(ConstantesXADES.URI_MAYUS);
		
		// El siguiente elemento es un nodo Issuer
		Node node = UtilidadTratarNodo.getFirstElementChild(element, true);
		if ((node == null) || (node.getNodeType() != Node.ELEMENT_NODE))
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de CRLIdentifierType");
		Element child = (Element)node;
		issuer = new Issuer(schema);
		issuer.load(child);
		
		// El siguiente elemento es un nodo IssueTime
		node = UtilidadTratarNodo.getNextElementSibling(child, true);
		if ((node == null) || (node.getNodeType() != Node.ELEMENT_NODE))
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de CRLIdentifierType");
		child = (Element)node;
		issueTime = new IssueTime(schema);
		issueTime.load(child);

		// El siguiente elemento puede ser un nodo IssueTime
		node = UtilidadTratarNodo.getNextElementSibling(child, true);
		if (node != null) { 
			if (node.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Se esperaba elemento como hijo de CRLIdentifierType");
			child = (Element)node;
			number = new Number(schema);
			number.load(child);
		}
	}

}
