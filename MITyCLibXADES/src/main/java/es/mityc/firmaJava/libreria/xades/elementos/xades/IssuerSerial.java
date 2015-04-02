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

import java.math.BigInteger;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.xmldsig.X509IssuerSerialType;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class IssuerSerial extends X509IssuerSerialType {
	
	protected XAdESSchemas schema;
	protected String namespaceXAdES;

	public IssuerSerial(XAdESSchemas schema) {
		super();
		this.schema = schema;
	}
	
	public IssuerSerial(XAdESSchemas schema, String issuerName, BigInteger serialNumber) {
		super(issuerName, serialNumber);
		this.schema = schema;
	}
	
	/**
	 * @return the schema
	 */
	public XAdESSchemas getSchema() {
		return schema;
	}


	/**
	 * @param schema the schema to set
	 */
	public void setSchema(XAdESSchemas schema) {
		this.schema = schema;
	}
	
	/**
	 * Este elemento lo pueden hacer público los elementos
	 * 
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	protected Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		return createElement(doc);
	}
	
	/**
	 * Este elemento lo pueden hacer público los elementos
	 * 
	 * @param doc
	 * @param namespaceXDsig
	 * @param namespaceXAdES
	 * @return
	 * @throws InvalidInfoNodeException
	 */
	public Element createElement(Document doc, String namespaceXDsig, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		return super.createElement(doc, namespaceXDsig);
	}
	
	/**
	 * @return the namespaceXAdES
	 */
	public String getNamespaceXAdES() {
		return namespaceXAdES;
	}


	/**
	 * @param namespaceXAdES the namespaceXAdES to set
	 */
	public void setNamespaceXAdES(String namespaceXAdES) {
		this.namespaceXAdES = namespaceXAdES;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.DigestAlgAndValueType#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), ConstantesXADES.ISSUER_SERIAL);
		super.load(element);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.DigestAlgAndValueType#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), schema.getSchemaUri(), ConstantesXADES.ISSUER_SERIAL);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.DigestAlgAndValueType#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + ConstantesXADES.ISSUER_SERIAL);
		addContent(res, namespaceXAdES, namespaceXDsig);
		return res;
	}
	
	/**
	 * 
	 * @param element
	 * @param namespaceXAdES
	 * @param namespaceXDsig
	 * @throws InvalidInfoNodeException
	 */
	public void addContent(Element element, String namespaceXAdES, String namespaceXDsig) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		super.addContent(element, namespaceXDsig);
	}

}
