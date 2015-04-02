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
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class Cert extends CertIDType {
	
	public Cert(XAdESSchemas schema) {
		super(schema);
	}

	/**
	 * @param schema
	 * @param digest
	 * @param issuerSerial
	 */
	public Cert(XAdESSchemas schema, CertDigest digest, IssuerSerial issuerSerial) {
		super(schema, digest, issuerSerial);
	}

	/**
	 * @param schema
	 * @param digestMethod
	 * @param digestValue
	 * @param issuerName
	 * @param serialNumber
	 * @throws InvalidInfoNodeException
	 */
	public Cert(XAdESSchemas schema, String digestMethod, byte[] digestValue, String issuerName, BigInteger serialNumber)
			throws InvalidInfoNodeException {
		super(schema, digestMethod, digestValue, issuerName, serialNumber);
	}

	/**
	 * @param schema
	 * @param digestMethod
	 * @param digestValue
	 * @param issuerName
	 * @param serialNumber
	 */
	public Cert(XAdESSchemas schema, String digestMethod, String digestValue, String issuerName, BigInteger serialNumber) {
		super(schema, digestMethod, digestValue, issuerName, serialNumber);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.DigestAlgAndValueType#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), ConstantesXADES.CERT);
		super.load(element);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.DigestAlgAndValueType#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), schema.getSchemaUri(), ConstantesXADES.CERT);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.AbstractXADESElement#createElement(org.w3c.dom.Document, java.lang.String, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXDsig, String namespaceXAdES) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXDsig, namespaceXAdES);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.DigestAlgAndValueType#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + ConstantesXADES.CERT);
		super.addContent(res, namespaceXAdES, namespaceXDsig);
		return res;
	}

}
