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

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class EncapsulatedX509Certificate extends EncapsulatedPKIDataType {
	
	/**
	 * @param schema
	 */
	public EncapsulatedX509Certificate(XAdESSchemas schema) {
		super(schema);
	}

	/**
	 * @param schema
	 * @param id
	 */
	public EncapsulatedX509Certificate(XAdESSchemas schema, String id) {
		super(schema, id);
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.EncapsulatedPKIDataType#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), ConstantesXADES.ENCAPSULATED_X_509_CERTIFICATE);
		super.load(element);

		// Si no está en DER está mal
		EncodingEnum encoding = getEncoding();
		if ((encoding != null) && (!encoding.equals(EncodingEnum.DER_ENCODED)))
			throw new InvalidInfoNodeException("El contenido de EncapsulatedX509Certificate debe estar en la codificación " + EncodingEnum.DER_ENCODED.getEncodingUri().toString());
				
		// Comprueba que el valor recogido es un certificado X509
		X509Certificate cert;
		try {
			cert = getX509Certificate();
		} catch (CertificateException ex) {
			throw new InvalidInfoNodeException("El contenido de EncapsulatedX509Certificate no es un certificado X509 válido", ex);
		}
		if (cert == null) {
			throw new InvalidInfoNodeException("El contenido de EncapsulatedX509Certificate no es un certificado X509 válido");
		}
	}
	
	public X509Certificate getX509Certificate() throws CertificateException {
		String value = getValue();
		if (value != null) {
			byte[] data;
			try {
				 data = Base64Coder.decode(value);
			} catch (IllegalArgumentException ex) {
				throw new CertificateException("Contenido base64 de EncapsulatedX509Certificate inválido", ex);
			}
			ByteArrayInputStream bais = new ByteArrayInputStream(data);
			CertificateFactory cf = CertificateFactory.getInstance(ConstantesXADES.X_509);
			Certificate cert = cf.generateCertificate(bais);
			if (cert instanceof X509Certificate)
				return (X509Certificate)cert;
			throw new CertificateException("Contenido base64 de EncapsulatedX509Certificate no es un certificado tipo X.509");
		}
		else 
			return null;
	}
	
	public void setX509Certificate(X509Certificate certificate) throws CertificateException {
		setValue(new String(Base64Coder.encode(certificate.getEncoded())));
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), schema.getSchemaUri(), ConstantesXADES.ENCAPSULATED_X_509_CERTIFICATE);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.AbstractXADESElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXAdES);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + ConstantesXADES.ENCAPSULATED_X_509_CERTIFICATE);
		super.addContent(res, namespaceXAdES);
		return res;
	}

}
