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

import java.io.ByteArrayInputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 *
 */
public class EncapsulatedCRLValue extends EncapsulatedPKIDataType {
	
	/**
	 * @param schema
	 */
	public EncapsulatedCRLValue(XAdESSchemas schema) {
		super(schema);
	}

	/**
	 * @param schema
	 * @param id
	 */
	public EncapsulatedCRLValue(XAdESSchemas schema, String id) {
		super(schema, id);
	}

	public EncapsulatedCRLValue(XAdESSchemas schema, String id, X509CRL crl) throws InvalidInfoNodeException {
		super(schema, id);
		try {
			setValue(new String(Base64Coder.encode(crl.getEncoded())));
		} catch (CRLException ex) {
			throw new InvalidInfoNodeException("Error al extraer la información de la crl", ex);
		}
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.EncapsulatedPKIDataType#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), ConstantesXADES.XADES_TAG_ENCAPSULATED_CRL_VALUE);
		super.load(element);

		// Si no está en DER está mal
		EncodingEnum encoding = getEncoding();
		if ((encoding != null) && (!encoding.equals(EncodingEnum.DER_ENCODED)))
			throw new InvalidInfoNodeException("El contenido de EncapsulatedCRLValue debe estar en la codificación " + EncodingEnum.DER_ENCODED.getEncodingUri().toString());
				
		// Comprueba que el valor recogido es un una CRL X.509
		X509CRL crl;
		try {
			crl = getX509CRL();
		} catch (CRLException ex) {
			throw new InvalidInfoNodeException("El contenido de EncapsulatedCRLValue no es un certificado X509 válido", ex);
		}
		if (crl == null) {
			throw new InvalidInfoNodeException("El contenido de EncapsulatedCRLValue no es un certificado X509 válido");
		}
	}
	
	public X509CRL getX509CRL() throws CRLException {
		String value = getValue();
		if (value != null) {
			byte[] data;
			try {
				 data = Base64Coder.decode(value);
			} catch (IllegalArgumentException ex) {
				throw new CRLException("Contenido base64 de EncapsulatedCRLValue inválido", ex);
			}
			ByteArrayInputStream bais = new ByteArrayInputStream(data);
			
			CertificateFactory cf;
			try {
				cf = CertificateFactory.getInstance(ConstantesXADES.X_509);
			} catch (CertificateException ex) {
				throw new CRLException(ex);			
			}
			CRL crl = cf.generateCRL(bais);
			if (crl instanceof X509CRL)
				return (X509CRL)crl;
			throw new CRLException("Contenido base64 de EncapsulatedCRLValue no es una CRL del tipo X.509");
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
		return isElementName(nodeToElement(node), schema.getSchemaUri(), ConstantesXADES.XADES_TAG_ENCAPSULATED_CRL_VALUE);
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
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + ConstantesXADES.XADES_TAG_ENCAPSULATED_CRL_VALUE);
		super.addContent(res, namespaceXAdES);
		return res;
	}

}
