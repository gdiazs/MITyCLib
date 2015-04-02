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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class CRLRefType extends AbstractXADESElement {
	
	private DigestAlgAndValue digest;
	private CRLIdentifier crlIdentifier;

	/**
	 * @param schema
	 */
	public CRLRefType(XAdESSchemas schema) {
		super(schema);
	}

	public CRLRefType(XAdESSchemas schema, String method, X509CRL crl) throws InvalidInfoNodeException {
		super(schema);
		loadCRL(method, crl);
	}
	
	public CRLRefType(XAdESSchemas schema, String method, File crlFile) throws InvalidInfoNodeException {
		super(schema);
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL)cf.generateCRL(new FileInputStream(crlFile));
			loadCRL(method, crl);
		} catch (CertificateException ex) {
			throw new InvalidInfoNodeException("Error generando digest de CRL", ex);
		} catch (CRLException ex) {
			throw new InvalidInfoNodeException("Error generando digest de CRL", ex);
		} catch (FileNotFoundException ex) {
			throw new InvalidInfoNodeException("Error generando digest de CRL", ex);
		}
	}
	
	private void loadCRL(String method, X509CRL crl) throws InvalidInfoNodeException {
		try {
			digest = new DigestAlgAndValue(schema, method, crl.getEncoded());
		} catch (CRLException ex) {
			throw new InvalidInfoNodeException("Error generando digest de CRL", ex);
		}
		BigInteger numeroRecuperado = null;
		byte[] extension = crl.getExtensionValue(ConstantesXADES.CRL_NUMBER_OID);
		if (extension != null) {
			try {
				ASN1InputStream ais = new ASN1InputStream(extension);
				ais = new ASN1InputStream(((DEROctetString)ais.readObject()).getOctets());
				DERInteger derInt = (DERInteger)ais.readObject();
				numeroRecuperado = derInt.getValue();
			} catch (IOException ex) {
				throw new InvalidInfoNodeException("Error generando digest de CRL", ex);
			}
		}
		crlIdentifier = new CRLIdentifier(schema, crl.getIssuerX500Principal().getName(), crl.getThisUpdate(), numeroRecuperado, null);
	}

	public DigestAlgAndValue getDigest() {
		return digest;
	}

	public void setDigest(DigestAlgAndValue digest) {
		this.digest = digest;
	}

	public CRLIdentifier getCrlIdentifier() {
		return crlIdentifier;
	}

	public void setCrlIdentifier(CRLIdentifier crlIdentifier) {
		this.crlIdentifier = crlIdentifier;
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES, String namespaceXDsig) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES, namespaceXDsig);
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (digest == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo CRLRefType");
		
		element.appendChild(digest.createElement(element.getOwnerDocument(), namespaceXDsig, namespaceXAdES));
		
		if (crlIdentifier != null) {
			element.appendChild(crlIdentifier.createElement(element.getOwnerDocument(), namespaceXAdES));
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CRLRefType) {
			CRLRefType crl = (CRLRefType) obj;
			if ((digest == null) || (crl.digest == null))
				return false;
			if (digest.equals(crl.digest))
				return true;
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		Node node = element.getFirstChild();
		DigestAlgAndValue digest = new DigestAlgAndValue(schema);
		if (!digest.isThisNode(node))
			throw new InvalidInfoNodeException("Nodo CRLRefType no tiene hijo DigestAlgAndValue");
		digest.load((Element)node);
		
		node = node.getNextSibling();
		CRLIdentifier crlIdentifier = null;
		if (node != null) {
			crlIdentifier = new CRLIdentifier(schema);
			if (!crlIdentifier.isThisNode(node))
				throw new InvalidInfoNodeException("Se esperaba hijo CRLIdentifier en nodo CRLRefType");
			crlIdentifier.load((Element)node);
		}

		this.digest = digest;
		this.crlIdentifier = crlIdentifier;
	}

}
