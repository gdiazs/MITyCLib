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

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class CertIDType extends AbstractXADESElement {
	
	private CertDigest digest;
	private IssuerSerial issuerSerial;
	
	public CertIDType(XAdESSchemas schema) {
		super(schema);
	}
	
	public CertIDType(XAdESSchemas schema, CertDigest digest, IssuerSerial issuerSerial) {
		super(schema);
		this.digest = digest;
		this.issuerSerial = issuerSerial;
	}
	
	public CertIDType(XAdESSchemas schema, String digestMethod, String digestValue, String issuerName, BigInteger serialNumber) {
		super(schema);
		this.digest = new CertDigest(schema, digestMethod, digestValue);
		this.issuerSerial = new IssuerSerial(schema, issuerName, serialNumber);
	}
	
	public CertIDType(XAdESSchemas schema, String digestMethod, byte[] digestValue, String issuerName, BigInteger serialNumber) throws InvalidInfoNodeException {
		super(schema);
		this.digest = new CertDigest(schema, digestMethod, digestValue);
		this.issuerSerial = new IssuerSerial(schema, issuerName, serialNumber);
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CertIDType) {
			CertIDType cit = (CertIDType) obj;
			if ((digest == null) || (issuerSerial == null)) {
				return false;
			}
			if (!digest.equals(cit.digest))
				return false;
			if (issuerSerial.equals(cit.issuerSerial))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		Node node = getFirstNonvoidNode(element);
		
		CertDigest digest = new CertDigest(getSchema());
		if (!digest.isThisNode(node)) {
			throw new InvalidInfoNodeException("Se esperaba nodo CertDigest en CertIDType");
		}
		digest.load((Element) node);
		
		node = getNextNonvoidNode(node);
		IssuerSerial issuerSerial = new IssuerSerial(getSchema());
		if (!issuerSerial.isThisNode(node)) {
			throw new InvalidInfoNodeException("Se esperaba nodo IssuerSerial en CertIDType");
		}
		issuerSerial.load((Element) node);
			
		this.digest = digest;
		this.issuerSerial = issuerSerial;
	}
	
	public void setDigest(CertDigest digest) {
		this.digest = digest;
	}
	
	public void setDigest(String digestMethod, String digestValue) {
		this.digest = new CertDigest(schema, digestMethod, digestValue);
	}
	
	public void setDigest(String digestMethod, byte[] digestValue) throws InvalidInfoNodeException {
		this.digest = new CertDigest(schema, digestMethod, digestValue);
	}
	
	public CertDigest getCertDigest() {
		return this.digest;
	}
	
	public void setIssuerSerial(String issuerName, BigInteger serialNumber) {
		this.issuerSerial = new IssuerSerial(schema, issuerName, serialNumber);
	}
	
	public void setIssuerSerial(IssuerSerial issuerSerial) {
		this.issuerSerial = issuerSerial;
	}
	
	public IssuerSerial getIssuerSerial() {
		return this.issuerSerial;
	}

}
