/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES 1.1.7".
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
package es.mityc.javasign.pkstore.pkcs11;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

/**
 * <p>Wrapper para permitir indicar de qué provider ha surgido este certificado.</p>
 * 
 */
public class P11CertificateProxy extends X509Certificate {
	/** Certificado X509 real. */
	private X509Certificate internalCert;
	/** Provider del que se ha extraido el certificado. */
	private Provider provider;
	
	/**
	 * <p>Constructor.</p>
	 * @param cert Certificado
	 * @param prov Provider del que surge el certificado
	 */
	P11CertificateProxy(X509Certificate cert, Provider prov) {
		this.internalCert = cert;
		this.provider = prov;
	}
	
	/**
	 * @throws CertificateExpiredException Lanzada cuando el certificado ha expirado
	 * @throws CertificateNotYetValidException Lanzada cuando el certificado todavía no tiene validez
	 * @see java.security.cert.X509Certificate#checkValidity()
	 */
	@Override
	public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
		internalCert.checkValidity();
	}

	/**
	 * <p>Comprueba que el certificado es válido contra la fecha provista.</p>
	 * @param date fecha contra la que comprobar
	 * @throws CertificateExpiredException lanzada si el certificado ha caducado
	 * @throws CertificateNotYetValidException lanzada si el certifiacdo todavía no es válido
	 * @see java.security.cert.X509Certificate#checkValidity(java.util.Date)
	 */
	@Override
	public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
		internalCert.checkValidity(date);
	}

	/**
	 * <p>Devuelve las restricciones de uso básicas.</p>
	 * @return flags de uso
	 * @see java.security.cert.X509Certificate#getBasicConstraints()
	 */
	@Override
	public int getBasicConstraints() {
		return internalCert.getBasicConstraints();
	}

	/**
	 * <p>Devuelve el DN del emisor del certififcado.</p>
	 * @return Princial con el nombre del emisor
	 * @see java.security.cert.X509Certificate#getIssuerDN()
	 */
	@Override
	public Principal getIssuerDN() {
		return internalCert.getIssuerDN();
	}

	/**
	 * <p>Devuelve el valor del campo <code>issuerUniqueID</code> del certificado.</p>
	 * @return array de bytes con el campo <code>issuerUniqueID</code>
	 * @see java.security.cert.X509Certificate#getIssuerUniqueID()
	 */
	@Override
	public boolean[] getIssuerUniqueID() {
		return internalCert.getIssuerUniqueID();
	}

	/**
	 * <p>Devuelve el uso de la clave.</p>
	 * @return flags de uso 
	 * @see java.security.cert.X509Certificate#getKeyUsage()
	 */
	@Override
	public boolean[] getKeyUsage() {
		return internalCert.getKeyUsage();
	}

	/**
	 * <p>Devuelve la fecha de <i>no usar antes</i> del certificado.</p>
	 * @return fecha
	 * @see java.security.cert.X509Certificate#getNotAfter()
	 */
	@Override
	public Date getNotAfter() {
		return internalCert.getNotAfter();
	}

	/**
	 * <p>Devuelve la fecha de caducidad del certificado.</p>
	 * @return fecha
	 * @see java.security.cert.X509Certificate#getNotBefore()
	 */
	@Override
	public Date getNotBefore() {
		return internalCert.getNotBefore();
	}

	/**
	 * <p>Devuelve el número serie del certificado.</p>
	 * @return BigInteger con el número serie
	 * @see java.security.cert.X509Certificate#getSerialNumber()
	 */
	@Override
	public BigInteger getSerialNumber() {
		return internalCert.getSerialNumber();
	}

	/**
	 * <p>Devuelve el nombre del algoritmo con el que se ha firmado el certificado.</p>
	 * @return nombre del algoritmo de firma
	 * @see java.security.cert.X509Certificate#getSigAlgName()
	 */
	@Override
	public String getSigAlgName() {
		return internalCert.getSigAlgName();
	}

	/**
	 * <p>Devuelve el OID del algoritmo con el que se ha firmado el certificado.</p>
	 * @return cadena con el OID del algoritmo de firma
	 * @see java.security.cert.X509Certificate#getSigAlgOID()
	 */
	@Override
	public String getSigAlgOID() {
		return internalCert.getSigAlgOID();
	}

	/**
	 * <p>Devuelve los parámetros del algoritmo con el que se ha firmado el certificado.</p>
	 * @return array de bytes con los parámetros de firma
	 * @see java.security.cert.X509Certificate#getSigAlgParams()
	 */
	@Override
	public byte[] getSigAlgParams() {
		return internalCert.getSigAlgParams();
	}

	/**
	 * <p>Devuelve la firma del certificado.</p>
	 * @return array de bytes con la firma
	 * @see java.security.cert.X509Certificate#getSignature()
	 */
	@Override
	public byte[] getSignature() {
		return internalCert.getSignature();
	}

	/**
	 * <p>Devuelve el DN del asunto del certificado.</p>
	 * @return Principal con el nombre del asunto
	 * @see java.security.cert.X509Certificate#getSubjectDN()
	 */
	@Override
	public Principal getSubjectDN() {
		return internalCert.getSubjectDN();
	}

	/**
	 * <p>Devuelve el campo <code>subjectUniqueID</code> del certificado.</p>
	 * @return campo <code>subjectUniqueID</code>
	 * @see java.security.cert.X509Certificate#getSubjectUniqueID()
	 */
	@Override
	public boolean[] getSubjectUniqueID() {
		return internalCert.getSubjectUniqueID();
	}

	/**
	 * <p>Devuelve el campo <code>tbsCertificate</code>.</p>
	 * @return <code>tbsCertificate</code>
	 * @throws CertificateEncodingException lanzada si hay algún problema con la codificación de la información binaria
	 * @see java.security.cert.X509Certificate#getTBSCertificate()
	 */
	@Override
	public byte[] getTBSCertificate() throws CertificateEncodingException {
		return internalCert.getTBSCertificate();
	}

	/**
	 * <p>Devuelve la versión del certificado.</p>
	 * @return versión del certificado
	 * @see java.security.cert.X509Certificate#getVersion()
	 */
	@Override
	public int getVersion() {
		return internalCert.getVersion();
	}

	/**
	 * <p>Devuelve el certificado en binario.</p>
	 * @return certificado en binario
	 * @throws CertificateEncodingException lanzada si hay algún poroblema con la codificación del certificado
	 * @see java.security.cert.Certificate#getEncoded()
	 */
	@Override
	public byte[] getEncoded() throws CertificateEncodingException {
		return internalCert.getEncoded();
	}

	/**
	 * <p>Devuelve la clave pública del certificado.</p>
	 * @return clave pública
	 * @see java.security.cert.Certificate#getPublicKey()
	 */
	@Override
	public PublicKey getPublicKey() {
		return internalCert.getPublicKey();
	}

	/**
	 * <p>Devuelve una representación textual del certificado.</p>
	 * @return cadena descriptiva del certificado
	 * @see java.security.cert.Certificate#toString()
	 */
	@Override
	public String toString() {
		return internalCert.toString();
	}

	/**
	 * <p>Verifica que el certificado ha sido firmado por la clave pública indicada.</p>
	 * @param key Clave pública que supuestamente firma el certificado
	 * @throws CertificateException lanzada si hay problemas con la codificación del certificado
	 * @throws NoSuchAlgorithmException lanzada si el proveedor no tiene el algoritmo con el que se ha firmado el certificado
	 * @throws InvalidKeyException lanzada si la clave pública no es válida
	 * @throws NoSuchProviderException lanzada si el proveedor indicado no existe
	 * @throws SignatureException lanzada si hay errores en la firma
	 * @see java.security.cert.Certificate#verify(java.security.PublicKey)
	 */
	@Override
	public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
		internalCert.verify(key);
	}

	/**
	 * <p>Verifica que el certificado ha sido firmado por la clave pública indicada.</p>
	 * @param key Clave pública que supuestamente firma el certificado
	 * @param sigProvider proveedor de los algoritmos de firma
	 * @throws CertificateException lanzada si hay problemas con la codificación del certificado
	 * @throws NoSuchAlgorithmException lanzada si el proveedor no tiene el algoritmo con el que se ha firmado el certificado
	 * @throws InvalidKeyException lanzada si la clave pública no es válida
	 * @throws NoSuchProviderException lanzada si el proveedor indicado no existe
	 * @throws SignatureException lanzada si hay errores en la firma
	 * @see java.security.cert.Certificate#verify(java.security.PublicKey, java.lang.String)
	 */
	@Override
	public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
		internalCert.verify(key, sigProvider);
	}

	/**
	 * <p>Devuelve los OIDs de las extensiones críticas del certificado.</p>
	 * <p>Los OIDs se devuelve en su representación de cadena.</p>
	 * @return conjunto de cadenas que identifican los OIDs
	 * @see java.security.cert.X509Extension#getCriticalExtensionOIDs()
	 */
	public Set<String> getCriticalExtensionOIDs() {
		return internalCert.getCriticalExtensionOIDs();
	}

	/**
	 * <p>Devuelve el valor de la extensión indicada.</p>
	 * <p>La extensión se identifica a través de la representación en cadena de su OID.</p>
	 * @param oid OID que identifica la extensión
	 * @return contenido binario de la extensión, <code>null</code> si no está presente
	 * @see java.security.cert.X509Extension#getExtensionValue(java.lang.String)
	 */
	public byte[] getExtensionValue(String oid) {
		return internalCert.getExtensionValue(oid);
	}

	/**
	 * <p>Devuelve un conjunto con los OIDs de las extensiones no críticas del certificado.</p>
	 * <p>Los OIDs se devuelven como cadenas.</p>
	 * @return cojunto de cadenas que idientifican los OIDs
	 * @see java.security.cert.X509Extension#getNonCriticalExtensionOIDs()
	 */
	public Set<String> getNonCriticalExtensionOIDs() {
		return internalCert.getNonCriticalExtensionOIDs();
	}

	/**
	 * <p>Indica si el certificado tiene extensiones críticas no soportadas.</p>
	 * @return <code>true</code> si el certificado tiene extensiones críticas no soportadas
	 * @see java.security.cert.X509Extension#hasUnsupportedCriticalExtension()
	 */
	public boolean hasUnsupportedCriticalExtension() {
		return internalCert.hasUnsupportedCriticalExtension();
	}
	
	/**
	 * <p>Devuelve el provider asociado con este certificado.</p> 
	 * @return provider
	 */
	public Provider getProvider() {
		return provider;
	}
	
	/**
	 * <p>Devuelve el certificado interno.</p>
	 * @return certificado interno
	 */
	public X509Certificate getInternalCertificate() {
		return internalCert;
	}
	
	/**
	 * <p>Devuelve un número único que identifique este certificado.</p>
	 * @return entero identificador del certificado
	 * @see java.security.cert.Certificate#hashCode()
	 */
	@Override
	public int hashCode() {
		return internalCert.hashCode();
	}
	
	/**
	 * <p>Compara este certificado con otro.</p>
	 * @param other el otro objeto con el que se compara
	 * @return <code>true</code> si los dos objetos representan al mismo certificado, <code>false</code> en cualquier otro caso
	 * @see java.security.cert.Certificate#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object other) {
		return internalCert.equals(other);
	}
	
}
