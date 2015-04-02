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
package es.mityc.firmaJava.libreria.xades;

import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

/**
 * Clase encargada de almacenar información referida a los certificados X509Certificate 
 */

public class DatosX509 {
	
	private String algMethod = null;
	private String digestValue = null;
	private BigInteger serial = null;
	private X500Principal issuer = null;
	
	public DatosX509 () {}
	
	/**
	 * @param algMethod Método de cálculo de digest 
	 * @param digestvalue Es el valor de digest del certificado utilizando el algoritmo referido
	 * @param serial Es el número de serie del certificado
	 * @param issuer Es el nombre del emisor del certificado
	 */
	public DatosX509 (String algMethod, String digestValue, BigInteger serial, X500Principal issuer) {		
		this.algMethod = algMethod;
		this.digestValue = digestValue;
		this.serial = serial;
		this.issuer = issuer;
	}

	/**
	 * @return algMethod
	 */
	public String getAlgMethod() {
		return algMethod;
	}

	/**
	 * @param algMethod
	 */
	public void setAlgMethod(String algMethod) {
		this.algMethod = algMethod;
	}

	/**
	 * @return digestValue
	 */
	public String getDigestValue() {
		return digestValue;
	}

	/**
	 * @param digestValue
	 */
	public void setDigestValue(String digestValue) {
		this.digestValue = digestValue;
	}

	/**
	 * @return issuer
	 */
	public X500Principal getIssuer() {
		return issuer;
	}

	/**
	 * @param issuer
	 */
	public void setIssuer(X500Principal issuer) {
		this.issuer = issuer;
	}

	/**
	 * @return serial
	 */
	public BigInteger getSerial() {
		return serial;
	}

	/**
	 * @param serial
	 */
	public void setSerial(BigInteger serial) {
		this.serial = serial;
	}
}
