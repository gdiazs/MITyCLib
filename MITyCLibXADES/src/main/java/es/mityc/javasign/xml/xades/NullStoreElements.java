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
package es.mityc.javasign.xml.xades;

import java.security.cert.X509Certificate;
import java.util.Map;

import es.mityc.javasign.certificate.ElementNotFoundException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.IRecoverElements;
import es.mityc.javasign.certificate.UnknownElementClassException;

/**
 * Con esta clase se indica que no se debe intentar recuperar ni guardar ninguno de los elementos relacionados con los certificados de
 * una firma.
 * 
 */
public class NullStoreElements implements IStoreElements, IRecoverElements {
	
	public static final NullStoreElements instance = new NullStoreElements(); 

	/**
	 * 
	 */
	public NullStoreElements() {
	}

	/**
	 * @see es.mityc.javasign.xml.xades.IStoreElements#init(java.lang.String)
	 */
	public void init(String baseURI) {
	}

	/**
	 * @see es.mityc.javasign.xml.xades.IStoreElements#storeCertAndStatus(java.security.cert.X509Certificate, es.mityc.firmaJava.certificates.status.ICertStatusElement)
	 */
	public String[] storeCertAndStatus(X509Certificate certificate, ICertStatus certStatus) {
		return new String[0];
	}

	/**
	 * @see es.mityc.javasign.certificate.IRecoverElements#getElement(java.util.Map, java.lang.Class)
	 */
	public <T> T getElement(Map<String, Object> props, Class<T> elementClass) throws ElementNotFoundException, UnknownElementClassException {
		return null; 
	}

}
