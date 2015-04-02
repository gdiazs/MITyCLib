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

import es.mityc.javasign.certificate.ICertStatus;

/**
 * Interfaz que ha de implementar la clase que gestione el almacenamiento de elementos de una firma XAdES externos a la firma (certificados,
 * respuestas OCSP y CRLs) para los casos de firmas con elementos externos (XAdES-C y XAdES-X).
 * 
 */
public interface IStoreElements {
	
	/**
	 * Inicializa el almacenador de elementos indicándole cuál es la URI base de la firma
	 * @param baseURI
	 */
	public void init(String baseURI);

	/**
	 * Indica cuál es el certificado y el status del certificado que hay que almacenar. Se espera de vuelta el nombre que se le ha
	 * asignado a los dos elementos para referenciarlos en la firma XAdES.
	 *  
	 * @param certificate
	 * @param certStatus
	 * @return <ul><li>String[0]: Nombre del elemento certificado</li><li>String[1]: Nombre del elemento estado del certificado</li></ul>
	 */
	public String[] storeCertAndStatus(X509Certificate certificate, ICertStatus certStatus);
	
}
