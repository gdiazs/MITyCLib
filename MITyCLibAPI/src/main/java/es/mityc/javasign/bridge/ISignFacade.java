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
package es.mityc.javasign.bridge;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.w3c.dom.Document;

/**
 *  <p>Fachada de servicios relacionados con firma electrónica que ha de implementar el sistema de firma electrónica utilizado.</p>
 *  
 *  <p>Estos servicios son:
 *  <ul>
 *    <li>Acceso a almacén de certificados</li>
 *    <li>Validación de certificado</li>
 *    <li>Firma electrónica</li>
 *    <li>Validación de firma electrónica</li>
 *  </ul>
 *  
 *  <p>La clase que implemente el interfaz deberá tener disponible un constructor sin parámetros para ser instanciado por la factoría.</p>
 *  
 */
public interface ISignFacade {
	
	/**
	 * <p>Inicializa el facade con propiedades de comportamiento que pueden ser requeridas para su correcto funcionamiento.</p>
	 * 
	 * @param props Conjunto de propiedades necesarias para que el facade puede inicializarse
	 * @throws ConfigurationException lanzada cuando falta algún parámetro de configuración necesario para el facade
	 */
	void init(Properties props) throws ConfigurationException;
	
	/**
	 * <p>Establece el almacén de certificados a utilizar. Por ejemplo:
	 *      - STORE_EXPLORER()
	 *      - STORE_MOZILLA(Path2Profile)
	 *      - STORE_MACOSX()
	 *      - STORE_MITYC(StreamConf)
	 *      - STORE_CLASS_NAME(ClassName)
	 * </p>
	 *      
	 * @param store .- Nombre del CSP
	 * @param extraProperty.- Propiedad extra para el almacén seleccionado
	 * @throws ConfigurationException lanzada cuando falta algún parámetro de configuración necesario para el facade
	 */
	public void setStoreManager(String store, String extraProperty) throws ConfigurationException;
	
	/**
	 * <p>Consigue la lista de certificados para firmar disponibles en el almacén de certificados.</p>
	 * 
	 * @return Lista de certificados obtenida
	 */
	List<X509Certificate> getSignCertificates();
	
	/**
	 * <p>Comprueba la validez del certificado indicado.</p>
	 * 
	 * @param cert Certificado a validar
	 * @throws InvalidCertificateException lanzada cuando el certificado es invalido, desconocido o se ha tenido alguna dificultad en
	 * 	la validación 
	 */
	void validateCert(X509Certificate cert) throws InvalidCertificateException;
	
	/**
	 * <p>Comprueba la validez de la cadena de certificados indicada.</p>
	 * 
	 * @param cert Certificado a validar
	 * @throws InvalidCertificateException lanzada cuando la cadena es no valida, desconocida o se ha tenido alguna dificultad en
	 * 	la validación 
	 */
	void validateCertChain(X509Certificate cert) throws InvalidCertificateException;
	
	/**
	 * <p>Firma el documento XML indicado utilizando el certificado.</p>
	 * 
	 * @param cert Certificado con el que realizar la firma
	 * @param doc documento con el que realizar la firma
	 * @return devuelve el documento con la firma incluida
	 * @throws SigningException lanzada cuando se produce un error al intentar realizar la firma.
	 */
	Document sign(X509Certificate cert, Document doc) throws SigningException;
	
	/**
	 * <p>Valida una firma XML.</p>
	 * 
	 * @param doc Documento XML con la firma a validar
	 * @return Lista de mapas con un conjunto de información sobre la/s firma/s
	 * @throws InvalidSignatureException lanzada cuando la firma es inválida
	 */
	List<Map<String, Object>> validate(Document doc) throws InvalidSignatureException;

}
