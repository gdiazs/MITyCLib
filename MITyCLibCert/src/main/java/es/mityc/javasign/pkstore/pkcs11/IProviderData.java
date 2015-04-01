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

import java.security.Provider;

/**
 * <p>Interfaz que ha de implementar un informador de un provider que permite acceso a <u>un dispositivo</u> PKCS#11.</p>
 * <p>A diferencia de {@link IModuleData} este interfaz representa a un único dispositivo de un tipo que podría estar conectado
 * en un momento dado.</p> * 
 */
public interface IProviderData {
	
	/**
	 * <p>Devuelve el provider que permite el acceso al slot.</p>
	 * @return Provider
	 */
	Provider getProvider();
	
	/**
	 * <p>Devuelve el nombre del keystore que administra este provider para acceder al dispositivo PKCS#11.</p>
	 * <p>Este nombre se puede utilizar después en la clase {@link java.security.KeyStore} para acceder al almacén de certificados
	 * disponibles en el módulo PKCS#11 accedido por este provider.</p>
	 * @return  Nombre del tipo de KeyStore
	 */
	String getKeyStoreTypeName();

}
