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
package es.mityc.javasign.pkstore.mozilla;

/**
 * <p>Interfaz que han de implementar los dialogs de petición de PIN para permitir la configuración de los mensajes mostrados.</p>
 *
 */

public interface IPINDialogConfigurable {
	
	/** Tipos de modos de funcionamiento de los mensajes de la ventana.*/
	public enum MESSAGES_MODE { AUTO, AUTO_TOKEN, EXPLICIT };
	
	/**
	 * <p>Establece el titulo de la ventana de petición de PIN.</p>
	 * @param title Título de la ventana
	 */
	void setTitle(String title);
	
	/**
	 * <p>Establece el mensaje de qué tipo de dato de identificación espera.</p>
	 * @param message Mensaje de tipo de contraseña esperada
	 */
	void setPINMessage(String message);
	
	/**
	 * Indica el modo en el que se deben obtener los mensajes de la ventana. Por defecto (o por ausencia de valor) actúa como AUTO.
	 * @param mode	<ul><li>AUTO indica que el dialog buscará sus propios títulos</li> 
	 * 				<li>AUTO_TOKEN indica que utilizará los títulos que le proporcione el token</li>
	 * 				<li>EXPLICIT indica que utilizará los títulos que se le provea a través de los métodos de este interfaz</li></ul>
	 */
	void setMessagesMode(MESSAGES_MODE mode);

}
