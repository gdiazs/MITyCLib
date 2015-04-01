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

import java.util.List;

/**
 * <p>Interfaz que ha cumplir un módulo que permite acceso a un <u>tipo</u> de dispositivo.</p>
 * <p>A diferencia de {@link IProviderData} este interfaz representa todos los posibles dispositivos de un tipo específico que
 * pueden estar conectados.</p>
 */
public interface IModuleData {

	/**
	 * <p>Devuelve un listado de todos los providers que representan a todos los dispositivos PKCS#11 de este tipo que
	 * pueden estar conectados al sistema (potencialmente).</p>
	 * @return listado de proveedores
	 */
	List<IProviderData> getProvidersData();
	
	/**
	 * <p>Realiza una petición al módulo para que se actualice a requerimiento.</p>
	 * <p>Se llama a este procedemiento generalmente antes de hacer un acceso a los dispositivos PKCS#11 gestionados por este módulo
	 * para tener una lista lo más actualizada posible de los dispositivos reales conectados.</p>
	 */
	void updateModule();
	
	/**
	 * <p>Devuelve un nombre descriptivo del módulo.</p>
	 * @return nombre del módulo
	 */
	String getName();

}
