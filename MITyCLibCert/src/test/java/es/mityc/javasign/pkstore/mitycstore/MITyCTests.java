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
/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package es.mityc.javasign.pkstore.mitycstore;

import org.junit.BeforeClass;

import es.mityc.javasign.pkstore.StoreTests;

/**
 * <p>Tests de funcionamiento general del almacén genérico del MITyC.</p>
 * 
 * 
 * TODO: indicar todos los tests de funcionalidad
 */
public class MITyCTests extends StoreTests {
	
	/**
	 * <p>Elimina los ficheros que hayan podido quedar residuales de otros tests.</p>
	 */
	@BeforeClass
	public void cleanDir() {
		// TODO: si no existe una carpeta en el directorio temporal, la crea
		// TODO: si existe la carpeta, la vacía de ficheros.
	}
	
	/**
	 * <p>Comprueba que se genera un almacén vacío cuando se requiere uno no existente.</p>
	 */
	public void testCreateMITyCStore() {
		// TODO: Llamar al almacén en modo autocreación
	}

}
