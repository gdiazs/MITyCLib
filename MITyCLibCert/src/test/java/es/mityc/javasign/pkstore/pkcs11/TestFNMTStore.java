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
package es.mityc.javasign.pkstore.pkcs11;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.junit.Before;
import static org.junit.Assert.fail;

import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KeyStoreTests;

/**
 * <p>Tests de funcionamiento de las operaciones sobre el una tarjeta FNMT.</p>
 * <p>El fichero de propiedades debe estar en la raíz de los recursos con el nombre <code>testP11.properties</code>. El fichero
 * deber incluir la propiedad:
 * <pre>
 * # Ruta del módulo PKCS#11 de FNMT
 * test.p11.fnmt=
 * </pre>
 * </p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class TestFNMTStore extends KeyStoreTests {
	
	/** Ruta de la librería pkcs#11. */
	private String libP11 = "";
	
	/**
	 * <p>Recupera la configuración de acceso al almacén de Mozilla (ruta del perfil) para estas pruebas.</p>
	 */
	@Before 
	public void initialize() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle("testP11");
			libP11 = rb.getString("test.p11.fnmt");
		} catch (MissingResourceException ex) {
			fail("No se encuentra disponible la configuración específica para este test. Recuerde crear y configurar el fichero testP11.properties");
		}
	}


	/**
	 * <p>Crea el acceso al almacén a través del objeto a testear.</p>
	 * @return Almacén de la FNMT
	 * @see es.mityc.javasign.pkstore.keystore.KeyStoreTests#getStore()
	 */
	@Override
	public IPKStoreManager getStore() {
		return new PKCS11Store(libP11, new HandlerPassPKCS11Store("Acceso a FNMT"));
	}

}
