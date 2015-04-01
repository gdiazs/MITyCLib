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
package es.mityc.javasign.pkstore.keystore;

import java.security.cert.X509Certificate;

import org.junit.Test;
import static org.junit.Assert.fail;

import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.StoreTests;

/**
 * <p>Tests de funcionamiento de las operaciones sobre el almacén de KeyStores.</p>
 * 
 */

public abstract class KeyStoreTests extends StoreTests {
	
	/**
	 * <p>Comprueba que se puede acceder a los certificados contenidos en el almacén.</p>
	 */
	@Test
	public void testGetCertificates() {
		IPKStoreManager sm = getStore();
		X509Certificate cert = getCertificate(sm);
		if (cert == null) {
			fail("No se pudo obtener un certificado del almacén");
		}
	}

	/**
	 * <p>Comprueba la funcionalidad de firma.</p>
	 */
	@Test
	public void sign() {
		IPKStoreManager sm = getStore();
		checkSign(sm);
	}
	
	/**
	 * <p>Sobreescribir este método con la generación específica de KeyStore que se desea testear.</p>
	 * @return Almacén sobre el que se realiza la prueba
	 */
	public abstract IPKStoreManager getStore();
}
