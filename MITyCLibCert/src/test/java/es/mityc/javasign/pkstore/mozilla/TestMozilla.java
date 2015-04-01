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
package es.mityc.javasign.pkstore.mozilla;

import static org.junit.Assert.fail;

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.junit.Before;
import org.junit.Test;

import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.StoreTests;

/**
 * <p>Tests de funcionamiento de las operaciones sobre el almacén de Mozilla.</p>
 * <p>Requisitos:<ul>
 * 	<li>tener cargado el certificado de test Usr0061.p12 en el almacén de certificados windows MY de la máquina donde se lanza el test.</li>
 * 	<li>El fichero de propiedades debe estar en la raíz de los recursos con el nombre <code>testMozilla.properties</code>. El fichero
 * deber incluir la propiedad:
 * <pre>
 * # Ruta donde se encuentra el perfil del mozilla que se utilizará para los tests
 * test.mozilla.profile=
 * </pre></li></ul>
 * </p>
 * 
 */
public class TestMozilla extends StoreTests {
	
	/** Ruta del perfil de usuario del mozilla. */
	private String profile = "";
	
	/**
	 * <p>Recupera la configuración de acceso al almacén de Mozilla (ruta del perfil) para estas pruebas.</p>
	 */
	@Before 
	public void initialize() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle("testMozilla");
			profile = rb.getString("test.mozilla.profile");
		} catch (MissingResourceException ex) {
			fail("No se encuentra disponible la configuración específica para este test. Recuerde crear y configurar el fichero testMozilla.properties");
		}
	}
	
	/**
	 * <p>Comprueba que se puede acceder a los certificados contenidos en el almacén.</p>
	 */
	@Test
	public void testGetCertificates() {
		try {
			IPKStoreManager sm = new MozillaStoreJSS(profile);
			X509Certificate cert = getCertificate(sm);
			if (cert == null) {
				fail("No se pudo obtener un certificado del almacén");
			}
		} catch (Exception e) {
			fail("Error al crear el almacén" + e.getMessage());
		}
	}
	
	/**
	 * <p>Comprueba la funcionalidad de firma.</p>
	 */
	@Test
	public void sign() {
		try {
		IPKStoreManager sm = new MozillaStoreJSS(profile);
		X509Certificate testCert = loadCertificate(this.getClass().getResourceAsStream("/keystores/usr0061.cer"));
		if (testCert == null) {
			fail("El certificado us0032 no está disponible en el almacén. Este test necesita que se importe el certificado en el MY" +
				 " del almacén de windows para poder ejecutarse");
		}
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(testCert);
		checkSign(sm);
		} catch (Exception e) {
			fail("Error al crear el almacén" + e.getMessage());
		}
	}
}
