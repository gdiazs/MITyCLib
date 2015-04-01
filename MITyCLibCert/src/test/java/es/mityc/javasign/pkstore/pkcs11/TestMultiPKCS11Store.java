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

import static org.junit.Assert.fail;

import java.security.NoSuchProviderException;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import java.security.cert.X509Certificate;

import org.junit.BeforeClass;

import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KeyStoreTests;

/**
 * <p>Tests de funcionamiento de las operaciones sobre múltiples smartcards/tokens.</p>
 * <p>El fichero de propiedades debe estar en la raíz de los recursos con el nombre <code>testP11.properties</code>. El fichero
 * deber incluir las propiedades:
 * <pre>
 * # nombre y ruta del módulo PKCS#11 a testear
 * test.p11.module.#.name=
 * test.p11.module.#.lib=
 * </pre>
 * Deberá haber tantas entradas pares como módulos a testear
 * </p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class TestMultiPKCS11Store extends KeyStoreTests {
	
	/** Store de acceso al PKCS11. */
	private static IPKStoreManager pkStore = null;
	

	/**
	 * <p>Recupera la configuración de acceso al almacén de Mozilla (ruta del perfil) para estas pruebas.</p>
	 */
	@BeforeClass
	public static void initialize() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle("testP11");
			ConfigMultiPKCS11 config = new ConfigMultiPKCS11();
			String lib = rb.getString("test.p11.fnmt");
			config.addSunProvider("FNMT", lib);
			lib = rb.getString("test.p11.dnie");
			config.addSunProvider("DNIe", lib);
			pkStore = new MultiPKCS11Store(config, new DefaultPassStoreP11());
			List <X509Certificate> lCertificates= pkStore.getSignCertificates();
			if ( lCertificates != null ) {
				for ( int i=0; i < lCertificates.size();i++){
					X509Certificate cert = lCertificates.get(i);
					System.out.println("DN del certificado: "+cert.getSubjectDN());
				}
			}	
			lCertificates= pkStore.getTrustCertificates();
			if ( lCertificates != null ) {
				for ( int i=0; i < lCertificates.size();i++){
					X509Certificate cert = lCertificates.get(i);
					System.out.println("DN del certificado trusted: "+cert.getSubjectDN());
				}
			}	
		}catch ( CertStoreException ex ) {
			fail("No se puede acceder al almacén de certificados. Recuerde crear y configurar el fichero testP11.properties");
		}
		catch (MissingResourceException ex) {
			fail("No se encuentra disponible la configuración específica para este test. Recuerde crear y configurar el fichero testP11.properties");
		} catch (NoSuchProviderException ex) {
			fail("No se encuentra disponible el módulo de Sun para PKCS#11: " + ex.getMessage());
		}
	}

	/**
	 * <p>Crea el acceso al almacén a través del objeto a testear.</p>
	 * @return Almacén del DNIe
	 * @see es.mityc.javasign.pkstore.keystore.KeyStoreTests#getStore()
	 */
	@Override
	public IPKStoreManager getStore() {
		return pkStore;
	}


}
