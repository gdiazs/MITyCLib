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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import static org.junit.Assert.fail;

import es.mityc.javasign.pkstore.IPKStoreManager;

/**
 * <p>Tests sobre acceso a almacenes JCEKS.</p>
 * 
 */
public class TestJCEKSStore extends KeyStoreTests {

	/**
	 * <p>Accede a un almacén JCEKS de pruebas.</p>
	 * @return Almacén JCEKS de pruebas
	 * @see es.mityc.javasign.pkstore.keystore.KeyStoreTests#getStore()
	 */
	@Override
	public IPKStoreManager getStore() {
		IPKStoreManager pks = null;
		try {
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(this.getClass().getResourceAsStream("/keystores/usr0031.jce"), "usr0031".toCharArray());
			Provider provider = Security.getProvider("SunRsaSign");
			pks = new KSStore(ks, provider, new PassStoreKS("usr0031"));
		} catch (KeyStoreException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		} catch (CertificateException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		} catch (IOException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		}
		return pks;
	}

}
