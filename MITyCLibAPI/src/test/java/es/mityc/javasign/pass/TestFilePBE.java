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
package es.mityc.javasign.pass;

import java.io.File;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import es.mityc.javasign.i18n.I18nDefaultManager;
import es.mityc.javasign.i18n.I18nTestFactory;

/**
 * <p>Comprueba el funcionamiento del protector de contraseñas PBE.</p>
 * 
 */
public class TestFilePBE {
	
	/** Contraseña de testeo. */
	private static final String TEST_PASS = "testpass";
	/** Ruta del fichero de pruebas de configuración. */
	private static final String FILE_TEST_CONF = "./testPBEFile.properties";
	
	/**
	 * <p>Comprueba que el fichero de pruebas no exista.</p>
	 */
	@Before
	public void deleteFile() {
		File file = new File(FILE_TEST_CONF);
		if (file.exists()) {
			file.delete();
		}
	}
	
	/**
	 * <p>Comprueba el manager de ofuscación por PBE simple.</p>
	 */
	@Test
	public void testPBEFile() {
		I18nTestFactory.setManager(I18nDefaultManager.class);
		Properties props = new Properties();
		File file = new File(FILE_TEST_CONF);
		props.setProperty("filePBE.URI", file.toURI().toString());
		try {
			IPassSecurity manager = new PBEFileSecurity(props);
			String res = manager.protect(TEST_PASS);
			Assert.assertNotSame("La contraseña no se ha protegido correctamente", TEST_PASS, res);
			res = manager.recover(res);
			Assert.assertEquals("La contraseña no se ha protegido correctamente", TEST_PASS, res);
		} catch (PassSecurityException ex) {
			Assert.fail("Error protegiendo contraseña: " + ex.getMessage());
		}
	}

}
