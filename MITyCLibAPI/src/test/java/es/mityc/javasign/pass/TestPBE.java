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

import org.junit.Assert;
import org.junit.Test;

import es.mityc.javasign.i18n.I18nDefaultManager;
import es.mityc.javasign.i18n.I18nTestFactory;

/**
 * <p>Comprueba el funcionamiento del protector de contraseñas PBE.</p>
 * 
 */
public class TestPBE {
	
	/** Identificador del manager de ofuscación a testear. */
	private static final String SIMPLEPBE_NAME = "simplePBE";
	/** Contraseña de testeo. */
	private static final String TEST_PASS = "testpass";
	/** Contraseña de testeo protegida. */
	private static final String TEST_PASS_PROTECT = "{4fefdcad8601a0f8518b20d9e74b13f6}";
	
	/**
	 * <p>Comprueba el manager de ofuscación por PBE simple.</p>
	 */
	@Test
	public void testPBE() {
		I18nTestFactory.setManager(I18nDefaultManager.class);
		IPassSecurity manager = PassSecurityFactory.getInstance().getPassSecurityManager(SIMPLEPBE_NAME, false);
		Assert.assertNotNull("No se ha encontrado el manager " + SIMPLEPBE_NAME, manager);
		String res = null;
		try {
			res = manager.protect(TEST_PASS);
		} catch (PassSecurityException ex) {
			Assert.fail("Error protegiendo contraseña: " + ex.getMessage());
		}
		Assert.assertEquals("", TEST_PASS_PROTECT, res);
		try {
			res = manager.recover(TEST_PASS_PROTECT);
		} catch (PassSecurityException ex) {
			Assert.fail("Error desprotegiendo contraseña: " + ex.getMessage());
		}
		Assert.assertEquals("", TEST_PASS, res);
	}

}
