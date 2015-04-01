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
package es.mityc.javasign.i18n;

import org.junit.Test;
import static org.junit.Assert.fail;

/**
 * <p>Test de pruebas del manager de internacionalización de tipo addendum.</p>
 * 
 */
public class TestAddendum {
	
	/** Nombre del fichero de internacionalización. */
	private static final String I18N_TEST_FILE = "TestAddendum";
	/** Clave 1 del fichero de internacionalización. */
	private static final String I18N_TEST_KEY_1 = "i18n.test.addendum.1";
	/** Clave 1 del fichero de internacionalización. */
	private static final String I18N_TEST_KEY_2 = "i18n.test.addendum.2";
	/** Valor de la clave 1 del fichero de internacionalización. */
	private static final String I18N_TEST_VALUE_1 = "Test A";
	/** Valor de la clave 1 del fichero de internacionalización. */
	private static final String I18N_TEST_VALUE_2 = "Test C";
	
	/**
	 * <p>Comprueba que addendum apila correctamente las entradas.</p>
	 */
	@Test
	public void testAddendum() {
		I18nTestFactory.setManager(I18nAddendumManager.class);
		II18nManager i18n = I18nFactory.getI18nManager(I18N_TEST_FILE);
		if (!I18N_TEST_VALUE_1.equals(i18n.getLocalMessage(I18N_TEST_KEY_1))) {
			fail("Valor de la clave 1 no coincide con el fichero de internacionalización");
		}
		if (!I18N_TEST_VALUE_2.equals(i18n.getLocalMessage(I18N_TEST_KEY_2))) {
			fail("Valor de la clave 2 no coincide con el fichero de addendum");
		}
	}

}
