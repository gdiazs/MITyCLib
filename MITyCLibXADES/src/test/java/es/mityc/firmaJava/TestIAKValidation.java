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
package es.mityc.firmaJava;

import static org.junit.Assert.assertTrue;
import junit.framework.JUnit4TestAdapter;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.Test;

public class TestIAKValidation extends ValidationBase {
	@Ignore
	@Test public void validaIAIKBesValid() {
		assertTrue("Firma de IAIK, XAdES-BES no validada", validateStream(loadRes("/IAIK/BES.xml"), getBaseUri("/IAIK/"), null));
	}
	
	@Test public void validaIAIKCValid() {
		assertTrue("Firma de IAIK, XAdES-C no validada", validateStream(loadRes("/IAIK/XAdES-C-OCSP.xml"), getBaseUri("/IAIK/"), null));
	}

	@Test public void validaIAIKXValid() {
		assertTrue("Firma de IAIK, XAdES-X no validada", validateStream(loadRes("/IAIK/XAdES-X-OCSP-2.xml"), getBaseUri("/IAIK/"), null));
	}

	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(TestIAKValidation.class);
	}

}
