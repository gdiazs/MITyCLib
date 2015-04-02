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
package es.mityc.javasign.issues;

import org.junit.Assert;
import org.junit.Test;

import es.mityc.firmaJava.ValidationBase;

/**
 * <p>Prueba de Issue #295.</p>
 * <p>Campo <code>SigningCertificate</code> mal formado.</p>
 * 
 */
public class Test295 extends ValidationBase {
	
	@Test
	public void test() {
		try {
			if (validateStreamThrowable(loadRes("/issues/295/295.xml"), null, null)) {
				Assert.fail("La firma del test #295 debería ser inválida por malformación del nodo SigningCertificate pero ha dado válida");
			}
		} catch (Throwable th) {
			LOGGER.info(th.getMessage());
			LOGGER.info("", th);
			Assert.fail("Error en test #295: " + th.getMessage());
		}
	}

}
