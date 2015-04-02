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

/**
 * Batería de test para comprobar el estado de la validación de los componentes.
 * 
 */
public class TestValidation extends ValidationBase {

	@Test
	@Ignore
	public void validaCli111BesValid() {
		assertTrue("Firma de cliente 1.1.1, XAdES-BES no validada", validateStream(loadRes("/cliente_1_1_1/BES.xml"), null, null));
	}
	
	@Test
	@Ignore
	public void validaCli111TValid() {
		assertTrue("Firma de cliente 1.1.1, XAdES-T no validada", validateStream(loadRes("/cliente_1_1_1/T.xml"), null, null));
	}

	@Test
	@Ignore
	public void validaCli111XLValid() {
		assertTrue("Firma de cliente 1.1.1, XAdES-XL no validada", validateStream(loadRes("/cliente_1_1_1/XL.xml"), null, null));
	}

	@Ignore
	@Test public void validaCli122BesValid() {
		assertTrue("Firma de cliente 1.2.2, XAdES-BES no validada", validateStream(loadRes("/cliente_1_2_2/BES.xml"), null, null));
	}
	
	@Test public void validaCli122TValid() {
		assertTrue("Firma de cliente 1.2.2, XAdES-T no validada", validateStream(loadRes("/cliente_1_2_2/T.xml"), null, null));
	}

	@Ignore
	@Test public void validaCli122XLValid() {
		assertTrue("Firma de cliente 1.2.2, XAdES-XL no validada", validateStream(loadRes("/cliente_1_2_2/XL.xml"), null, null));
	}

	@Ignore
	@Test public void validaCli132BesValid() {
		assertTrue("Firma de cliente 1.3.2, XAdES-BES no validada", validateStream(loadRes("/cliente_1_3_2/BES.xml"), null, null));
	}
	
	@Test public void validaCli132TValid() {
		assertTrue("Firma de cliente 1.3.2, XAdES-T no validada", validateStream(loadRes("/cliente_1_3_2/T.xml"), null, null));
	}

	@Ignore
	@Test public void validaCli132XLValid() {
		assertTrue("Firma de cliente 1.3.2, XAdES-XL no validada", validateStream(loadRes("/cliente_1_3_2/XL.xml"), null, null));
	}

	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(TestValidation.class);
	}


}
