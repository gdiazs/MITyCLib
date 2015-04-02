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
package es.mityc.javasign.ts;

import static org.junit.Assert.fail;

import java.net.Authenticator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.junit.Before;
import org.junit.Test;

import es.mityc.javasign.tsa.ITimeStampValidator;
import es.mityc.javasign.tsa.TimeStampException;
import es.mityc.javasign.utils.SimpleAuthenticator;

/**
 * <p>Tests de de peticiones de sellos de tiempo a TSA vía http.</p>
 * <p>Requisitos:<ul>
 * 	<li>El fichero de propiedades debe estar en la raíz de los recursos con el nombre <code>testTSA.properties</code>. El fichero
 * deber incluir la propiedad:
 * <pre>
 * # Ruta donde se encuentra la TSA que se utilizará para los tests
 * test.tsa.url=
 * </pre></li></ul>
 * </p>
 * 
 */
public class TestTSA {
	
	/** Ruta de la TSA de pruebas. */
	private String urlTSA = "";
	
	/**
	 * <p>Recupera la configuración de acceso a la TSA para estas pruebas.</p>
	 */
	@Before 
	public void initialize() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle("testTSA");
			urlTSA = rb.getString("test.tsa.url");
		} catch (MissingResourceException ex) {
			fail("No se encuentra disponible la configuración específica para este test. Recuerde crear y configurar el fichero testTSA.properties");
		}
	}
	
	private void prepareProxy() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle("testTSA");
			String proxy = rb.getString("test.http.proxy.need");
			if (Boolean.parseBoolean(proxy)) {
				System.setProperty("http.proxyHost", rb.getString("test.http.proxy.host"));
				System.setProperty("http.proxyPort", rb.getString("test.http.proxy.port"));
				System.setProperty("https.proxyHost", rb.getString("test.http.proxy.host"));
				System.setProperty("https.proxyPort", rb.getString("test.http.proxy.port"));
				if (Boolean.parseBoolean(rb.getString("test.http.proxy.authenticated"))) {
					Authenticator.setDefault(new SimpleAuthenticator(rb.getString("test.http.proxy.user"), 
							rb.getString("test.http.proxy.pass")));
				}
			}
		} catch (MissingResourceException ex) {
			fail("No se encuentra disponible algún parámetro de configuración de proxy. Recuerde crear y configurar el fichero testTSA.properties");
		}
	}
	
	@Test
	public void testTSA() {
		prepareProxy();
		HTTPTimeStampGenerator client = new HTTPTimeStampGenerator(urlTSA, TSPAlgoritmos.SHA1);
		byte result[] = null;
		byte data[] = new byte[1024];
		try {
			result = client.generateTimeStamp(data);
		} catch (TimeStampException ex) {
			fail("Error obteniendo sello de tiempo de " + urlTSA + ": " + ex.getMessage());
		}
		try {
			// TODO: comprobar en el test la identidad del firmante del sello de tiempo
			ITimeStampValidator tsValidator = new TimeStampValidator();
			tsValidator.validateTimeStamp(data, result);
		} catch (TimeStampException ex) {
			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
		}
	}
}
