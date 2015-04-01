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
package es.mityc.crypto.test;

import org.junit.Before;
import org.junit.Test;

import es.mityc.crypto.Utils;
import es.mityc.crypto.symetric.TripleDESManager;

/**
 * <p>Tests de encriptación y generación de claves bajo el algoritmo TripleDES.</p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class TripleDESTest {

	/**
	 * <p>Recupera la configuración para realizar el Test.</p>
	 */
	@Before 
	public void initialize() {
		
	}

	/**
	 * <p>Lanza el Test a realizar.</p>
	 */
	@Test
	public void launchTest() {
		String claro = "TextoEnClaro 1234567890";
		String pass = "1234567890123456789012345678901234567890";
		TripleDESManager p = new TripleDESManager();
		System.out.println("Texto en claro: " + claro);
		String buffer = Utils.obfuscate(claro);
		System.out.println("Texto ofuscado: " + buffer);
		buffer = Utils.undoObfuscate(buffer.getBytes());
		System.out.println("Texto recuperado: " + buffer);

		char[] bufferChar = p.protectTripleDES(buffer, pass);
		buffer = new String(bufferChar);
		System.out.println("Texto encriptado triple DES: " + buffer);
		buffer = new String(p.recoverTripleDES(bufferChar, pass));
		System.out.println("Texto desencriptado triple DES: " + buffer);

		long start = System.currentTimeMillis();
		buffer = Utils.obfuscate(new String(p.protectTripleDES(buffer, pass)));
		System.out.println("Encriptado y ofuscado triple DES: " + buffer);
		buffer = new String(p.recoverTripleDES(Utils.undoObfuscate(buffer.getBytes()).toCharArray(), pass));
		long time = System.currentTimeMillis() - start;
		System.out.println("Texto recuperado: " + buffer + "\nTiempo consumido (ms): " + time);
	}
}
