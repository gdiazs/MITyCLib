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
package es.mityc.crypto.examples;

import java.security.SecureRandom;
import es.mityc.crypto.symetric.TripleDESManager;

public class PBEEncryption extends GenericEncryption {

    /**
     * <p>
     * Contraseña a utilizar
     * </p>
     */
    private final static String PASSWORD = "1234567890";

    /**
	 * @param args
	 */
	public static void main(String[] args) {
		PBEEncryption pbe = new PBEEncryption();
		pbe.execute();
	}
	
	protected char [] encrypt (String dataToEncrypt) {
		TripleDESManager p = new TripleDESManager();

		// Se establece una semilla. Se recomienda introducir ruido.
		p.feedSeed(SecureRandom.getSeed(8));
		
		char[] bufferChar = p.protectTripleDES(dataToEncrypt, PASSWORD);
		return bufferChar;
		
	}
	
	protected String decrypt (char [] encrypted) {
		TripleDESManager p = new TripleDESManager();
		return new String(p.recoverTripleDES(encrypted,PASSWORD));
	}

}
