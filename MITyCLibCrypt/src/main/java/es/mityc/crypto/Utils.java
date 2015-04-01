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
package es.mityc.crypto;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class Utils {
	
	/** Sistema de traceo. */
	private static Log logger = LogFactory.getLog(Utils.class);
	
	/**
	 * <p>Metodo para ofuscar información. No admite caracteres fuera del código ASCII.</p>
	 * @param enClaro
	 * @return Texto ofuscado
	 */
	public static String obfuscate (String enClaro) throws SecurityException {
		return obfuscate(enClaro, 0);
	}
	
	/**
	 * <p>Metodo para ofuscar información. No admite caracteres fuera del código ASCII.</p>
	 * @param enClaro
	 * @param pass
	 * @return Texto ofuscado
	 */
	public static String obfuscate (String enClaro, long pass) throws SecurityException {		
		StringBuffer bufer = new StringBuffer(enClaro).reverse();
		byte arr[];
		try {
			arr = (bufer.toString()).getBytes("ASCII");
		} catch (Exception e) {
			arr = (bufer.toString()).getBytes();
		} 
		StringBuffer resultado = new StringBuffer();
		
		pass = (pass/101)%997;
		
		long aumento = bufer.length() * (13 + pass);
		
		for (int x = 0; x < bufer.length(); ++x) {
			int ascii = arr[x];	
			if (ascii < 0) {
				throw new SecurityException("El caracter leído no es de tipo ASCII --> " + arr[x]);
			}
			ascii = (int)((ascii + aumento)%92) + 34;
			if ((32 >= ascii) && (ascii >= 130)) {
				throw new SecurityException("Error al encriptar la posición: " + (bufer.length() - x) + " Letra en claro: " + (char)arr[x]);
			}
			if (61 == ascii) // El = se utiliza como separador de tokens, se debe excluir
				ascii = 33;
			aumento = aumento + ((x+2)*(13 + pass));
			char ascitotext = (char)(ascii);
			resultado.append(ascitotext);
		}
		
		return resultado.toString();
	}
	
	/**
	 * <p>Recupera el texto ofuscado con el método anterior.</p>
	 * @param codigo Texto ofuscado
	 * @return Texto en claro
	 * @throws SecurityException
	 */
	public static String undoObfuscate(byte[] codigo) throws SecurityException {
		return undoObfuscate(codigo, 0);
	}
	
	/**
	 * <p>Recupera el texto ofuscado con el método anterior.</p>
	 * @param codigo Texto ofuscado
	 * @return Texto en claro
	 * @throws SecurityException
	 */
	public static String undoObfuscate(byte[] codigo, long pass) throws SecurityException {		
		StringBuffer resultado = new StringBuffer();
		
		pass = (pass/101)%997;
		
		long decremento = codigo.length * (13 + pass);
		
		for (int x = 0; x < codigo.length; ++x) {
			int ascii = codigo[x];
			if (33 == ascii)
				ascii = 61;
			int ret = 0;
			ascii = ((ascii - 34));

			for(int y = 31; y < 200 && (ascii != ((y + decremento)%92)) ; ++y)
				ret = y + 1;
			
			decremento = decremento + ((x+2)*(13 + pass));
			if (ret >= 128) {
				throw new SecurityException("El caracter leído no es de tipo ASCII --> " + ret);
			}
			char ascitotext = (char)(ret);
			resultado.append(ascitotext);
		}
		resultado.reverse();
		return resultado.toString();
	}
}
   