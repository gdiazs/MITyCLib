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
package es.mityc.javasign.utils;

/**
 * <p>Utilidad para trabajar con cadenas de texto en formato hexadecimal.</p>
 */
public final class HexUtils {
	
	/**
	 * <p>Constructor oculto.</p>
	 */
	private HexUtils() { }
	
	/**
	 * <p>Convierte información binaria en una cadena de texto hexadecimal.</p>
	 * @param data Datos en binario a convertir
	 * @return cadena de texto hexadecimal
	 */
	public static String convert(byte[] data) {
		return hexString(data);
	}
	
	/**
	 * <p>Convierte una cadena de texto hexadecimal en el equivalente de datos binarios.</p>
	 * @param hex cadena de texto hexadecimal
	 * @return datos en binario equivalentes
	 */
	public static byte[] convert(String hex) {
		return fromHexString(hex);
	}
	
	/**
	 * <p>Diccionario de valores hexadecimales de un dígito.</p>
	 */
	private static final char[] NIBBLE = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };

    /**
     * <p>Devuelve la cadena en Hexadecimal.</p>
     * @param buf datos en binario que convertir
     * @param i inicio del buffer de datos en binario desde el que comenzar a convertir la cadena
     * @param longitud cantidad de datos que convertir de la cadena
     * @return cadena de texto hexadecimal equivalente al contenido binario
     */
	private static String hexString(final byte[] buf, final int i, final int longitud) {
    StringBuffer sb = new StringBuffer();
        for (int j = i; j < i + longitud; j++) {
           sb.append(NIBBLE[(buf[j] >>> 4) & 15]);
           sb.append(NIBBLE[ buf[j]        & 15]);
        }
        return String.valueOf(sb);
    }

    /**
     * <p>Devuelve la cadena en hexadecimal.</p>
     * @param buf buffer que convertir
     * @return cadena de texto equivalente
     */
    private static String hexString(final byte[] buf) {
        return hexString(buf, 0, buf.length);
    }

    /**
     * <p>Convierte un caracter de texto hexadecimal a su equivalente binario.</p>
     * @param n caracter a convertir
     * @return dato binario equivalente
     */
    private static byte fromHexNibble(final char n) {
        if (n <= '9') {
            return (byte) (n - '0');
        }
        if (n <= 'G') {
            return (byte) (n - ('A' - 10));
        }
        return (byte) (n - ('a' - 10));
    }

    /**
     * <p>Convierte una cadena de digitos hexadecimales a un array de bytes.</p>
     * @param hex cadena de texto hexadecimal
     * @return datos binarios equivalentes
     */
    private static byte[] fromHexString(final String hex) {
        int l = (hex.length() + 1) >>> 1;
        byte[] r = new byte[l];
        int i = 0;
        int j = 0;
        if ((hex.length() % 2) != 0) {
            // Número impar de caracteres: debe manejar medio byte primero. 
            r[0] = fromHexNibble(hex.charAt(0));
            i = 1; j = 1;
        }
        while (i < l) {
            r[i++] = (byte) ((fromHexNibble(hex.charAt(j++)) << 4) | fromHexNibble(hex.charAt(j++)));
        }
        return r;
    }

}
