/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES".
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
package es.mityc.firmaJava.libreria.utilidades;

/**
 * Convierte Array de bytes a Hexadecimal
 *
 */

public class ByteArrayAHex
{
	
	
	final private static char[] NIBBLE = {
                                      '0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
                                  };

    /**
     * Devuelve la cadena en Hexadecimal
     * @param buf 
     * @param i 
     * @param longitud 
     * @return 
     */
	public static final String hexString(byte[] buf, int i, int longitud)
    {
    StringBuffer sb = new StringBuffer();
        for (int j=i; j<i+longitud ; j++) {
           sb.append(NIBBLE[(buf[j]>>>4)&15]);
           sb.append(NIBBLE[ buf[j]     &15]);
        }
        return String.valueOf(sb);
    }

    /**
     * Devuelve la cadena en hexadecimal
     * @param buf 
     * @return 
     */
    public static final String hexString(byte[] buf)
    {
        return hexString(buf, 0, buf.length);
    }

    /**
     * 
     * @param n 
     * @return 
     */
     public static byte fromHexNibble(char n)
    {
        if(n<='9')
            return (byte)(n-'0');
        if(n<='G')
            return (byte)(n-('A'-10));
        return (byte)(n-('a'-10));
    }

    /**
     * Convierte una cadena de digitos hexadecimales a un array de bytes
     * @param hex
     */
    public static byte[] fromHexString(String hex)
    {
        int l=(hex.length()+1) >>> 1;
        byte[] r = new byte[l];
        int i = 0;
        int j = 0;
        if(hex.length()%2 != 0) {
            // Número impar de caracteres: debe manejar medio byte primero. 
            r[0]=fromHexNibble(hex.charAt(0));
            i=j=1;
        }
        while(i<l)
            r[i++] = (byte)((fromHexNibble(hex.charAt(j++)) << 4) | fromHexNibble(hex.charAt(j++)));
        return r;
    }
    
    /**
     * Concatena 2 arrays de bytes
     */
    public static byte[] concatByteArrays(byte[] array1, byte[] array2) {
    	
    	if(array1.length == 0)
    		return array2;
    	else if(array2.length == 0)
    		return array1;
    	else
    	{
    		int logitudFinal = array1.length + array2.length;
    		byte[] arrayCombinado = new byte[logitudFinal];
    		// añadir primer array
    		System.arraycopy(array1,0, arrayCombinado, 0, array1.length);
    		System.arraycopy(array2, 0, arrayCombinado, array1.length, array2.length);
    		
    		return arrayCombinado;
    	}
    }
}