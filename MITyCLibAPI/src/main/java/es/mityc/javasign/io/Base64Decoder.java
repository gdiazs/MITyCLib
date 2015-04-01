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
package es.mityc.javasign.io;

/**
 * <p>Decodificador de tramas base64 basado en la clase <code>java.utils.prefs.Base64</code>.</p>
 * 
 * <p>Implementa la interfaz {@link IDecoder} para permitir su uso en <i>streams</i> de entrada, pudiendo decodificar al vuelo en pequeños
 * bloques de lectura.</p>
 * 
 * <p>Hay que tener en cuenta que base64 se dispone en bloques de 4 elementos. Debido a que el bloque obtenido para decodificar puede no
 * ajustarse a ese tamaño, el decodificador mantiene un pequeño buffer para los elementos que quedan fuera del bloque. Una vez finalizada
 * la lectura y decodificación se aconseja comprobar mediante el método {@link #isIncomplete()} la existencia de datos que no
 * se han podido decodificar (es decir, que la trama base64 no finalizaba correctamente).</p>
 * 
 * 
 * @see es.mityc.javasign.io.IDecoder
 */
public class Base64Decoder implements IDecoder {
	/** Longitud de un bloque de datos en base 64.*/
	private static final int BASE64_CHUNK_LENGTH = 4;
	/** Longitud de un bloque de datos en base64 decodificado.*/
	private static final int BASE64_CHUNK_DECODED_LENGTH = 3;
	
	/** Buffer de lectura. */
	private byte[] buffer;
	/** Buffer para almacenar las tramas de base64 no completadas en la lectura de un chunk. */
	private byte[] remaining;
	/** Flag para el indicador de funcionar sólo en modo de cuenta. */
	private boolean countMode;
	/** Contador de número de bytes procesados. */
	private long count = 0;

	/**
	 * <p>Constructor.</p>
	 */
	public Base64Decoder() { 
		this(false);
	}
	
	/**
	 * <p>Constructor.</p>
	 * @param onlyCountMode Indica si se debe iniciar el decoder sólo contando bytes sin decodificar
	 */
	public Base64Decoder(final boolean onlyCountMode) {
		this.countMode = onlyCountMode;
	}
	
	/**
	 * <p>Resetea el contador de bytes.</p>
	 */
	public void reset() {
		count = 0;
	}
	
	/**
	 * <p>Devuelve la cantidad de bytes que se han obtenido en binario desde el último reseteo.</p>
	 * @return cantidad de bytes contados
	 */
	public long getCount() {
		return count;
	}

	/**
	 * <p>Añade el buffer indicado al ya existente.</p>
	 * @param data array con los nuevos datos
	 * @param pos posición del array desde la que se incluyen los datos
	 * @param len cantidad de bytes que hay que añadir
	 * @see es.mityc.javasign.io.IDecoder#addInput(byte[], int, int)
	 */
	public void addInput(final byte[] data, final int pos, final int len) {
		int totalLen = len + ((buffer != null) ? buffer.length : 0) + ((remaining != null) ? remaining.length : 0);
		byte[] temp = new byte[totalLen];
		int off = 0;
		if (remaining != null) {
			System.arraycopy(remaining, 0, temp, 0, remaining.length);
			off += remaining.length;
		}
		if (buffer != null) {
			System.arraycopy(buffer, 0, temp, off, buffer.length);
			off += buffer.length;
		}
		System.arraycopy(data, pos, temp, off, len);
		buffer = temp;
		remaining = null;
	}

	/**
	 * <p>Pasa de Base64 a binario los datos disponibles en el buffer.</p>
	 * <p>Lanzará una excepción {@link ArrayIndexOutOfBoundsException} si los datos de acceso al buffer de escritura son incorrectos.</p>
	 * @param data Array en el que escribir los datos
	 * @param off Posición a partir de la cual escribir
	 * @param len Cantidad de bytes máximo que se puede escribir
	 * @return Cantidad de bytes que se han decodificado
	 * @throws DecodingException Si la cantidad de datos a leer es demasiado 
	 * @see es.mityc.javasign.io.IDecoder#decode(byte[], int, int)
	 */
	public int decode(final byte[] data, final int off, final int len) throws DecodingException {
		if (off < 0 || len < 0 || off > data.length - len) {
		    throw new ArrayIndexOutOfBoundsException();
		}
		if (len < BASE64_CHUNK_DECODED_LENGTH) {
			throw new DecodingException("Buffer too small, minimum size = " + BASE64_CHUNK_DECODED_LENGTH);
		}
		int res = 0;
		if (buffer != null) {
			// Recoge lo que hay en el buffer y elimina caracteres anómalos
			String s = new String(buffer).replace("\r\n", "").replace(" ", "").replace("\n","");
			// Si hay un grupo incompleto lo guarda 
			if ((s.length() % BASE64_CHUNK_LENGTH) != 0) {
				remaining = s.substring(s.length() - (s.length() % BASE64_CHUNK_LENGTH)).getBytes();
				s = s.substring(0, s.length() - (s.length() % BASE64_CHUNK_LENGTH));
			} else {
				remaining = null;
			}
			// Si el array de escritura es demasiado pequeño se asegura de escribir grupos completos
			int len64 = (s.length() * BASE64_CHUNK_DECODED_LENGTH) / BASE64_CHUNK_LENGTH;
			if (s.endsWith("==")) {
				len64 -= 2;
			} else if (s.endsWith("=")) {
				len64--;
			}
			int actualLen = len;
			if (actualLen < len64) {
				actualLen = actualLen - (actualLen % BASE64_CHUNK_DECODED_LENGTH); // Se queda con multiplos de 3
				buffer = s.substring((actualLen * BASE64_CHUNK_LENGTH) / BASE64_CHUNK_DECODED_LENGTH).getBytes();
				s = s.substring(0, ((actualLen * BASE64_CHUNK_LENGTH) / BASE64_CHUNK_DECODED_LENGTH) - 1);
			} else {
				buffer = null;
			}
			if (!countMode) {
				res = base64ToByteArray(s, data, off);
				count += res;
			} else {
				count += (s.length() * BASE64_CHUNK_DECODED_LENGTH) / BASE64_CHUNK_LENGTH;
			}
		}
		return res;
	}
	
	/**
	 * <p>Modified from java.utils.prefs.Base64.</p>
	 * @param s base64 string
	 * @param data binary result
	 * @param off offset to write in data
	 * @return bytes writed in data
	 * @author  Josh Bloch
	 * @version 1.5, 12/19/03
	 * @see     java.util.prefs.Preferences
	 * @since   1.4
	 */
	private static int base64ToByteArray(final String s, byte[] data, final int off) {
        int sLen = s.length();
        int numGroups = sLen / BASE64_CHUNK_LENGTH;
        if (BASE64_CHUNK_LENGTH * numGroups != sLen) {
            throw new IllegalArgumentException("String length must be a multiple of four.");
        }
        int missingBytesInLastGroup = 0;
        int numFullGroups = numGroups;
        if (sLen != 0) {
            if (s.charAt(sLen - 1) == '=') {
                missingBytesInLastGroup++;
                numFullGroups--;
            }
            if (s.charAt(sLen - 2) == '=') {
                missingBytesInLastGroup++;
            }
        }
        // Translate all full groups from base64 to byte array elements
        int inCursor = 0, outCursor = off;
        for (int i = 0; i < numFullGroups; i++) {
            int ch0 = base64toInt(s.charAt(inCursor++), BASE64_TO_INT);
            int ch1 = base64toInt(s.charAt(inCursor++), BASE64_TO_INT);
            int ch2 = base64toInt(s.charAt(inCursor++), BASE64_TO_INT);
            int ch3 = base64toInt(s.charAt(inCursor++), BASE64_TO_INT);
            data[outCursor++] = (byte) ((ch0 << 2) | (ch1 >> 4));
            data[outCursor++] = (byte) ((ch1 << 4) | (ch2 >> 2));
            data[outCursor++] = (byte) ((ch2 << 6) | ch3);
        }

        // Translate partial group, if present
        if (missingBytesInLastGroup != 0) {
            int ch0 = base64toInt(s.charAt(inCursor++), BASE64_TO_INT);
            int ch1 = base64toInt(s.charAt(inCursor++), BASE64_TO_INT);
            data[outCursor++] = (byte) ((ch0 << 2) | (ch1 >> 4));

            if (missingBytesInLastGroup == 1) {
                int ch2 = base64toInt(s.charAt(inCursor++), BASE64_TO_INT);
                data[outCursor++] = (byte) ((ch1 << 4) | (ch2 >> 2));
            }
        }
        // assert inCursor == s.length()-missingBytesInLastGroup;
        // assert outCursor == result.length;
        return (outCursor - off);
    }
	
    /**
     * Translates the specified character, which is assumed to be in the
     * "Base 64 Alphabet" into its equivalent 6-bit positive integer.
     * @param c character
     * @param alphaToInt alphabet
     * @return translated character
     * @throw IllegalArgumentException or ArrayOutOfBoundsException if
     *        c is not in the Base64 Alphabet.
     */
    private static int base64toInt(final char c, final byte[] alphaToInt) {
        int result = alphaToInt[c];
        if (result < 0) {
            throw new IllegalArgumentException("Illegal character " + c);
        }
        return result;
    }

	
    /**
     * This array is a lookup table that translates unicode characters
     * drawn from the "Base64 Alphabet" (as specified in Table 1 of RFC 2045)
     * into their 6-bit positive integer equivalents.  Characters that
     * are not in the Base64 alphabet but fall within the bounds of the
     * array are translated to -1.
     */
    private static final byte[] BASE64_TO_INT = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54,
        55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };


    /**
     * <p>Indica que se ha quedado sin datos en el buffer para seguir decodificando.</p>
	 * @return <code>true</code> si necesita más datos, <code>false</code> en otro caso
     * @see es.mityc.javasign.io.IDecoder#needsInput()
     */
	public boolean needsInput() {
		return (buffer == null);
	}
	
	/**
	 * <p>Indica que han quedado datos en los buffers internos.</p>
	 * @return <code>true</code> si quedan bytes sin haber sido decoficados en el buffer, <code>false</code> en otro caso
	 * @see es.mityc.javasign.io.IDecoder#isIncomplete()
	 */
	public boolean isIncomplete() {
		return ((remaining != null) || (buffer != null));
	}

}
