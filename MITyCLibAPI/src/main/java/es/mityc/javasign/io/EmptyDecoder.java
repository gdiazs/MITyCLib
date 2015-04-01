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

import es.mityc.javasign.io.DecodingException;
import es.mityc.javasign.io.IDecoder;

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
public class EmptyDecoder implements IDecoder {

	/** Buffer de lectura. */
	private byte[] buffer;

	/**
	 * <p>Constructor.</p>
	 */
	public EmptyDecoder() { 
	}
	
	/**
	 * <p>Añade el buffer indicado al ya existente.</p>
	 * @param data array con los nuevos datos
	 * @param pos posición del array desde la que se incluyen los datos
	 * @param len cantidad de bytes que hay que añadir
	 * @see es.mityc.javasign.io.IDecoder#addInput(byte[], int, int)
	 */
	public void addInput(final byte[] data, final int pos, final int len) {
		int totalLen = len + ((buffer != null) ? buffer.length : 0);
		byte[] temp = new byte[totalLen];
		int off = 0;
		if (buffer != null) {
			System.arraycopy(buffer, 0, temp, off, buffer.length);
			off += buffer.length;
		}
		System.arraycopy(data, pos, temp, off, len);
		buffer = temp;
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
		if ((off < 0) || (len < 0) || (off > (data.length - len))) {
		    throw new ArrayIndexOutOfBoundsException();
		}
		int res = 0;
		if (buffer != null) {
			// Si el array de escritura es demasiado pequeño se asegura de escribir grupos completos
			int lenBuffer = buffer.length;

			int actualLen = Math.min(len, lenBuffer);
			System.arraycopy(buffer, 0, data, off, actualLen);
			if (actualLen < lenBuffer) {
				int tempLen = lenBuffer - actualLen;
				byte[] temp = new byte[tempLen];
				System.arraycopy(buffer, actualLen, temp, 0, tempLen);
				buffer = temp;
			} else {
				buffer = null;
			}
			res = actualLen;
		}
		return res;
	}
	


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
		return (buffer != null);
	}

}

