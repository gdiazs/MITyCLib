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

import java.io.CharArrayWriter;
import java.io.IOException;

/**
 * <p>Implementa el interfaz {@link IWriter} sobre una cadena de caracteres.</p>
 * 
 */
public class CharWrittable implements IWriter {

	/** Escritor interno de caracteres. */
	private CharArrayWriter caw;
	
	/**
	 * <p>Constructor.</p>
	 */
	public CharWrittable() {
		caw = new CharArrayWriter();
	}
	
	/**
	 * <p>Escribe nuevos datos en el buffer de escritura.</p>
	 * 
	 * @param c array de caracteres a escribir
	 * @param off Offset sobre el array de caracteres
	 * @param len cantidad de bytes a escribir
	 */
	public void write(final char[] c, final int off, final int len) {
		caw.write(c, off, len);
	}
	
	/**
	 * <p>Asegura el contenido del buffer interno.</p>
	 * @throws IOException Lanzada cuando se produce un error al asegurar el buffer interno
	 * @see es.mityc.javasign.io.IWriter#flush()
	 */
	public void flush() throws IOException {
		caw.flush();
	}

	/**
	 * <p>Inicializa el objeto vaciando los buffers internos.</p>
	 * @see es.mityc.javasign.io.IWriter#reset()
	 */
	public void reset() {
		caw.reset();
	}

	/**
	 * <p>Devuelve la cantidad de datos disponibles en el buffer interno.</p>
	 * @return número de bytes disponibles
	 * @see es.mityc.javasign.io.IWriter#size()
	 */
	public int size() {
		return caw.size();
	}

	/**
	 * <p>Devuelve un array con los datos disponibles en el buffer interno.</p>
	 * @return array con los datos disponibles
	 * @see es.mityc.javasign.io.IWriter#toByteArray()
	 */
	public byte[] toByteArray() {
		return caw.toString().getBytes();
	}
}
