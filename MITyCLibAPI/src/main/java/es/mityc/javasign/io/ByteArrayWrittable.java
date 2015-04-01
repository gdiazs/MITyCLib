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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * <p>Implementa el interfaz {@link IWriter} sobre un array de bytes.</p>
 * 
 */
public class ByteArrayWrittable implements IWriter {
	
	/** Buffer privado para acceder a un array de bytes. */
	private ByteArrayOutputStream baos;
	
	/**
	 * <p>Constructor.</p>
	 */
	public ByteArrayWrittable() {
		baos = new ByteArrayOutputStream();
	}
	
	/**
	 * <p>Escribe nuevos datos en el buffer de escritura.</p>
	 * 
	 * @param b array de bytes que contiene los datos que hay que escribir
	 * @param off Offset en el array de bytes
	 * @param len Número de bytes a escribir
	 */
	public void write(final byte[] b, final int off, final int len) {
		baos.write(b, off, len);
	}
	
	/**
	 * <p>Asegura que los datos que están en bufferes temporales se guarden.</p>
	 * @throws IOException Lanzada cuando no se han podido asegurar los datos
	 * @see es.mityc.javasign.io.IWriter#flush()
	 */
	public void flush() throws IOException {
		baos.flush();
	}

	/**
	 * <p>Limpia el buffer vaciándolo.</p>
	 * 
	 * @see es.mityc.javasign.io.IWriter#reset()
	 */
	public void reset() {
		baos.reset();
	}

	/**
	 * <p>Devuelve el número de bytes disponibles en el buffer.</p>
	 * @return número de bytes disponibles en el buffer interno
	 * @see es.mityc.javasign.io.IWriter#size()
	 */
	public int size() {
		return baos.size();
	}

	/**
	 * <p>Devuelve en un array de bytes los datos acumulados.</p>
	 * @return array de bytes disponible en el buffer
	 * @see es.mityc.javasign.io.IWriter#toByteArray()
	 */
	public byte[] toByteArray() {
		return baos.toByteArray();
	}
}
