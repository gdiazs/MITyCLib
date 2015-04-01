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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * <p>Implementa un {@link InputStream} equivalente a {@link ByteArrayInputStream} pero que permite escribir en el array del que se alimenta
 * durante su uso.</p> 
 * 
 * <p>Permite asociar un escritor general para ir llenando el array interno. El escritor general ha de implementar el interfaz 
 * {@link IWriter}.</p>
 * 
 */
public class ByteArrayWrittableInputStream extends InputStream {
	
	/** Buffer interno de lectura. */
	private ByteArrayInputStream bais = null;
	/** Escritor para rellenar el buffer interno. */
	private IWriter writer = null;
	
	/**
	 * <p>Constructor.</p>
	 * @param wrt Escritor que se utilizará para rellenar el buffer
	 */
	public ByteArrayWrittableInputStream(final IWriter wrt) {
		bais = new ByteArrayInputStream(new byte[0]);
		this.writer = wrt;
	}
	
	
	/**
	 * <p>Lee del buffer de lectura. Si se vacía lo cambia al buffer de escritura y éste lo resetea.</p>
	 * @return byte leido del buffer
	 * @throws IOException lanzada cuando se produce un error al leer del buffer
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException {
		int data = bais.read();
		if (data == -1) {
			updateBuffer();
			data = bais.read();
		}
		return data;
	}
	
	/**
	 * <p>Actualiza los buffers de escritura y lectura con los últimos bytes escritos por el {@link IWriter} asociado.</p>
	 * @throws IOException Lanzada si se produce un error al actualizar el buffer
	 */
	private void updateBuffer() throws IOException {
		flush();
		bais = new ByteArrayInputStream(writer.toByteArray());
		writer.reset();
	}
	
	/**
	 * <p>Vacía el contenido del {@link IWriter} asociado en el array interno.</p>
	 * 
	 * @throws IOException Lanzada si se produce un error al asegurar el contenido interno
	 */
	public void flush() throws IOException {
		writer.flush();
	}
	
	/**
	 * <p>Indica si se pueden recuperar más bytes del buffer interno.</p>
	 * 
	 * <p>Comprueba en primer lugar si todavía quedan disponibles bytes en el buffer interno, y si no es el caso, consulta al 
	 * {@link IWriter} asociado a ver si ya se han producido más datos.</p> 
	 * @return Númer de bytes disponibles en el buffer intermedio
	 * @throws IOException Lanzada si se produce un error al acceder al contenido interno
	 * @see java.io.InputStream#available()
	 */
	@Override
	public int available() throws IOException {
		int i = bais.available();
		if (i == 0) {
			i = writer.size();
		}
		return i;
	}

}
