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

import java.io.IOException;
import java.io.InputStream;

/**
 * <p><i>InputStream</i> que bloquea el indicativo de final de <i>stream</i> hasta que recibe el aviso de desbloquearlo.</p>
 * 
 * <p>Con esta peculiaridad se puede tener acceso a un InputStream basado en otros <i>streams</i> que pueden estar recibiendo información
 * según están siendo leídos sin que indiquen que su contenido ha finalizado.</p>
 * 
 */
public class InjectableInputStream extends InputStream {
	/** InputStream interno para la lectura de datos.*/
	private InputStream is;
	/** Flag que indica si se puede indicar que el stream se encuentra finalizado. */
	private boolean ended = false;

	/**
	 * <p>Constructor.</p>
	 * @param inputStream InputStream del que se leen los datos
	 */
	public InjectableInputStream(InputStream inputStream) {
		this.is = inputStream;
	}

	/**
	 * <p>Lee un byte del stream.</p>
	 * @return byte leído
	 * @throws IOException lanzada si se produce un error durante la lectura
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException {
		return is.read();
	}
	
	/**
	 * <p>Lee un bloque de datos del stream.</p>
	 * @param b array de bytes en el que se escriben los datos leídos
	 * @param off offset sobre el que escribir los datos
	 * @param len cantidad de datos máxima a escribir
	 * @return número de bytes que se han conseguido leer, -1 si el stream ha finalizado y no está disponible para más lecturas
	 * @throws IOException Lanzada cuando se produce un error al leer del stream
	 * @see java.io.InputStream#read(byte[], int, int)
	 */
	@Override
	public int read(byte[] b, final int off, final int len) throws IOException {
		int res = is.read(b, off, len);
		if ((!isEnded()) && (res == -1)) {
			return 0;
		} else {
			return res;
		}
	}
	
	/**
	 * <p>Marca que no se van a inyectar más datos en el stream de entrada.</p>
	 */
	public void endStream() {
		ended = true;
	}
	
	/**
	 * <p>Devuelve si el stream está marcado para permitir su finalización.</p>
	 * @return <code>true</code> si se permite que el stream pueda finalizar, <code>false</code> en caso contrario
	 */
	public boolean isEnded() {
		return ended;
	}
	
	/**
	 * <p>Devuelve la cantidad de datos disponibles en el stream.</p>
	 * @return número de bytes disponibles
	 * @throws IOException Lanzada cuando se produce un error al acceder al stream
	 * @see java.io.InputStream#available()
	 */
	@Override
	public int available() throws IOException {
		return is.available();
	}
	
	/**
	 * <p>Cierra el stream.</p>
	 * @throws IOException Lanzada cuando se produce un error al cerrar el stream
	 * @see java.io.InputStream#close()
	 */
	@Override
	public void close() throws IOException {
		InputStream in = is;
		is = null;
		if (in != null) {
			in.close();
		}
	}
	
	/**
	 * <p>Marca la posición en el stream.</p>
	 * <p>Esta función se delega al stream interno por lo que podría falla si el stream interno no la admite.</p>
	 * @param readlimit marca donde habrá que volver en un reset del stream
	 * @see java.io.InputStream#mark(int)
	 */
	@Override
	public synchronized void mark(final int readlimit) {
		is.mark(readlimit);
	}
	
	/**
	 * <p>Resetea a la última posición marcada en el stream.</p>
	 * @throws IOException Lanzada cuando se produce un error al realizar un reset al stream 
	 * @see java.io.InputStream#reset()
	 */
	@Override
	public synchronized void reset() throws IOException {
		is.reset();
	}
	
	/**
	 * <p>Salta un número de bytes sin leerlos del stream.</p>
	 * @param n número de bytes a saltar
	 * @return número de bytes que se han podido saltar del stream
	 * @throws IOException Lanzada cuando se produce un error al realizar el salto
	 * @see java.io.InputStream#skip(long)
	 */
	@Override
	public long skip(final long n) throws IOException {
		return is.skip(n);
	}
	
	/**
	 * <p>Indica si el stream asociado admite marca.</p>
	 * @return <code>true</code> si el stream admite marca, <code>false</code> en otro caso
	 * @see java.io.InputStream#markSupported()
	 */
	@Override
	public boolean markSupported() {
		return is.markSupported();
	}
}
