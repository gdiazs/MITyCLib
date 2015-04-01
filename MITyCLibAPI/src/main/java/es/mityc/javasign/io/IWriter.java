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

/**
 * <p>Interfaz que debe implementar la clase que inyecte datos en un {@link ByteArrayWrittableInputStream}.</p>
 *  
 */
public interface IWriter {
	
	/**
	 * <p>Vacía los buffers intermedios.</p>
	 *  
	 * @throws IOException si hay algún problema en el vaciado
	 */
	void flush() throws IOException;
	
	/**
	 * <p>Devuelve un array de bytes con el contenido escrito.</p>
	 * @return byte[] con el contenido escrito
	 */
	byte[] toByteArray();
	
	/**
	 * <p>Inicializa el escritor marcándolo como vacío.</p>
	 */
	void reset();
	
	/**
	 * <p>Devuelve el tamaño actual del contenido escrito.</p>
	 * @return tamaño en bytes del contenido actual
	 */
	int size();

}
