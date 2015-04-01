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
 * Interfaz que deben cumplir los decodificadores utilizados en {@link DecoderInputStream} para poder decodificar una entrada al aire
 * (directamente desde el <i>stream</i> de entrada, en pequeños bloques, sin tener que cargar todo el contenido del <i>stream</i>).
 * 
 */
public interface IDecoder {
	
	/**
	 * <p>Indica que para poder continuar decoficando se ha de incluir más datos en el buffer.</p>
	 * 
	 * @return <code>true</code> si necesita más datos, <code>false</code> en otro caso
	 */
	boolean needsInput();
	
	/**
	 * <p>Indica quedan bytes en el buffer sin decodificar.</p>
	 * 
	 * @return <code>true</code> si quedan bytes sin haber sido decoficados en el buffer, <code>false</code> en otro caso
	 */
	boolean isIncomplete();
	
	/**
	 * <p>Añade nuevos datos en el buffer de decodificación.</p>
	 * 
	 * @param data array con los nuevos datos
	 * @param off posición del array desde la que se incluyen los datos
	 * @param len cantidad de bytes que hay que añadir
	 */
	void addInput(byte[] data, int off, int len);
	
	/**
	 * <p>Decodifica en el array de bytes indicado la información contenida en el buffer.</p>
	 * 
	 * @param data Array en el que escribir los datos
	 * @param off Posición a partir de la cual escribir
	 * @param len Cantidad de bytes máximo que se puede escribir
	 * @return Cantidad de bytes que se han decodificado
	 * @throws DecodingException lanzada cuando se produce un error decodificando (los datos no se ajustan al codec o hay desincronismos en el
	 * 			buffer)
	 */
	int decode(byte[] data, int off, int len) throws DecodingException;
	

}
