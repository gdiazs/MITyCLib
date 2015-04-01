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
package es.mityc.javasign.tsa;

/**
 * <p>Interfaz que debe cumplir todos los generadores de sellos de tiempo.</p>
 */
public interface ITimeStampGenerator {

    /**
     * <p>
     * Genera un sello de tiempo de unos determinados datos
     * </p>
     * 
     * @param dataToSeal
     *            Datos a sellar
     * @return Sello de tiempo asociado
     * @throws TimeStampException
     *             Si ocurre algún error al generar el sello de tiempo
     */
	public byte[] generateTimeStamp(byte[] dataToSeal) throws TimeStampException;
	
}
