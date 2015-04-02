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
package es.mityc.firmaJava.libreria.xades.elementos.xades;

/**
 */
public enum QualifierEnum {

	OIDAsURI("OIDAsURI"),
	OIDAsURN("OIDAsURN");

	
	private String value;
	
	private QualifierEnum(String value) {
		this.value = value;
	}
	
	/**
	 * @see java.lang.Enum#toString()
	 */
	@Override
	public String toString() {
		return new String(value);
	}
	
	public static QualifierEnum getQualifierEnum(String value) {
		if (value == null)
			return null;
		if (OIDAsURI.toString().equals(value))
			return OIDAsURI;
		else if (OIDAsURN.toString().equals(value))
			return OIDAsURN;
		return null;
	}

}
