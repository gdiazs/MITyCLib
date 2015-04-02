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
package es.mityc.javasign.xml.refs;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Representa un objeto interior al XML pero exterior a la firma (ds:signature) que se quiere firmar.
 * 
 */
public class InternObjectToSign extends AbstractObjectToSign {
	
	private String id;
	
	/**
	 * <p>Constructor.</p>
	 * @param id Identidad del nodo a firmar
	 */
	public InternObjectToSign(String id) {
		this.id = id;
	}

	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(String id) {
		this.id = id;
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getReferenceURI()
	 */
	@Override
	public String getReferenceURI() {
		return ConstantesXADES.ALMOHADILLA + getId();
	}

}
