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
 * <p>Representa una firma que es contrafirmada.</p>
 * <p>Este objeto sólo debe utilizarse en una firma XAdES 1.3.2 o superior. Si es está firmando mediante un XAdES 1.1.1 o 1.2.2 se
 * recomienda utilizar la clase {@link InternObjectToSign}.</p>
 * 
 */
public class SignObjectToSign extends InternObjectToSign {

	/**
	 * <p>Constructor.</p>
	 * @param id identidad que tiene la firma contrafirmada
	 */
	public SignObjectToSign(String id) {
		super(id);
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getType()
	 */
	@Override
	public String getType() {
		return ConstantesXADES.SCHEMA_COUNTER_SIGNATURE;
	}

}
