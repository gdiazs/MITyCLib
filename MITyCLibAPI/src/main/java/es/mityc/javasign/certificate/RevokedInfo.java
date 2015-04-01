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
package es.mityc.javasign.certificate;

import java.util.Date;

/**
 * <p>Almacena información sobre el estado de revocación de un certificado.</p>
 * 
 */
public class RevokedInfo {
	
	/** Motivo de revocación. */
	private Object revokedReason;
	/** Fecha de revocación. */
	private Date revokedDate;
	
	/**
	 * <p>Constructor.</p>
	 * @param reason Motivo de la revocación
	 * @param date Fecha de la revocación
	 */
	public RevokedInfo(Object reason, Date date) {
		this.revokedReason = reason;
		this.revokedDate = date;
	}

	/**
	 * <p>Devuelve el motivo de revocación.</p>
	 * @return Object que indica el motivo de revocación
	 */
	public Object getRevokedReason() {
		return revokedReason;
	}

	/**
	 * <p>Devuelve la fecha de revocación.</p>
	 * @return fecha de revocación
	 */
	public Date getRevokedDate() {
		return revokedDate;
	}
	
	/**
	 * <p>Clona el objeto y la fecha, pero no el motivo de revocación.</p>
	 * @return clonado del objeto
	 * @see java.lang.Object#clone()
	 */
	@Override
	public Object clone() {
		Date date = (revokedDate != null) ? (Date) revokedDate.clone() : null;
		return new RevokedInfo(revokedReason, date);
	}

}
