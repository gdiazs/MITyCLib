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

import java.security.cert.X509Certificate;

/**
 * <p>Interfaz que han de implementar las respuestas de los validadores de certificados.</p>
 * 
 */
public interface ICertStatus {
	
	/** Posibles estados de los certificados. */
	enum CERT_STATUS { 
		/** Desconocido: no se conoce el estado del certificado. */
		unknown,
		/** Válido: el estado del certificado es válido. */
		valid,
		/** Revocado: el certificado se encuentra revocado. */
		revoked;
	}
	
	/**
	 * <p>Devuelve el estado del certificado consultado.</p>
	 * 
	 * @return uno de los estados del enumerado que se ajuste al estado del certificado
	 */
	CERT_STATUS getStatus();
	
	/**
	 * <p>Devuelve el certificado sobre el que se realizó la consulta de estado.</p>
	 * 
	 * @return Certificado consultado
	 */
	X509Certificate getCertificate();
	
	/**
	 * <p>Devuelve el estado del certificado en su forma original.</p>
	 * @return array de bytes con la forma original del estado del certificado
	 */
	byte[] getEncoded();
	
	/**
	 * <p>Devuelve información sobre la revocación del certificado.</p>
	 * @return Información de revocación del certificado, <code>null</code> si no está revocado
	 */
	RevokedInfo getRevokedInfo();

}
