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
package es.mityc.javasign.pkstore.iexplorer;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * <p>Actúa como proxy de clave privada para el acceso a claves privadas de un almacén de IExplorer mediante la interfaz nativa DLLFirmaVC.</p>
 * 
 */
public class PKProxyIE implements PrivateKey {
	
	/** Certificado asociado a la clave privada. */
	private X509Certificate certificatePK;
	
	/**
	 * <p>Crea el proxy relacionado con un certificado del almacén.</p>
	 * 
	 * @param certificate certificado asociado con la clave privada
	 */
	public PKProxyIE(final X509Certificate certificate) {
		this.certificatePK = certificate;
	}
	
	/**
	 * <p>Devuelve el certificado relacionado con la clave privada relacionada con este proxy.</p>
	 * @return Certificado asociado con la clave privada
	 */
	public X509Certificate getCertificate() {
		return certificatePK;
	}

	/**
	 * <p>Sin uso.</p>
	 * @return sin uso
	 * @see java.security.Key#getAlgorithm()
	 */
	public String getAlgorithm() {
		return null;
	}

	/**
	 * <p>Sin uso.</p>
	 * @return sin uso
	 * @see java.security.Key#getEncoded()
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * <p>Sin uso.</p>
	 * @return sin uso
	 * @see java.security.Key#getFormat()
	 */
	public String getFormat() {
		return null;
	}

}
