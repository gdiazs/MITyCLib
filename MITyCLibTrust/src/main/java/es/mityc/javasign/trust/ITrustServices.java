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
package es.mityc.javasign.trust;

import java.security.cert.X509Certificate;
import java.util.List;

import es.mityc.javasign.trust.MyPropsTruster.TrustCertStruct;
import es.mityc.javasign.trust.PropsTruster.TrusterType;

/**
 * <p>Interfaz que ha de implementar un validador de confianza que permita incluir certificados.</p>
 * 
 */
public interface ITrustServices {
	
	/**
	 * <p>Devuelve una lista con todas las CAs de usuario configuradas.</p>
	 * @return Lista de certificados configurada
	 * @throws TrustException En caso de error
	 */
	public List<TrustCertStruct> getCAs() throws TrustException;
	
	/**
	 * <p>Comprueba si la clave existe dentro de las propiedades cargadas.</p>
	 * @param md5Digest 
	 * @return
	 */
	public boolean containsCert(String md5Digest) throws TrustException;

	/**
	 * <p>Añade una nueva CA a la colección.</p>
	 * @param cert Certificado a añadir
	 * @param type Tipo de CA
	 * @param path Ruta al repositorio
	 * @throws TrustException
	 */
	void addCA(X509Certificate cert, TrusterType type, String path) throws TrustException;
	
	/**
	 * <p>Permite borrar un certificado del repositorio del usuario.<p>
	 * @param cert Certificado a borrar.
	 * @param type Tipo de certificado.
	 * @param path Ruta física al repositorio
	 * @see es.mityc.javasign.trust.PropsTruster.TrusterType
	 */
	public void removeCA(X509Certificate cert, TrusterType type, String path) throws TrustException;
}
