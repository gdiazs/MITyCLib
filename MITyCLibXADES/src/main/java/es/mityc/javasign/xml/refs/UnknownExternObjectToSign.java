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

import es.mityc.javasign.ConstantsXAdES;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.xml.resolvers.IPrivateData;
import es.mityc.javasign.xml.resolvers.MITyCResourceResolver;
import es.mityc.javasign.xml.resolvers.ResolverPrivateData;
import es.mityc.javasign.xml.transform.Transform;

/**
 * <p>Representa un objeto externo al XML (no definido) que debe ser firmado.</p>
 * <p>Para poder acceder al contenido y obtener su digest se debe proporcionar el digester adecuado que implemente el interfaz
 * <code>IPrivateDate</code>.</p>
 * <p>Este tipo de objetos delega la seguridad e integridad del contenido en el gestionador de la información privada, que será
 * el responsable de asegurar que no se produce ningún ataque sobre la informacón.</p>
 * 
 */
public class UnknownExternObjectToSign extends AbstractObjectToSign {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsXAdES.LIB_NAME);
	
	private String name;
	private IPrivateData digester;
	

	/**
	 * 
	 */
	public UnknownExternObjectToSign(String name, IPrivateData privateDataDigester) {
		this.name = name;
		this.digester = privateDataDigester;
	}


	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * 
	 * @return
	 */
	public IPrivateData getDigester() {
		return digester;
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#addTransform(es.mityc.javasign.xml.transform.Transform)
	 */
	@Override
	public void addTransform(Transform t) {
		throw new IllegalArgumentException(I18N.getLocalMessage(ConstantsXAdES.I18N_SIGN_10));
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getReferenceURI()
	 */
	@Override
	public String getReferenceURI() {
		return name;
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getResolver()
	 */
	@Override
	public MITyCResourceResolver getResolver() {
		return new ResolverPrivateData(getDigester());
	}
}
