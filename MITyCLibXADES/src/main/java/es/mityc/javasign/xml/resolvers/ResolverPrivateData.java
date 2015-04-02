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
package es.mityc.javasign.xml.resolvers;

import org.w3c.dom.Attr;

import adsi.org.apache.xml.security.signature.XMLSignatureInput;
import adsi.org.apache.xml.security.utils.resolver.ResourceResolverException;

/**
 * Este ResourceResolverSpi permite acceder a información privada obtiendo su digest para poder realizar una firma XML.
 * 
 */
public class ResolverPrivateData extends MITyCResourceResolver {
	
	private final static String[] keys = { "digest.algorithm" };
	
	private IPrivateData internalResolver;

	/**
	 * 
	 */
	public ResolverPrivateData(IPrivateData internalResolver) {
		super();
		this.internalResolver = internalResolver;
	}

	/**
	 * @see adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineCanResolve(org.w3c.dom.Attr, java.lang.String)
	 */
	@Override
	public boolean engineCanResolve(Attr uri, String BaseURI) {
		if (internalResolver == null) {
			return false;
		}
		return internalResolver.canDigest(uri.getValue(), BaseURI);
	}

	/**
	 * @see adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineResolve(org.w3c.dom.Attr, java.lang.String)
	 */
	@Override
	public XMLSignatureInput engineResolve(Attr uri, String BaseURI) throws ResourceResolverException {
		if (internalResolver == null) {
			throw new ResourceResolverException("", uri, BaseURI);
		}
		String algName = engineGetProperty( "digest.algorithm");
		if (algName == null) {
			throw new ResourceResolverException("", uri, BaseURI);
		}
		try {
			byte[] data = internalResolver.getDigest(uri.getValue(), BaseURI, algName);
			XMLSignatureInput xsi = new XMLSignatureInput(data);
			return xsi;
		} catch (ResourceDataException ex) {
			throw new ResourceResolverException("", uri, BaseURI);
		}
	}
	
	/**
	 * @see adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineIsPrivateData()
	 */
	@Override
	public boolean engineIsPrivateData() {
		return true;
	}
	
	/**
	 * @see adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineGetPropertyKeys()
	 */
	@Override
	public String[] engineGetPropertyKeys() {
		return keys;
	}
}
