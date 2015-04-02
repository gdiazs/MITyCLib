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

import java.io.InputStream;

import org.w3c.dom.Attr;

import adsi.org.apache.xml.security.signature.XMLSignatureInput;
import adsi.org.apache.xml.security.utils.resolver.ResourceResolverException;

/**
 * Este ResourceResolverSpi permite acceder a información de un elemento a través de un interfaz propio para poder realizar una firma XML.
 * 
 */
public class XAdESResourceResolverSpi extends MITyCResourceResolver {
	
	private IResourceData internalResolver;

	/**
	 * 
	 */
	public XAdESResourceResolverSpi(IResourceData internalResolver) {
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
		return internalResolver.canAccess(uri.getValue(), BaseURI);
	}

	/**
	 * @see adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineResolve(org.w3c.dom.Attr, java.lang.String)
	 */
	@Override
	public XMLSignatureInput engineResolve(Attr uri, String BaseURI) throws ResourceResolverException {
		if (internalResolver == null) {
			throw new ResourceResolverException("", uri, BaseURI);
		}
		try {
			Object dataAccess = internalResolver.getAccess(uri.getValue(), BaseURI);
			XMLSignatureInput xsi = null;
			if (dataAccess instanceof InputStream) {
				xsi = new XMLSignatureInput((InputStream)dataAccess);
			} else if (dataAccess instanceof byte[]) {
				xsi = new XMLSignatureInput((byte[])dataAccess);
			} else {
				throw new ResourceResolverException("", uri, BaseURI);
			}
			return xsi;
		} catch (ResourceDataException ex) {
			throw new ResourceResolverException("", uri, BaseURI);
		}
	}

}
