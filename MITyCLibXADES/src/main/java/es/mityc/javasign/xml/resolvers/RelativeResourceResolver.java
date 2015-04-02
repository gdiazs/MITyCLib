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

import java.io.File;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import adsi.org.apache.xml.security.signature.XMLSignatureInput;
import adsi.org.apache.xml.security.utils.resolver.ResourceResolverException;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFicheros;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.CanonicalizationEnum;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import es.mityc.javasign.xml.refs.AbstractObjectToSign;
import es.mityc.javasign.xml.refs.RelativeDetachedFileToSign;

/**
 * Este ResourceResolverSpi permite acceder a información externa para poder realizar una firma XML.
 * 
 */
public class RelativeResourceResolver extends MITyCResourceResolver {
	
	private RelativeDetachedFileToSign internalResolver;

	/**
	 * 
	 */
	public RelativeResourceResolver(File file) {
		super();
		this.internalResolver = new RelativeDetachedFileToSign(file);
	}
	
	public AbstractObjectToSign getResolver() {
		return internalResolver;
	}

	/**
	 * @see adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineCanResolve(org.w3c.dom.Attr, java.lang.String)
	 */
	@Override
	public boolean engineCanResolve(Attr uri, String BaseURI) {
		if (internalResolver == null) {
			return false;
		}
		try {
			return internalResolver.getFile().exists();
		} catch(Exception e) {
			return false;
		}
	}

	/**
	 * @see adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineResolve(org.w3c.dom.Attr, java.lang.String)
	 */
	@Override
	public XMLSignatureInput engineResolve(Attr uri, String BaseURI) throws ResourceResolverException {
		if (internalResolver == null) {
			throw new ResourceResolverException("", uri, BaseURI);
		}
		
		// Se tiene en cuenta la canonicalización
		CanonicalizationEnum canonicalization = null;
		try {
			NodeList nodosCanonicalizationMethod = ((Element)uri.getOwnerElement().getParentNode()).getElementsByTagNameNS(ConstantesXADES.SCHEMA_DSIG, 
					ConstantesXADES.CANONICALIZATION_METHOD);
			int numNodosCanonicalization = nodosCanonicalizationMethod.getLength();
			
			if (numNodosCanonicalization > 0) {
				Element nodoCanonicalizationMethod = (Element)nodosCanonicalizationMethod.item(0);
				String meth = nodoCanonicalizationMethod.getAttribute(ConstantesXADES.ALGORITHM);
				canonicalization = CanonicalizationEnum.getCanonicalization(meth);
				if (canonicalization.equals(CanonicalizationEnum.UNKNOWN)) { 
					canonicalization = CanonicalizationEnum.C14N_OMIT_COMMENTS;
				}
			}
		} catch (Exception e) {
			canonicalization = CanonicalizationEnum.C14N_OMIT_COMMENTS;
		}

		if (uri.getValue().startsWith(ConstantesXADES.ALMOHADILLA)) {
			try {
				Element el = UtilidadTratarNodo.getElementById(uri.getOwnerDocument(), uri.getValue().substring(1));
				byte[] source = UtilidadTratarNodo.obtenerByte(el, canonicalization);
				if (source == null || source.length <= 0)
					throw new ResourceDataException("No se puede obtener el contenido referenciado");
				XMLSignatureInput xsi = new XMLSignatureInput(source);
				return xsi;
			} catch (ResourceDataException ex) {
				throw new ResourceResolverException("", uri, BaseURI);
			} catch (FirmaXMLError e) {
				throw new ResourceResolverException(e.getMessage(), uri, BaseURI);
			}
		} else {
			byte[] data = UtilidadFicheros.readFile(internalResolver.getFile());
			XMLSignatureInput xsi = new XMLSignatureInput(data);
			return xsi;
		}
	}
}
