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
package es.mityc.javasign.xml.transform;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.javasign.ConstantsXAdES;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.xml.xades.TransformProxy;

/**
 * <p>Transformada que aplica transformaciones XSLT.</p>
 * 
 */
public class TransformXSLT extends Transform implements ITransformData {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsXAdES.LIB_NAME);

	
	/** Elemento raíz de la hoja de estilo. */
	private Element stylesheet;
	
	/**
	 * <p>Constructor.</p>
	 */
	public TransformXSLT() {
		super(TransformProxy.TRANSFORM_XSLT, null);
		setTransformData(this);
	}
	
	/**
	 * @see es.mityc.javasign.xml.transform.Transform#getExtraData(org.w3c.dom.Document)
	 */
	@Override
	public NodeList getExtraData(Document doc) {
		SimpleNodeList nl = null;
		if ((stylesheet != null)) {
			try {
				Node node = doc.importNode(stylesheet, true);
				nl = new SimpleNodeList();
				nl.addNode(node);
			} catch (DOMException ex) {
			}
		}
		return nl;
	}
	
	/**
	 * <p>Establece la hoja de estilo de esta transformada.</p>
	 * @param stylesheet Hoja de estilo
	 * @throws IllegalArgumentException si el elemento no se corresponde con una hoja de estilo
	 */
	public void setStyleSheet(Element stylesheet) throws IllegalArgumentException {
		if (!"http://www.w3.org/1999/XSL/Transform".equals(stylesheet.getNamespaceURI())) {
			throw new IllegalArgumentException(I18N.getLocalMessage(ConstantsXAdES.I18N_SIGN_8, stylesheet.getNamespaceURI()));
		}
		if (!"stylesheet".equals(stylesheet.getLocalName())) {
			throw new IllegalArgumentException(I18N.getLocalMessage(ConstantsXAdES.I18N_SIGN_9, stylesheet.getLocalName()));
		}
		this.stylesheet = stylesheet;
	}
	
}
