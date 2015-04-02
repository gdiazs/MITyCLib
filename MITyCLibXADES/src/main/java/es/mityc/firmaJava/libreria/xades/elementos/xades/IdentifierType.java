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
package es.mityc.firmaJava.libreria.xades.elementos.xades;

import java.net.URI;
import java.net.URISyntaxException;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public abstract class IdentifierType extends AbstractXADESElement {
	
	private URI uri;
	private QualifierEnum qualifier = null;

	/**
	 * @param namespaceXAdES
	 * @param namespaceXDSig
	 * @param schema
	 */
	public IdentifierType(XAdESSchemas schema) {
		super(schema);
	}
	
	public IdentifierType(XAdESSchemas schema, URI uri, QualifierEnum qualifier) {
		super(schema);
		this.uri = uri;
		this.qualifier = qualifier;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof IdentifierType) {
			IdentifierType it = (IdentifierType) obj;
			if (uri.equals(it.uri))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		Node node = getFirstNonvoidNode(element);
		if (node.getNodeType() != Node.TEXT_NODE) {
			throw new InvalidInfoNodeException("Nodo IdentifierType no contiene CDATA como primer valor");
		}
		
		// Obtiene el qualifier si existe
		qualifier = QualifierEnum.getQualifierEnum(element.getAttribute(ConstantesXADES.QUALIFIER));

		String data = node.getNodeValue();
		if (data == null)
			throw new InvalidInfoNodeException("No hay URI en nodo IdentifierType");
		try {
			// FIX: Cambia los espacios por %20 para evitar problemas con la clase URI
			data = data.replace(" ", "%20");
			uri = new URI(data);
		} catch (URISyntaxException ex) {
			throw new InvalidInfoNodeException("URI malformada en nodo IdentifierType", ex);
		}
	}

	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (uri == null)
			throw new InvalidInfoNodeException("No hay información de URI para nodo IdentifierType");
		element.setTextContent(uri.toString());
		
		if (qualifier != null)
			element.setAttributeNS(null, ConstantesXADES.QUALIFIER, qualifier.toString());
	}

	/**
	 * @return the uri
	 */
	public URI getUri() {
		return uri;
	}

	/**
	 * @param uri the uri to set
	 */
	public void setUri(URI uri) {
		this.uri = uri;
	}

	/**
	 * @return the qualifier
	 */
	public QualifierEnum getQualifier() {
		return qualifier;
	}

	/**
	 * @param qualifier the qualifier to set
	 */
	public void setQualifier(QualifierEnum qualifier) {
		this.qualifier = qualifier;
	}
	
}
