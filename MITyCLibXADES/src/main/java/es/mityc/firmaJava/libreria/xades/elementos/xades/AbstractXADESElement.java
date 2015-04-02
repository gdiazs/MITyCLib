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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * Interfaz que ha de cumplir una implementación de un elemento del esquema xades
 */
public abstract class AbstractXADESElement extends AbstractXDsigElement {
	
	protected XAdESSchemas schema;
	protected String namespaceXAdES;
	
	protected AbstractXADESElement(XAdESSchemas schema) {
		super();
		this.schema = schema;
	}
	
	/**
	 * @return the schema
	 */
	public XAdESSchemas getSchema() {
		return schema;
	}


	/**
	 * @param schema the schema to set
	 */
	public void setSchema(XAdESSchemas schema) {
		this.schema = schema;
	}

	/**
	 * Este elemento lo pueden hacer público los elementos
	 * 
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	protected Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		return createElement(doc);
	}
	
	/**
	 * Este elemento lo pueden hacer público los elementos
	 * 
	 * @param doc
	 * @param namespaceXDsig
	 * @param namespaceXAdES
	 * @return
	 * @throws InvalidInfoNodeException
	 */
	protected Element createElement(Document doc, String namespaceXDsig, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		return super.createElement(doc, namespaceXDsig);
	}
	
	/**
	 * Este metodo lo puede hacer público los tipos
	 * 
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xmldsig.AbstractXDsigElement#addContent(org.w3c.dom.Document, org.w3c.dom.Element, java.lang.String)
	 */
	protected void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		addContent(element);
	}

	/**
	 * Este metodo lo puede hacer público los tipos.
	 * @param doc
	 * @param element
	 * @param namespaceXAdES
	 * @param namespaceXDsig
	 * @throws InvalidInfoNodeException
	 */
	protected void addContent(Element element, String namespaceXAdES, String namespaceXDsig) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		super.addContent(element, namespaceXDsig);
	}

	/**
	 * @return the namespaceXAdES
	 */
	public String getNamespaceXAdES() {
		return namespaceXAdES;
	}


	/**
	 * @param namespaceXAdES the namespaceXAdES to set
	 */
	public void setNamespaceXAdES(String namespaceXAdES) {
		this.namespaceXAdES = namespaceXAdES;
	}


}
