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
package es.mityc.firmaJava.libreria.xades.elementos.xmldsig;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;


/**
 * Interfaz que ha de cumplir una implementación de un elemento del esquema XDsig
 * 
 */
public abstract class AbstractXDsigElement extends AbstractXMLElement {
	
	protected String namespaceXDsig;
	
	protected AbstractXDsigElement() {
		super();
	}
	
	/**
	 * Este método pueden hacerlo público los elementos finales.
	 * 
	 * @param doc
	 * @param namespace
	 * @return
	 * @throws InvalidInfoNodeException
	 */
	protected Element createElement(Document doc, String namespaceXDsig) throws InvalidInfoNodeException {
		setNamespaceXDsig(namespaceXDsig);
		return createElement(doc);
	}
	
	/**
	 * Este método pueden hacerlo público los tipos.
	 * 
	 * @param doc
	 * @param element
	 * @param namespace
	 * @throws InvalidInfoNodeException
	 */
	protected void addContent(Element element, String namespaceXDsig) throws InvalidInfoNodeException {
		setNamespaceXDsig(namespaceXDsig);
		addContent(element);
	}

	/**
	 * @return the namespaceXDsig
	 */
	public String getNamespaceXDsig() {
		return namespaceXDsig;
	}

	/**
	 * @param namespaceXDsig the namespaceXDsig to set
	 */
	public void setNamespaceXDsig(String namespaceXDsig) {
		this.namespaceXDsig = namespaceXDsig;
	}
	
}
