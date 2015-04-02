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
import java.util.ArrayList;
import java.util.Iterator;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class DocumentationReferencesType extends AbstractXADESElement {
	
	private ArrayList<DocumentationReference> references;

	/**
	 * @param schema
	 */
	public DocumentationReferencesType(XAdESSchemas schema) {
		super(schema);
	}

	public DocumentationReferencesType(XAdESSchemas schema, ArrayList<DocumentationReference> list) {
		super(schema);
		this.references = list;
	}
	
	

	public ArrayList<DocumentationReference> getList() {
		return references;
	}

	public void setList(ArrayList<DocumentationReference> list) {
		this.references = list;
	}
	
	public void addReference(DocumentationReference qualifier) {
		if (references == null)
			references = new ArrayList<DocumentationReference>();
		references.add(qualifier);
	}

	public void addReference(URI uri) {
		if (references == null)
			references = new ArrayList<DocumentationReference>();
		references.add(new DocumentationReference(schema, uri));
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DocumentationReferencesType) {
			DocumentationReferencesType cvt = (DocumentationReferencesType) obj;
			ArrayList<DocumentationReference> comp = cvt.references;
			if (((references == null) || (references.isEmpty())) &&
				((comp == null) || (comp.isEmpty())))
				return true;
			if (((references != null) && (comp != null)) && 
				 (references.size() == comp.size())) {
				Iterator<DocumentationReference> itThis = references.iterator();
				Iterator<DocumentationReference> itComp = comp.iterator();
				while (itThis.hasNext()) {
					if (!itThis.next().equals(itComp.next()))
						return false;
				}
				return true;
			}
		}
		return false;
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((references != null) && (references.size() > 0)) {
			Iterator<DocumentationReference> it = references.iterator();
			while (it.hasNext()) {
				element.appendChild(it.next().createElement(element.getOwnerDocument(), namespaceXAdES));
			}
		}
		else
			throw new InvalidInfoNodeException("Nodo DocumentationReferencesType no tiene ningún hijo");
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}
	

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		NodeList nodos = element.getChildNodes();
		ArrayList<DocumentationReference> temp = new ArrayList<DocumentationReference>(nodos.getLength());
		for (int i = 0; i < nodos.getLength(); i++) {
			Node nodo = nodos.item(i);
			if (isDecorationNode(nodo))
				continue;
			
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Hijo de DocumentationReferencesType no es un elemento");
			
			DocumentationReference reference = new DocumentationReference(schema);
			reference.load((Element)nodo);
			temp.add(reference);
		}

		if (temp.size() == 0)
			throw new InvalidInfoNodeException("DocumentationReferencesType debe tener al menos un hijo");
		
		references = temp;
	}

}
