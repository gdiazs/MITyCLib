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
package es.mityc.firmaJava.libreria.xades.elementos;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public abstract class AbstractXMLElement {
	
	protected AbstractXMLElement() {
		
	}
	
	/**
	 * Incluye la información de este nodo al elemento indicado. Implementado por los tipos.
	 * 
	 * @param doc
	 * @return
	 * @throws InvalidInfoNodeException
	 */
	protected void addContent(Element element) throws InvalidInfoNodeException {
		throw new UnsupportedOperationException("invalid operation");
	}

	/**
	 * Devuelve el árbol de nodos que representa este elemento. Implementado por los elementos finales.
	 * 
	 * @param doc Documento donde se agregará el elemento
	 */
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		throw new UnsupportedOperationException("invalid operation");
	}
	
	/**
	 * Lee la información del nodo
	 * 
	 * @param element elemento del que cuelga la información
	 * @throws InvalidInfoNodeException lanzada cuando la estructura de nodos leída es inválida
	 */
	public abstract void load(Element element) throws InvalidInfoNodeException;
	
	/**
	 * Compara otro objeto similar a ver si contienen la misma información
	 * 
	 * @param obj Objeto que ha de ser de la misma clase
	 * @return <code>true</code> si contienen la misma información, <code>false</code> en cualquier otro caso
	 */
	public abstract boolean equals(Object obj);
	
	/**
	 * Comprueba que el elemento indicado tiene el namespaceURI y el nombre esperados
	 * 
	 * @param element Elemento que chequear
	 * @param namespaceURI NamespaceURI esperado
	 * @param name Nombre esperado
	 * @throws InvalidInfoNodeException Se lanza cuando no se cumple lo esperado
	 */
	protected void checkElementName(Element element, String namespaceURI, String name) throws InvalidInfoNodeException {
		if (!isElementName(element, namespaceURI, name))
			throw new InvalidInfoNodeException("Elemento esperado (".concat(namespaceURI).concat(":").concat(name).concat(" Elemento obtenido ") + element.getNamespaceURI() + ":".concat(element.getLocalName()));
	}
	
	/**
	 * Comprueba si el elemento indicado tiene el nombre esperado
	 * 
	 * @param element Elemento que chequear
	 * @param namespaceURI NamespaceURI esperado
	 * @param name Nombre esperado
	 * @return
	 */
	protected boolean isElementName(Element element, String namespaceURI, String name) {
		if ((element != null) &&
			(new NombreNodo(namespaceURI, name).equals(
			 new NombreNodo(element.getNamespaceURI(), element.getLocalName()))))
			return true;
		return false;
	}
	
	/**
	 * Indica si el nodo pasado es o no del tipo al que se le hace la consulta
	 * 
	 * @param node
	 * @return
	 */
	protected boolean isThisNode(Node node) {
		throw new UnsupportedOperationException("invalid operation");
	}
	
	/**
	 * Convierte el nodo indicado a un elemento
	 * @param node
	 * @return <code>null<code> si el nodo indicado no es un Element
	 */
	protected Element nodeToElement(Node node) {
		Element element = null;
		if (node != null) {
			if (node.getNodeType() == Node.ELEMENT_NODE)
				element = (Element)node;
		}
		return element; 
	}
	
	protected static boolean isDecorationNode(Node node) {
		if (node != null) {
			switch (node.getNodeType()) {
				case Node.TEXT_NODE:
					String text = node.getNodeValue().trim();
					text = text.replaceAll("/n", ConstantesXADES.CADENA_VACIA);
					text = text.replaceAll("/r", ConstantesXADES.CADENA_VACIA);
					text = text.replaceAll(ConstantesXADES.ESPACIO, ConstantesXADES.CADENA_VACIA);		
					if (text.equals(ConstantesXADES.CADENA_VACIA))
						return true;
					else 
						return false;
				case Node.COMMENT_NODE:
					return true;
				case Node.ELEMENT_NODE:
				default: 
					return false;
			}
		}
		return true;
	}
	
	protected static Node getFirstNonvoidNode(Node node) {
		Node child = node.getFirstChild();
		
		while ((child != null) && (isDecorationNode(child))) {
			child = child.getNextSibling();
		}
		return child;
	}

	protected static Node getNextNonvoidNode(Node node) {
		Node child = node.getNextSibling();
		
		while ((child != null) && (isDecorationNode(child))) {
			child = child.getNextSibling();
		}
		return child;
	}
	
	protected static boolean compare(Object obj1, Object obj2) {
		if ((obj1 == null) && (obj2 == null))
			return true;
		if (obj1 != null)
			return (obj1.equals(obj2));
		return false;
	}
}
