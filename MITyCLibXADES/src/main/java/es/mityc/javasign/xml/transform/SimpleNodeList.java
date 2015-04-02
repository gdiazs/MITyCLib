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

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * <p>Lista de nodos.</p>
 * 
 */
public class SimpleNodeList implements NodeList {
	
	/** Listado de nodos. */
	private List<Node> list = new ArrayList<Node>();
	
	public void addNode(Node node) {
		list.add(node);
	}
	
	/**
	 * @see org.w3c.dom.NodeList#getLength()
	 */
	public int getLength() {
		return list.size();
	}
	
	/**
	 * @see org.w3c.dom.NodeList#item(int)
	 */
	public Node item(int index) {
		return list.get(index);
	}

}
