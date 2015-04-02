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
package es.mityc.firmaJava.libreria.utilidades;

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Clase que implementa un iterador de elementos NTo1Link<E>
 *
 */public class NTo1LinkIterator<E> implements Iterator<NTo1Link<E>> {
	
	private NTo1Link<E> nextNode;
	
	NTo1LinkIterator(NTo1Link<E> first) {
		nextNode = first;
	}

	public boolean hasNext() {
		return (nextNode != null);
	}

	public NTo1Link<E> next() {
		if (nextNode == null)
			throw new NoSuchElementException();
		NTo1Link<E> node = nextNode;
		nextNode = nextNode.getNext();
		return node;
	}

	public void remove() {
		throw new UnsupportedOperationException();
	}

}
