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

import java.util.ArrayList;
import java.util.Iterator;

/**
 * Clase para enlazar objetos del tipo (0..n) -> (0..1) 
 *
 */
public class NTo1Link<E> implements Iterable<NTo1Link<E>> {
	
	private ArrayList<NTo1Link<E>> prevs;
	private NTo1Link<E> next;
	private E data;
	
	public NTo1Link(E obj) {
		data = obj;
	}
	
	@Override
	public boolean equals(Object obj) {
		Object comp = obj;
		if (obj instanceof NTo1Link) {
			comp = ((NTo1Link)obj).getData();
		} 
		if ((comp != null) && (comp.equals(data))) {
			return true;
		}
		return false;
	}
	
	/**
	 * Establece el dato
	 * @param obj dato que se enlaza, <code>null</code> si no hay ninguno
	 */
	public void setData(E obj) {
		data = obj;
	}
	
	/**
	 * Devuelve el dato que se enlaza
	 * @return
	 */
	public E getData() {
		return data;
	}
	
	/**
	 * Añade un nuevo enlace hacia este objeto
	 * @param node
	 */
	public void addPrev(NTo1Link<E> node) {
		if (prevs == null)
			prevs = new ArrayList<NTo1Link<E>>();
		prevs.add(node);
	}
	
	/**
	 * Devuelve un <code>Iterator</code> a los elementos que enlazan a este elemento.
	 * @return iterator a elementos que enlazan a este elemento, <code>null</code> si no hay ninguno
	 */
	public Iterator<NTo1Link<E>> getPrevs() {
		if (prevs != null)
			return prevs.iterator();
		return null;
	}
	
	/**
	 * Devuelve el número de elementos que enlazan a este elemento
	 * @return
	 */
	public int getNumPrevs() {
		if (prevs != null)
			return prevs.size();
		return 0;
	}
	
	/**
	 * Establece el enlace hacia el siguiente elemento.
	 * @param node Siguiente elemento, <code>null</code> si no se quiere enlazar ningún elemento
	 */
	public void setNext(NTo1Link<E> node) {
		next = node;
	}
	
	/**
	 * Devuelve el siguiente elemento
	 * @return
	 */
	public NTo1Link<E> getNext() {
		return next;
	}

	public Iterator<NTo1Link<E>> iterator() {
		return new NTo1LinkIterator<E>(this);
	}

}
