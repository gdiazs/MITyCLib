/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES 1.1.7".
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
package es.mityc.javasign.pkstore.mitycstore.mantainer;

/**
 * Modelo visual de la estructura árbol que muestra los datos de firma.
 *
 */
public class TypeTreeNode {	
	
	/** Nombre del nodo. */
	private String nombre = null;
	/** Tooltip asociado al nodo. */
	private String toolTip = null;
	/** Datos asociados al nodo. */
	private Object datosAsociados = null;

	/** Constructor por defecto. */
	public TypeTreeNode() { }
	
	/**
	 * <p>Modelo de datos para los nodos del árbol de información de certificados.</p>
	 * @param nombreNodo Nombre del nodo.
	 * @param datosAsoc Datos asociados al nodo
	 */
	public TypeTreeNode(final String nombreNodo, final Object datosAsoc) {
		this.nombre = nombreNodo;
		this.toolTip = nombreNodo;
		this.datosAsociados = datosAsoc;
	}	
	
	/**
	 * <p>Devuelve el nombre asociado al nodo.</p>
	 * @return String con el nombre del nodo
	 */
	public String getNombre() {
		return nombre;
	}
	/**
	 * <p>Establece el nombre del nodo.</p>
	 * @param name Nombre a asociar al nodo
	 */
	public void setNombre(final String name) {
		this.nombre = name;
	}
	/**
	 * <p>Devuelve el tooltip asociado al nodo.</p>
	 * @return El tooltip coincide con el nombre
	 */
	public String getToolTip() {
		return toolTip;
	}
	/**
	 * <p>Establece el tooltip que se mostrará en el nodo.</p>
	 * @param toolTipNodo El tooltip coincide con el nombre
	 */
	public void setToolTip(final String toolTipNodo) {
		this.toolTip = toolTipNodo;
	}		
	/**
	 * <p>Devuelve los datos asociados al nodo.</p>
	 * @return El objeto de datos asociado al nodo
	 */
	public Object getDatosAsociados() {
		return datosAsociados;
	}
	/**
	 * <p>Establece el objeto de datos a asociar con el nodo.</p>
	 * @param datosAsoc Objeto de datos a asociar.
	 */
	public void setDatosAsociados(final Object datosAsoc) {
		this.datosAsociados = datosAsoc;
	}

	/**
	 * <p>Devuelve el nombre del nodo.</p>
	 * @return El nombre asociado al nodo
	 */
	@Override
	public String toString() {
		return nombre;
	}
}