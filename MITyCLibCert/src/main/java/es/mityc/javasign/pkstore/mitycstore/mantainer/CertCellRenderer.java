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

import java.awt.Component;

import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * <p>Renderizador de las celdas para las tablas de certificados.</p> 
 *  
 */
public class CertCellRenderer extends DefaultTableCellRenderer {
	
	/**
	 * <p>Devuelve la clase encargada de dibujar la celda correspondiente.</p>
	 * <p>El comportamiento es el mismo que por defecto, salvo por la alineación y el tooltip.</p>
	 * 
	 * @param table Tabla a la que la ceda pertenece
	 * @param value Valor contenido dentro de la celda
	 * @param isSelected Booleano que indica si la celda está marcada como seleccionada
	 * @param hasFocus Booleano que indica si la tabla tiene el foco
	 * @param row Numero de fila (empezando por el 0)
	 * @param column Número de columna (empezando por el 0)
	 * @return Devuelve una instancia a ésta misma clase 
	 */
	@Override
	public Component getTableCellRendererComponent(
			final JTable table,
			final Object value,
			final boolean isSelected,
			final boolean hasFocus,
			final int row,
			final int column) { 
		
		super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
		
		// ToolTip
		 setToolTipText((String) value);
		 getAccessibleContext().setAccessibleName((String) value);
		
		 // Allignment
		if (column == 0) {
			setHorizontalAlignment(SwingConstants.LEFT);
		} else if (column == 1) {
			setHorizontalAlignment(SwingConstants.LEFT);
		} else	if (column == 2) {
			setHorizontalAlignment(SwingConstants.CENTER);
		} 
				
		return this; 
	} 
}
