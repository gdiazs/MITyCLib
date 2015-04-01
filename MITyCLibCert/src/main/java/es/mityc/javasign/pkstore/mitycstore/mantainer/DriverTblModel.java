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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.swing.table.AbstractTableModel;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
 * <p>Modelo visual de la tabla de drivers para pasarelas PKCS#11.</p>
 *
 */
public class DriverTblModel extends AbstractTableModel {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Nombres de los campos a mostrar. */
    private String[] columnNames = null;
    /** Datos obtenidos. */
    private Object[][] data = null;

    /**
     * <p>Constructor por defecto.</p>
     * @param drvrList Mapa de claves con las rutas de los driver a mostrar en la tabla.
     */
    public DriverTblModel(final HashMap<String, String> drvrList) {
    	columnNames = new String[2];
    	// Nombre
        columnNames[0] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_94);
        // Path del driver
        columnNames[1] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_95);
        
    	int rows = 0;
    	if (drvrList != null) {
    		rows = drvrList.size();
    	} else {
    		return;
    	}
    	data = new Object[rows][2];
    	
    	Iterator<Map.Entry<String, String>> contents = drvrList.entrySet().iterator();
    	Map.Entry<String, String> content = null;
    	int i = 0;
    	while (contents.hasNext()) {
    		content = contents.next();
    		// Nombre
    		data[i][0] = content.getKey();

    		// Ruta
    		data[i][1] = content.getValue();
    		 ++i;
    	}  
    }
       
    /**
     * <p>Devuelve el número de columnas de la tabla.</p>
     * @return Número de columnas de la tabla.
     */
    public int getColumnCount() {
        return columnNames.length;
    }

    /**
     * <p>Devuelve el número de filas de la tabla.</p>
     * @return Número de filas de la tabla.
     */
    public int getRowCount() {
        return data.length;
    }

    /**
     * <p>Devuelve el valor de la celda que se le pasa como parámetro.</p>
     * @param fil Fila a la que pertenece la celda que queremos recuperar.
     * @param col Columna a la que pertenece la celda que queremos recuperar.
     * @return Valor de la celda.
     */
    public Object getValueAt(final int fil, final int col) {
    	if (fil >= 0 && fil < data.length && col >= 0 && col < 2) {
    		return data[fil][col];
    	} else {
    		return null;
    	}
    }
    
    /**
     * <p>Devuelve el nombre de la columna que se le pasa como parámetro.</p>
     * @param col Número de la columna cuyo nombre queremos recuperar.
     * @return Nombre de la columna.
     */
    @Override
    public String getColumnName(final int col) {
        return columnNames[col];
    }
    
    /**
     * <p> Delvuelve el tipo de dato que contiene la columna.</p>
     * @param columnIndex Número de la columna cuyo tipo queremos recuperar.
     * @return Tipo de dato de la columna.
     */
    @Override
	public Class< ? > getColumnClass(final int columnIndex) {
		return String.class;
	}
    
    /**
     * <p>Regenera toda la estructura de datos, incluyendo la nueva fila.</p>
     * @param name Nombre del driver a añadir
     * @param value Ruta al driver a añadir
     */
    public void addRow(final String name, final String value) {
    	Object[][] newData = new Object[data.length + 1][2];
    	for (int i = 0; i < data.length; ++i) {
    		newData[i][0] = data[i][0];
    		newData[i][1] = data[i][1];
    	}
    	newData[data.length][0] = name;
    	newData[data.length][1] = value;
    	data = newData;
    	fireTableDataChanged();
    }
    
    /**
     * <p>Regenera toda la estructura de datos, salvo el índice a eliminar.</p>
     * @param index Indice de la fila a borrar
     */
    public void removeRow(final int index) {
    	if (index >= 0 && index < data.length) {
    		Object[][] newData = new Object[data.length - 1][2];
    		int newIndex = 0;
    		for (int i = 0; i < data.length; ++i) {
    			if (i == index) {
    				// La copia salta el indice a eliminar 
    				continue;
    			}
    			newData[newIndex][0] = data[i][0];
    			newData[newIndex][1] = data[i][1];
    			++newIndex;
    		}
    		data = newData;
    		fireTableRowsDeleted(index, index);
    	} else {
    		return;
    	}
    }
}
