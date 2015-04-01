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

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.List;

import javax.swing.table.AbstractTableModel;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.mitycstore.CertUtil;

/**
 * <p>Modelo visual de la tabla de certificados.</p>
 *
 */
public class CertTblModel extends AbstractTableModel {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/**
	 * Enumerado para referirse a emisor o al receptor del certificado.
	 */
	public enum SUBJECT_OR_ISSUER {
		/** Propietario del certificado. */
		SUBJECT, 
		/** Emisor del certificado. */
		ISSUER
	};
	
	/** Nombres de los campos a mostrar. */
    private String[] columnNames = null;
    /** Datos obtenidos del certificado. */
    private Object[][] data = null;

    /**
     * <p>Constructor por defecto.</p>
     * @param listCertificates Vector con los objetos X509Certificate a mostrar en la tabla.
     */
    public CertTblModel(final List<X509Certificate> listCertificates) {

    	columnNames = new String[3];
    	// Emitido para
        columnNames[0] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_47);
        // Emitido por
        columnNames[1] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_48);
        // Fecha de caducidad
        columnNames[2] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_49);
    	int rows = 0;
    	if (listCertificates != null) {
    		rows = listCertificates.size();
    	}
    	data = new Object[rows][4];
    	SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
    	X509Certificate certTemp = null;
    	for (int a = 0; a < rows; a++) {
    		certTemp = (X509Certificate) listCertificates.get(a);

    		//Emitido para
    		data[a][0] = getName(certTemp, SUBJECT_OR_ISSUER.SUBJECT);

    		//Emitido por
    		data[a][1] = getName(certTemp, SUBJECT_OR_ISSUER.ISSUER);

    		//Fecha de caducidad
    		data[a][2] = sdf.format(certTemp.getNotAfter());
    		
    		//Oculto.- Certificado
    		data[a][3] = certTemp;    		
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
        return data[fil][col];
    }
    
    /**
     * <p> Devuelve el certificado asociado a la celda.</p>
     * @param row .- Fila buscada.
     * @return Certificado asociado a la fila.
     */
    public X509Certificate getCertificate(final int row) {
    	if (row >= 0 && row < getRowCount()) {
    		return (X509Certificate) data[row][3];
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
     * <p>Obtiene el CN, o en su lugar OU, ó O.</p>
     * 
     * @param cert X509Certificate Certificado del cual se obtiene el nombre
     * @param tipo Tipo de nombre requerido
     * @return String Nombre obtenido 
     */
    private String getName(final X509Certificate cert, final SUBJECT_OR_ISSUER tipo) {
    	
    	String retorno = "";
    	
    	// Se discrimina que tipo de certificado es requerido
    	if (tipo == SUBJECT_OR_ISSUER.ISSUER) {
    		retorno = CertUtil.extractName(cert.getIssuerX500Principal());
    	} else {
    		retorno = CertUtil.extractName(cert.getSubjectX500Principal());
    	}
    	
		return retorno;
    }
}
