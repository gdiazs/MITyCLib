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
import java.util.Date;

import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.mitycstore.CertUtil;

/**
 * <p>Modelo visual de la estructura árbol que muestra los datos del certificado.</p>
 *
 */
public class CertificadoModeloTree extends DefaultTreeModel   {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/**
	 * Implementa el modelo de datos encargado de extraer la información indicada en el 
	 * certificado pasado como argumento.
	 * @param root .- Nodo raíz del árbol
	 * @param cert .- Certificado dle que se obtendrá su información
	 */
	public CertificadoModeloTree(DefaultMutableTreeNode root, X509Certificate cert) {
		super(root);
		
		String datos = "";
		
		// Propietario:
		DefaultMutableTreeNode sujeto = new DefaultMutableTreeNode(new TypeTreeNode(
				I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_25,
        		CertUtil.extractName(cert.getSubjectX500Principal().getName())),
				null));
		
		// Nombre completo:
		DefaultMutableTreeNode sujetoDN = new DefaultMutableTreeNode(new TypeTreeNode(
				I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_26, cert.getSubjectDN()),
				null));
		
		sujeto.add(sujetoDN);
	    root.add(sujeto);
	    
	    // Emisor:
	    DefaultMutableTreeNode emisor = new DefaultMutableTreeNode(new TypeTreeNode(
	    		I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_27,
	    		CertUtil.extractName(cert.getIssuerX500Principal().getName())),
				null));
	    
	    // Nombre completo:
	    DefaultMutableTreeNode emisorDN = new DefaultMutableTreeNode(new TypeTreeNode(
	    		I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_26, cert.getIssuerDN()),
				null));
		
		emisor.add(emisorDN);
	    root.add(emisor);
	    
	    String aviso = "";
	    if ((new Date()).before(cert.getNotBefore())) {
	    	//  Certificado aún no válido
	    	aviso = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_32);
	    }
	    if ((new Date()).after(cert.getNotAfter())) {
	    	//  Certificado caducado
	    	aviso = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_33);
	    }

	    // Desde {0} hasta {1}
	    datos = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_34, CertUtil.convertDate(cert.getNotBefore()),
	    	CertUtil.convertDate(cert.getNotAfter())) + aviso;
	    
	    // Validez:
	    DefaultMutableTreeNode validez = new DefaultMutableTreeNode(new TypeTreeNode(
	    		I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_28, datos),
				null));
  
	    root.add(validez);
	    
	    datos = cert.getSerialNumber().toString();
	    
	    // Nº de serie: 
	    DefaultMutableTreeNode nroSerie = new DefaultMutableTreeNode(new TypeTreeNode(
	    		I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_29, datos),
				null));
 
	    root.add(nroSerie);
        
		//Usos del certificado: 
		//F Firma digital,N no repudio, Cc cifrado de claves, 
		//Cd cifrado de datos, Ac Acuerdo de claves, Fc Firma de certificados, 
		//Fcrl Firma de CRL, Sc Solo cifrado, Sf solo firma

        StringBuilder claveUsoString = new StringBuilder("");
		String[] clavesUsadasArray = new String[9];
		
		// Firma digital
		clavesUsadasArray [0] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_35);
		// No repudio
		clavesUsadasArray [1] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_36);
		// Cifrado de claves
		clavesUsadasArray [2] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_37);
		// Cifrado de datos
		clavesUsadasArray [3] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_38);
		// Acuerdo de claves
		clavesUsadasArray [4] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_39);
		// Firma de certificados
		clavesUsadasArray [5] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_40);
		// Firma de CRL
		clavesUsadasArray [6] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_41);
		// Sólo cifrado
		clavesUsadasArray [7] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_42);
		// Sólo firma
		clavesUsadasArray [8] = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_43);

        // AppPerfect: Falso Positivo
		boolean[] claveUso = cert.getKeyUsage();
		if (claveUso != null) {
			for (int z = 0; z < claveUso.length; z++) {
				if (claveUso[z]) {
					claveUsoString.append(clavesUsadasArray[z]);
					claveUsoString.append(", ");
				}
			}
			claveUsoString.deleteCharAt(claveUsoString.length() - 1);
		} else {
			// No definido
			claveUsoString.append(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_44));
		}	
		
		// Usos:
	    DefaultMutableTreeNode uso = new DefaultMutableTreeNode(new TypeTreeNode(
	    		I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_30, claveUsoString.toString()),
				null));
  
	    root.add(uso);
	    
	    try {
	    	datos = cert.getSigAlgName();
	    } catch (Throwable t) {
	    	// Sin datos
	    	datos = I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_45);
	    }
	    
	    // Algoritmo de firma: 
	    DefaultMutableTreeNode algoritmo = new DefaultMutableTreeNode(new TypeTreeNode(
	    		I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_31, datos),
				null));
           
	    root.add(algoritmo);
	}
}
