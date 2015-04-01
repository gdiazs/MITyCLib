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

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
 * <p>Clase que muestra una nueva ventana modal con los datos en formato árbol
 * del certificado sobre el cual se ha hecho doble clic en los datos de firma.</p>
 * 
 */

public class DialogoCert extends JDialog {
	
	/** Logger. */
	Log logger = LogFactory.getLog(DialogoCert.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	/** Icono de información de certificados. */
	private static final String STR_ICON_CERT =	"/es/mityc/javasign/pkstore/mitycstore/Images/CertSmall.png";
	/** Ancho del diálogo. */
	private static final int WIDTH = 585;
	/** Alto del diálogo. */
	private static final int HEIGHT = 355;
	/** Certificado cuya información se va a mostrar. */
	private X509Certificate cert = null;
	/** Padre del diálogo. */
	private Frame owner = null;
	
	/** 
	 * <p>Constructor del diálogo.</p>
	 * @param ownr Padre del diálogo
	 */
    protected DialogoCert(Frame ownr) {    	
    	super(ownr, true);
    	this.owner = ownr;
    	dialogInit();
    }
    
    /**
     * <p>Inicializa el diálogo con los datos de entrada y lo muestra.</p>
     * @param certificate Certificado a mostrar
     */
    protected void muestraInfo(final X509Certificate certificate) {
    	this.cert = certificate;  	
    	muestraDialogo();
    }
    
    /**
     * <p<Construye el diálogo y lo hace visible.</p>
     */
    private void muestraDialogo() {
    	if (cert != null) {
	    	ImageIcon iconoCertificado = new ImageIcon(getClass().getResource(STR_ICON_CERT));
	    	if (iconoCertificado != null) {
	    		DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
	    		renderer.setLeafIcon(iconoCertificado);
	    		renderer.setOpenIcon(iconoCertificado);
	    		renderer.setClosedIcon(iconoCertificado);
	    		renderer.setBorder(BorderFactory.createLineBorder(new Color(0, 0, 0, 0), 2)); // Margen transparente de dos pixels
	    		jTreeDatoCertificado.setCellRenderer(renderer);
	    	}
	    	
	    	// Certificado
	    	DefaultMutableTreeNode root = new DefaultMutableTreeNode(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_50));
	    	
	    	// Se escriben los datos del certificado de firma
	    	CertificadoModeloTree cmt = new CertificadoModeloTree(root, cert);
	    	jTreeDatoCertificado.setModel(cmt);
	    	cmt.reload();
	    	setVisible(true);
	    	jTreeDatoCertificado.validate();
	    	jTreeDatoCertificado.repaint();
	    	
	    	// Se expanden y bloquean los nodos
	    	int rows = jTreeDatoCertificado.getRowCount();
	    	for (int i = 0; i < rows - 1; ++i) {
	    		jTreeDatoCertificado.expandRow(i);
	    	}
	    	
    	} else {
    		logger.debug("No se recibió el certificado");
    	}
    }
	
	 /**
     * Inicialización de los componentes visuales.
     */
    @Override
	protected void dialogInit() {
    	super.dialogInit();
    	panPrincipal = new JPanel();
        jDatosCertificadoScrollPane = new JScrollPane();
        jTreeDatoCertificado = new JTree();
   
        jCerrarButton = new JButton();
        jExportarCertificadoButton = new JButton();
        
        setLayout(new GridBagLayout());
        panPrincipal.setLayout(new GridBagLayout());
        
        // Diálogo Datos del Certificado       
		GridBagConstraints datosCertificadoScrollPaneConstraints = new GridBagConstraints();
		datosCertificadoScrollPaneConstraints.gridx = 0;
		datosCertificadoScrollPaneConstraints.gridy = 1;
		datosCertificadoScrollPaneConstraints.weightx = 1.0;
		datosCertificadoScrollPaneConstraints.weighty = 1.0;
		datosCertificadoScrollPaneConstraints.gridwidth = 4;
		datosCertificadoScrollPaneConstraints.fill = GridBagConstraints.BOTH;
		datosCertificadoScrollPaneConstraints.insets = new Insets(10, 10, 10, 10);
		// Datos del certificado
		jDatosCertificadoScrollPane.setBorder(BorderFactory.createTitledBorder(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_51)));
        jDatosCertificadoScrollPane.setViewportView(jTreeDatoCertificado);

		GridBagConstraints cerrarButtonConstraints = new GridBagConstraints();
		cerrarButtonConstraints.gridx = 1;
		cerrarButtonConstraints.gridy = 2;
		cerrarButtonConstraints.insets = new Insets(0, 225, 10, 10);
        jCerrarButton.setText("Cerrar");
        jCerrarButton.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
                jCerrarButtonActionPerformed();
            }
        });
        
        GridBagConstraints exportarButtonConstraints = new GridBagConstraints();
        exportarButtonConstraints.gridx = 2;
        exportarButtonConstraints.gridy = 2;
        exportarButtonConstraints.insets = new Insets(0, 78, 10, 0);
        // Exportar
        jExportarCertificadoButton.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_52));
        jExportarCertificadoButton.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt)  {
                jExportarCertButtonActionPerformed(cert);
            }
        });
        
        panPrincipal.add(jDatosCertificadoScrollPane, datosCertificadoScrollPaneConstraints);
        panPrincipal.add(jCerrarButton, cerrarButtonConstraints);
        panPrincipal.add(jExportarCertificadoButton, exportarButtonConstraints);
        
        GridBagConstraints panPrincipalConstraints = new GridBagConstraints();
        panPrincipalConstraints.fill = GridBagConstraints.BOTH;
        panPrincipalConstraints.weightx = 1.0;
        panPrincipalConstraints.weighty = 1.0;
        
        add(panPrincipal, panPrincipalConstraints);

        // Certificado
        setTitle(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_50));
        setSize(WIDTH, HEIGHT);
    	setLocationRelativeTo(owner);
    	if (owner == null) {
    		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
			setLocation(screenSize.width / 2 - getWidth() / 2, screenSize.height / 2 - getHeight() / 2);
    	}
    	setModal(true);
        setResizable(false);
    }
    
    /**
     * <p>Cierra la ventana donde se muestran los datos del certificado seleccionado.</p>
     */
    private void jCerrarButtonActionPerformed() {
    	setVisible(false);
    	dispose();
    }
    
    /**
     * <p>Exporta a un soporte físico el certificado seleccionado.</p>
     * @param certMostrado .- Certificado a exportar
     */
    private void jExportarCertButtonActionPerformed(final X509Certificate certMostrado) {
    	String destino = null;
    	// Se pide la ruta sobre la que guardar el certifiado
    	JFileChooser chooser = new JFileChooser();
    	// Exportar certificado
		chooser.setDialogTitle(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_53));
	    chooser.setFileFilter(new CertsFilter(true));
	    chooser.setDialogType(JFileChooser.SAVE_DIALOG);
	    // Exportar
	    int returnVal = chooser.showDialog(owner, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_52));
	    if (returnVal == JFileChooser.APPROVE_OPTION) {
	    	destino = chooser.getSelectedFile().getAbsolutePath();
	    }
    	
    	if (destino == null) {		
    		return;
    	} else if (!destino.contains(".")) {
    		destino = destino + ".cer";
    	} else {
    		destino = destino.substring(0, destino.lastIndexOf(".")) + ".cer";
    	}
    	
    	if (certMostrado == null) {
    		logger.debug("No se recibió el certificado");
    		JOptionPane.showMessageDialog(this, 
    				// El certificado no existe en el almacén
    				I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_16),
    				// Exportar
    				I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_52),
					JOptionPane.ERROR_MESSAGE);
    		return;
    	}
    	
    	// Se salva el certificado seleccionado
    	BufferedOutputStream f = null;
		try {
			f = new BufferedOutputStream(new FileOutputStream(destino));
			f.write(certMostrado.getEncoded()); // Certificado guardado
			f.flush();
		} catch (FileNotFoundException e) {
			// No se pudo salvar. No se encuentra el destino
			logger.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_54), e);
		} catch (IOException e) {
			// No se pudo salvar. Hubo un error de escritura
			logger.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_55), e);
		} catch (CertificateEncodingException e) {
			// No se pudo salvar. Error de codificación del certificado
			logger.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_56), e);
		} finally {
			try {
				if (f != null) {
					f.close();
				}
			} catch (IOException e) { /* No se hace nada */ }
		}
    }
    
	// Declaración de los componentes visuales.
	/** Panel principal. */
    private JPanel panPrincipal = null;
	/** Botón para cerrar el diálogo. */
	private JButton jCerrarButton = null;
	/** Botón para exportar el certificado. */
	private JButton jExportarCertificadoButton = null;
	/** ScrollPane para el panel de datos. */
    private JScrollPane jDatosCertificadoScrollPane = null;
    /** Árbol de datos del certificado. */
    private JTree jTreeDatoCertificado = null;
}
