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
package es.mityc.javasign.pkstore.mitycstore;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
 * Clase que muestra una nueva ventana modal con los datos en formato árbol
 * del certificado sobre el cual se ha hecho doble clic en los datos de firma.
 * 
 */

public class PKContextDialog extends JDialog {
	
	/** logger. */
	Log logger = LogFactory.getLog(PKContextDialog.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Instancia del alamcén. */
	private MITyCStore ks = null;
	
	/** Padre del diálogo. */
	private Frame owner = null;
	
	/**
	 * <p>Constructor. Muestra el diálogo de configuración del contexto de clave.</p> 
	 * @param ownerFrame Padre del diálogo
	 * @param keyStore KeyStore asociado
	 */
    protected PKContextDialog(final Frame ownerFrame, final MITyCStore keyStore) {    	
    	super(ownerFrame);
    	this.owner = ownerFrame;
    	this.ks = keyStore;
    	dialogInit();
    }
    
    /**
     * <p>Devuelve el código que se corresponde con la configuración introducida.</p>
     * @return El prefijo del alias según la configuración introducida
     */
    protected String getContext() {
    	MITyCStore.AliasFormat context = ks.new AliasFormat("");
    	boolean isPro = protectedRadio.isSelected();
    	boolean isCached = cachedCheck.isSelected();
    	boolean mayWarn = alertCheck.isSelected();
    	
    	return context.genAliasPrefix(isPro, isCached, mayWarn);
    }
    
    /**
     * <p>Devuelve la contraseña que será empleada para proteger la clave.</p>
     * @return La contraseña introducida por el usuario
     */
    protected char[] getPass() {
    	 return passField.getPassword();
    }
	
	 /**
     * Inicialización de los componentes visuales.
     */
    @Override
	protected void dialogInit() {
    	super.dialogInit();
    	panPrincipal = new JPanel();
    	// Contexto de clave
    	panPrincipal.setBorder(BorderFactory.createTitledBorder(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_18)));
    	
    	// Protegido con contraseña
        protectedRadio = new JRadioButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_19));
        // Contraseña
        passLabel = new JLabel(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_20));
        passField = new JPasswordField();
        // Sólo pedir la primera vez
        cachedCheck = new JCheckBox(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_21));
        // No protegido con contraseña
        unprotectedRadio = new JRadioButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_22));
        // Alertar en su uso
        alertCheck = new JCheckBox(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_23));
        
        aceptarButton = new JButton();
        
        ButtonGroup group = new ButtonGroup();
        group.add(protectedRadio);
        group.add(unprotectedRadio);
        
        protectedRadio.addChangeListener(new ChangeListener() {
			public void stateChanged(final ChangeEvent e) {
				boolean sel = ((JRadioButton) e.getSource()).isSelected();
				passLabel.setEnabled(sel);
				passField.setEnabled(sel);
				cachedCheck.setEnabled(sel);
				
				panPrincipal.repaint();
			}
        });
        
        unprotectedRadio.addChangeListener(new ChangeListener() {
        	public void stateChanged(final ChangeEvent e) {
				alertCheck.setEnabled(((JRadioButton) e.getSource()).isSelected());
				
				panPrincipal.repaint();
			}
        });
        
        // Se inicializa
        protectedRadio.setSelected(true);
        alertCheck.setEnabled(false);
        
        this.setLayout(new GridBagLayout());
        panPrincipal.setLayout(new GridBagLayout());
        
        // Diálogo Datos del Certificado       
		GridBagConstraints protectedRadioConstraints = new GridBagConstraints();
		protectedRadioConstraints.gridx = 0;
		protectedRadioConstraints.gridy = 0;
		protectedRadioConstraints.weightx = 1.0;
		protectedRadioConstraints.gridwidth = 4;
		protectedRadioConstraints.fill = GridBagConstraints.HORIZONTAL;
		protectedRadioConstraints.insets = new Insets(3, 10, 0, 0);
		panPrincipal.add(protectedRadio, protectedRadioConstraints);
		
		GridBagConstraints passLabelConstraints = new GridBagConstraints();
		passLabelConstraints.gridx = 1;
		passLabelConstraints.gridy = 1;
		passLabelConstraints.insets = new Insets(3, 30, 0, 5);
		panPrincipal.add(passLabel, passLabelConstraints);
		
		GridBagConstraints passFieldConstraints = new GridBagConstraints();
		passFieldConstraints.gridx = 2;
		passFieldConstraints.gridy = 1;
		passFieldConstraints.weightx = 1.0;
		passFieldConstraints.gridwidth = 2;
		passFieldConstraints.fill = GridBagConstraints.HORIZONTAL;
		passFieldConstraints.insets = new Insets(3, 0, 2, 20);
		panPrincipal.add(passField, passFieldConstraints);
		
		GridBagConstraints cachedCheckConstraints = new GridBagConstraints();
		cachedCheckConstraints.gridx = 2;
		cachedCheckConstraints.gridy = 2;
		cachedCheckConstraints.weightx = 1.0;
		cachedCheckConstraints.weighty = 1.0;
		cachedCheckConstraints.gridwidth = 4;
		cachedCheckConstraints.fill = GridBagConstraints.HORIZONTAL;
		panPrincipal.add(cachedCheck, cachedCheckConstraints);
		
		GridBagConstraints unprotectedRadioConstraints = new GridBagConstraints();
		unprotectedRadioConstraints.gridx = 0;
		unprotectedRadioConstraints.gridy = 3;
		unprotectedRadioConstraints.weightx = 1.0;
		unprotectedRadioConstraints.gridwidth = 4;
		unprotectedRadioConstraints.fill = GridBagConstraints.HORIZONTAL;
		unprotectedRadioConstraints.insets = new Insets(5, 10, 0, 0);
		panPrincipal.add(unprotectedRadio, unprotectedRadioConstraints);
		
		GridBagConstraints alertCheckConstraints = new GridBagConstraints();
		alertCheckConstraints.gridx = 2;
		alertCheckConstraints.gridy = 4;
		alertCheckConstraints.weightx = 1.0;
		alertCheckConstraints.gridwidth = 2;
		alertCheckConstraints.fill = GridBagConstraints.HORIZONTAL;
		panPrincipal.add(alertCheck, alertCheckConstraints);

		GridBagConstraints aceptarButtonConstraints = new GridBagConstraints();
		aceptarButtonConstraints.gridx = 2;
		aceptarButtonConstraints.gridy = 5;
		aceptarButtonConstraints.insets = new Insets(30, 60, 10, 0);
        // Aceptar
		aceptarButton.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_ACCEPT));
        aceptarButton.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
                jAceptarButtonActionPerformed();
            }
        });
        panPrincipal.add(aceptarButton, aceptarButtonConstraints);

        // Panel Principal
        GridBagConstraints panPrincipalConstraints = new GridBagConstraints();
        panPrincipalConstraints.fill = GridBagConstraints.BOTH;
        panPrincipalConstraints.weightx = 1.0;
        panPrincipalConstraints.weighty = 1.0;
        
        add(panPrincipal, panPrincipalConstraints);

        // Clave privada
        setTitle(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_24));
        setSize(400, 250);
    	setLocationRelativeTo(owner);
    	if (owner == null) {
    		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
			setLocation(screenSize.width / 2 - getWidth() / 2, screenSize.height / 2 - getHeight() / 2);
    	}
    	setModal(true);
        setResizable(false);
    }
    
    /**
     * Cierra la ventana donde se muestran los datos del certificado seleccionado.
     * @param evt
     */
    private void jAceptarButtonActionPerformed() {
    	setVisible(false);
    	dispose();
    }
    
	// Declaración de los componentes visuales.
	/** Panel principal. */
    private JPanel panPrincipal = null;
	
    /** Botón para aceptar. */
	private JButton aceptarButton = null;
	
	/** RadioButton para indicar protección por password. */
	private JRadioButton protectedRadio = null;
	/** RadioButton para dehabilitar la protección por password. */ 
	private JRadioButton unprotectedRadio = null;
	
	/** Etiqueta "Contraseña". */
	private JLabel passLabel = null;
	/** Campo para la introducción de la contraseña. */
	private JPasswordField passField = null;
	
	/** CheckBox para que la contraseña sólo se pida una vez. */ 
	private JCheckBox cachedCheck = null;
	/** CheckBox para que se alerte en los accesos a la clave privada. */
	private JCheckBox alertCheck = null;
}
