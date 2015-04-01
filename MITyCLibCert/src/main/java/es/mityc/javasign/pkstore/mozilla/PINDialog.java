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
package es.mityc.javasign.pkstore.mozilla;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
 * <p>Ventana emergente de petición de contraseña.</p>
 * 
 */

public class PINDialog {
	
//	private static final Log logger = LogFactory.getLog(PINDialog.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/** Acción de aceptar la contraseña indtroducida. */
	private static final String STR_OK = "OK";
	/** Acción de cancelar la contraseña introducida. */
	private static final String STR_CLOSE = "CLOSE";

	/** Indica si el diálogo ha finalizado en cancelación. */
	private boolean cancelado = false;
	/** Ventana de petición de contraseña. */
	protected JDialog dialog = null;
	/** Label de petición de contraseña. */
	protected JLabel lblMessage = null;
    /** Caja de texto del password. */
    private JPasswordField pass = null;
    	
    /**
     * <p>Construye los elementos de la ventana emergente.</p>
     * @param owner Frame propietario de la ventana
     */
    public PINDialog(Frame owner) {
		dialog = new JDialog(owner, I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_TITLE), true);
		dialogInit();
	}
    
    /**
     * <p>Inicializa los elementos de la ventana.</p>
     */
    protected void dialogInit() {
    	try {
    		JPanel distr = new JPanel();
    		JButton aceptar = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_ACCEPT));
    		JButton cancelar = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_CANCEL));

    		aceptar.setActionCommand(STR_OK);
    		cancelar.setActionCommand(STR_CLOSE);

    		pass = new JPasswordField(15);
    		GridBagConstraints g = new GridBagConstraints();
    		distr.setLayout(new GridBagLayout());
    		dialog.setResizable(false);

    		g.insets = new Insets(5, 15, 3, 15);
    		g.gridx = 0;
    		g.gridy = 2;
    		g.gridwidth = 1;
    		g.fill = GridBagConstraints.NONE;
    		g.weightx = 0.0;

    		lblMessage = new JLabel(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_PIN));
    		distr.add(lblMessage, g);

    		g.gridy = 2;
    		g.gridx = GridBagConstraints.RELATIVE;
    		g.gridwidth = GridBagConstraints.REMAINDER;
    		g.fill = GridBagConstraints.HORIZONTAL;
    		g.weightx = 1.0;
    		distr.add(pass, g);

    		g.gridx = 0;
    		g.gridy = 3;
    		g.fill = GridBagConstraints.NONE;
    		g.weightx = 0.0;
    		g.gridwidth = 6;
    		g.anchor = GridBagConstraints.WEST;

    		distr.add(aceptar, g);

    		g.gridx = GridBagConstraints.RELATIVE;
    		g.gridy = 3;
    		g.fill = GridBagConstraints.NONE;
    		g.weightx = 0.0;
    		g.gridwidth = GridBagConstraints.REMAINDER;
    		g.anchor = GridBagConstraints.EAST;
    		distr.add(cancelar, g);

    		distr.doLayout();
    		dialog.add(distr);
    		dialog.setResizable(false);
    		dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
    		dialog.getRootPane().setDefaultButton(aceptar);
    		dialog.setLocationRelativeTo(null);

    		aceptar.addActionListener(
    				new ActionListener() {
    					public void actionPerformed(final ActionEvent e) {
    						if (e.getActionCommand().equals(STR_OK)) {
    							dialog.setVisible(false);
    						}
    					}
    				});

    		cancelar.addActionListener(
    				new ActionListener() {
    					public void actionPerformed(final ActionEvent e) {
    						if (e.getActionCommand().equals(STR_CLOSE)) {
    							cancelado = true;
    							dialog.setVisible(false);
    						}
    					}
    				});
    		dialog.setSize(new Dimension(300, 300));
    	} catch (Exception e) {
    		// Nunca se produce
    		e.printStackTrace();
    	}
    }
	
	/**
	 * <p>Establece el título de la ventana.</p>
	 * @param newTitle Nuevo título
	 */
    public void setTitle(final String newTitle) {
		dialog.setTitle(newTitle);
	}
	
	/**
	 * <p>Establece el mensaje de tipo de contraseña esperada.</p>
	 * @param newMessage nuevo mensaje
	 */
    public void setPINMessage(final String newMessage) {
		lblMessage.setText(newMessage);
	}
	
	/**
	 * <p>Reajusta los elementos para su representación.</p>
	 */
    public void pack() {
		dialog.pack();
	}
	
	/**
	 * <p>Establece la visibilidad de la ventana.</p>
	 * <p>Marcando a <code>true</code> se muestra la ventana, y marcando a <code>false</code> se oculta la ventana y se resetea la contraseña.</p>
	 * 
	 * @param flag <code>true</code> muestra la ventana, <code>false</code> la oculta
	 */
    public void setVisible(final boolean flag) {
		if (flag) {
			cancelado = false;
			pass.setText("");
		}
		dialog.setVisible(flag);
	}
	
	/**
	 * <p>Devuelve la contraseña introducida en la ventana.</p>
	 * @return contraseña introducida
	 */
    public char[] getPassword() {
		return pass.getPassword();
	}
	
	/**
	 * <p>Libera recursos.</p>
	 */
    public void dispose() {
		dialog.dispose();
	}

	/**
	 * <p>Indica si se canceló la introducción de la contraseña.</p>
	 * @return <code>true</code> si se canceló la introducción de la contraseña, <code>false</code> en otro caso
	 */
    public boolean isCancelado() {
		return cancelado;
	}

}
