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
package es.mityc.javasign.pkstore.mitycstore.PKHandlers;

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
 * Teclado virtual
 *
 */
public class VirtualQwerty {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	private static final String NOT_VISIBLE = "NoVisible";
	private static final String UNIR_SUPERIOR = "UnirSuperior";
	private static final String UNIR_IZQUIERDA = "UnirIzquierda";
	
	private static final String[] keyMatrixUpperCase = {
		"Esc","1","2","3","4","5","6","7","8","9","0","'","¡","Retroceso","/",
		"Tab","Q","W","E","R","T","Y","U","I","O","P","`","+","Intro",".",
		"Mayus","A","S","D","F","G","H","J","K","L","Ñ","´","Ç",UNIR_SUPERIOR,NOT_VISIBLE,
		"Shift","<","Z","X","C","V","B","N","M",",",".","-","Shift",NOT_VISIBLE,NOT_VISIBLE,
		"Ctrl","Alt",NOT_VISIBLE,"Espacio",UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,NOT_VISIBLE,"Alt",NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE};
	
	private static final String[] keyMatrixLowerCase = {
		"Esc","1","2","3","4","5","6","7","8","9","0","'","¡","Retroceso","/",
		"Tab","q","w","e","r","t","y","u","i","o","p","`","+","Intro",".",
		"Mayus","a","s","d","f","g","h","j","k","l","ñ","´","Ç",UNIR_SUPERIOR,NOT_VISIBLE,
		"Shift","<","z","x","c","v","b","n","m",",",".","-","Shift",NOT_VISIBLE,NOT_VISIBLE,
		"Ctrl","Alt",NOT_VISIBLE,"Espacio",UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,NOT_VISIBLE,"Alt",NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE};
	
	private static final String[] keyMatrixShiftCase = {
		"Esc","!","\"","·","$","%","&","/","(",")","=","?","¿","Retroceso","/",
		"Tab","","","","","","","","","","","^","*","Intro",".",
		"Mayus","","","","","","","","","","","¨","Ç",UNIR_SUPERIOR,NOT_VISIBLE,
		"Shift",">","","","","","","","",";",":","_","Shift",NOT_VISIBLE,NOT_VISIBLE,
		"Ctrl","Alt",NOT_VISIBLE,"Espacio",UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,NOT_VISIBLE,"Alt",NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE};
	
	private static final String[] keyMatrixAltCase = {
		"Esc","|","@","#","~","€","¬","7","8","9","0","'","¡","Retroceso","/",
		"Tab","","","","","","","","","","","[","]","Intro",".",
		"Mayus","","","","","","","","","","","{","}",UNIR_SUPERIOR,NOT_VISIBLE,
		"Shift","<","","","","","","","",",",".","-","Shift",NOT_VISIBLE,NOT_VISIBLE,
		"Ctrl","Alt",NOT_VISIBLE,"Espacio",UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,UNIR_IZQUIERDA,NOT_VISIBLE,"Alt",NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,NOT_VISIBLE,};
	
	private Frame owner = null;
	/**
     * <p>Construye los elementos de la ventana emergente.</p>
     * @param owner Frame propietario de la ventana
     */
    public VirtualQwerty(Frame owner) {
		dialog = new JDialog(owner, I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_TITLE), true);
		this.owner = owner;
		init();
	}
	
    private class HotKey {
    	public int[] posicion = new int[2];
    	public JButton tecla = null;

    	public HotKey(int x, int y, String text, int width, int height) {
    		posicion[0] = x;
    		posicion[1] = y;

    		tecla = new JButton(text);
    		tecla.setMargin(new Insets(0, 1, 1, 0));
    		tecla.setBackground(new Color(150, 217, 250));
    		tecla.setContentAreaFilled(false);
    		tecla.setSize(new Dimension(width, height));
    		tecla.setPreferredSize(new Dimension(width, height));
    		tecla.setMaximumSize(new Dimension(width, height));
    		tecla.setMinimumSize(new Dimension(width, height));
    		tecla.addMouseListener(
    				new MouseListener() {
    					public void mousePressed(MouseEvent e) {
    						JButton boton = (JButton)e.getSource();
    						String buttonText = boton.getText();
    						if (buttonText != null && buttonText.equalsIgnoreCase("SHIFT") ) {
    							if (boton.isContentAreaFilled()) {
    								boton.setContentAreaFilled(false);
    								changeKeyBoard(keyMatrixLowerCase);
    							} else {
    								boton.setContentAreaFilled(true);
    								changeKeyBoard(keyMatrixShiftCase);
    							}
    						} else if (buttonText != null && buttonText.equalsIgnoreCase("Mayus") ) {
    							if (boton.isContentAreaFilled()) {
    								boton.setContentAreaFilled(false);
    								changeKeyBoard(keyMatrixLowerCase);
    							} else {
    								boton.setContentAreaFilled(true);
    								changeKeyBoard(keyMatrixUpperCase);
    							}
    						} else if (buttonText != null && buttonText.equalsIgnoreCase("Retroceso") ) {
    							String password = new String(pass.getPassword());
    							int size = password.length() - 1;
    							if (size >= 0) {
    								pass.setText(password.substring(0, size));
    								System.out.println(new String(pass.getPassword()));
    							}
    						} else if (buttonText != null && buttonText.equalsIgnoreCase("Alt") ) {
    							if (boton.isContentAreaFilled()) {
    								boton.setContentAreaFilled(false);
    								changeKeyBoard(keyMatrixLowerCase);
    							} else {
    								boton.setContentAreaFilled(true);
    								changeKeyBoard(keyMatrixAltCase);
    							}
    						} else {
    							pass.setText(new String(pass.getPassword()) + boton.getText());
    							System.out.println(new String(pass.getPassword()));
    						}
    					}

    					public void mouseExited(MouseEvent e) {
    						mainPanel.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
    					}
    					public void mouseEntered(MouseEvent e) {
    						mainPanel.setCursor(new Cursor(Cursor.HAND_CURSOR));
    					}
    					public void mouseClicked(MouseEvent e) {}
    					public void mouseReleased(MouseEvent e) {}
    				});
    	}

    	public void changeKeyBoard(String[] newValue) {
    		int y = 1;
    		HotKey teclaItem = null;
    		for (int x = 1; y < 6; x++) {
    			String valueToShow = newValue[((x-1) + ((y-1)*15))];
    			teclaItem = teclado[((x-1) + ((y-1)*15))];
    			String before = null;
    			if (teclaItem == null) {
    				if (x > 14) {
    					x = 0;
    					++y;
    				}
    				continue;
    			} else {
    				before = teclaItem.tecla.getText();
    			}

    			if (before == null || before.equals(NOT_VISIBLE)
    					|| before.equals(UNIR_SUPERIOR)
    					|| before.equals(UNIR_IZQUIERDA)) {
    				if (x > 14) {
    					x = 0;
    					++y;
    				}
    				continue;
    			} else {		
    				teclaItem.tecla.setText(valueToShow);
    			}

    			if (x > 14) {
    				x = 0;
    				++y;
    			}
    		}
    	}
    };

	
	private void init() {
		teclado = new HotKey[15*5];		
		
		mainPanel = new JPanel();
		JButton aceptar = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_ACCEPT));
		JButton cancelar = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_CANCEL));

		aceptar.setActionCommand(STR_OK);
		cancelar.setActionCommand(STR_CLOSE);

		pass = new JPasswordField(15);
		GridBagConstraints g = new GridBagConstraints();
		mainPanel.setLayout(new GridBagLayout());

		g.insets = new Insets(5, 15, 3, 15);
		g.gridx = 0;
		g.gridy = 2;
		g.gridwidth = 1;
		g.fill = GridBagConstraints.NONE;
		g.weightx = 0.0;

		lblMessage = new JLabel(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_PIN));
		mainPanel.add(lblMessage, g, 0);

		g.gridy = 2;
		g.gridx = GridBagConstraints.RELATIVE;
		g.gridwidth = GridBagConstraints.REMAINDER;
		g.fill = GridBagConstraints.HORIZONTAL;
		g.weightx = 1.0;
		mainPanel.add(pass, g, 1);
		
		g.gridy = 3;
		g.gridx = 0;
		g.fill = GridBagConstraints.BOTH;
		g.weightx = 1.0;
		mainPanel.add(paintKeyBoard(keyMatrixLowerCase), g, 2);

		g.gridx = 0;
		g.gridy = 4;
		g.fill = GridBagConstraints.NONE;
		g.weightx = 0.0;
		g.gridwidth = 6;
		g.anchor = GridBagConstraints.WEST;

		mainPanel.add(aceptar, g, 3);

		g.gridx = GridBagConstraints.RELATIVE;
		g.gridy = 4;
		g.fill = GridBagConstraints.NONE;
		g.weightx = 0.0;
		g.gridwidth = GridBagConstraints.REMAINDER;
		g.anchor = GridBagConstraints.EAST;
		mainPanel.add(cancelar, g, 4);

		mainPanel.doLayout();
		dialog.add(mainPanel);
		dialog.setResizable(true);
		//dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
		dialog.getRootPane().setDefaultButton(aceptar);
		if (owner != null && false) {
			dialog.setLocationRelativeTo(owner);
		} else {
			// Posiciona la aplicación en el centro de la pantalla
	        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
	        dialog.setBounds((screenSize.width-660)/2, (screenSize.height-500)/2, 660, 500); 
		}

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
							System.exit(0);
						}
					}
				});
		dialog.setSize(new Dimension(900, 300));
				
		
	}
	
	private JPanel paintKeyBoard(String[] value) {
		HotKey tecla = null;
		Dimension teclaSize = new Dimension(40, 30);
		
		JPanel tecladoPanel = new JPanel();
		tecladoPanel.setLayout(new GridBagLayout());
		int y = 1;
		for (int x = 1; y < 6; x++) {
			String valueToShow = value[((x-1) + ((y-1)*15))];
			if (valueToShow.equals(NOT_VISIBLE)) {
				if (x > 14) {
					x = 0;
					++y;
				}
			} else if (valueToShow.equals(UNIR_SUPERIOR)) {
				// No se hace nada.
			} else {								
				int width = (int)teclaSize.getWidth();
				int celdasUnidas = 0;
				String nextElement = null;
				for(int neXt = x; neXt < 14; ++neXt) {
					nextElement = value[((neXt) + ((y-1)*15))];
					if (nextElement.equals(UNIR_IZQUIERDA)) {
						width = width + (int)teclaSize.getWidth();
						celdasUnidas++;
					} else {
						break;
					}
				}
				
				int height = (int)teclaSize.getHeight();
				int columnasUnidas = 0;
				for(int down = y; down < 5; ++down) {
					nextElement = value[((x-1) + ((down)*15))];
					if (nextElement.equals(UNIR_SUPERIOR)) {
						height = height + (int)teclaSize.getHeight();
						columnasUnidas++;
					} else {
						break;
					}
				}
				
				tecla = new HotKey(x, y, valueToShow, width, height);
				teclado[((x-1) + ((y-1)*15))] = tecla;
				
				GridBagConstraints g = new GridBagConstraints();
				g.insets = new Insets(1, 1, 0, 0);
				g.gridx = x;
				g.gridy = y;
				if (celdasUnidas > 0)
					g.gridwidth = celdasUnidas + 1;
				if (columnasUnidas > 0)
					g.gridheight = columnasUnidas + 1;
				tecladoPanel.add(tecla.tecla, g);
				
				x = x + celdasUnidas;
			}
			
			if (x > 14) {
				x = 0;
				++y;
			}
		}
		
		return tecladoPanel;
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
	
	private HotKey[] teclado = null;
	
	/** Panel principal del diálogo. */
	protected JPanel mainPanel = null;	
	/** Ventana de petición de contraseña. */
	protected JDialog dialog = null;
	/** Label de petición de contraseña. */
	protected JLabel lblMessage = null;
    /** Caja de texto del password. */
    private JPasswordField pass = null;
    /** Acción de aceptar la contraseña indtroducida. */
	private static final String STR_OK = "OK";
	/** Acción de cancelar la contraseña introducida. */
	private static final String STR_CLOSE = "CLOSE";
	/** Indica si el diálogo ha finalizado en cancelación. */
	private boolean cancelado = false;
	
	public static void main(String[] args) {
		VirtualQwerty vq = new VirtualQwerty(new JFrame());
		
		vq.setVisible(true);
	}
}
