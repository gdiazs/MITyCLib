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

import java.awt.Dimension;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JSeparator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreMaintainer;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.mitycstore.MITyCStore;

/**
 * Componente para la presentación de un diálogo de selección de certificados.
 * Emplea el almacén de certificados del Ministrio de Industria.
 * 
 */
public final class KSManagerDialog extends JDialog {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(KSManagerDialog.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Ancho del diálogo. */
	private static final int WIDTH = 600;
	/** Alto del diálogo. */
	private static final int HEIGHT = 500;
	
	// Componentes de la pantalla
	/** Barra de menú. */
	private JMenuBar menuBar = null;
	/** Opción "archivo". */
    private JMenu fileMenu = null;
    /** Opción "cargar". */
    private JMenuItem loadItem = null;
    /** Opción "salir". */
    private JMenuItem exitMenuItem = null;
    /** Opción "ayuda". */
    private JMenu helpMenu = null;
    /** Opción "mostrar". */
    private JMenuItem showHelpMenuItem = null;
    
    /** Botón indefinido. */
    private JButton acceptBtn = null;
    /** Botón "salir". */
	private JButton cancelBtn = null;
	
	/** barra separadora. */
	private JSeparator statusPanelSeparator = null;
	/** Panel de estado. */
	private JPanel statusPanel = null;
	/** Barra de progreso. */
    private JProgressBar progressBar = null;
	
    /** Instancia del panel de administración de certificados. */
    private KSManagerPanel ksmp = null;
    /** Padre del diálogo. */
    private Frame owner = null;
    
    /** Instancia del diálogo. */
	private static KSManagerDialog ksm = null;
	
	/**
	 * <p> devuelve una instancia de la ventana de adminsitración del almacén de certificado.</p>
	 * @param owner Ventana que invoca el diálogo
	 * @param modal Indica si es modal o no.
	 * @param pksm .- Clase de conexión con el Keystore
	 * @param pksma .- Clase de enlace con el administrador del KeyStore
	 * @return Instancia invisible de la ventana.
	 */
	public static KSManagerDialog getInstance(final Frame owner, final boolean modal, 
			final IPKStoreManager pksm, final IPKStoreMaintainer pksma) {
		if (ksm == null) {
			ksm = new KSManagerDialog(owner, modal, pksm, pksma);
		}
		
		return ksm;
	}
	
	/**
	 * <p>constructor del diálogo de administració.</p>
	 * @param own .- Padre del diálogo
	 * @param modal .- Establece si la pantalla es modal o no
	 * @param pksm .- Clase que implementa el acceso al Key Store
	 * @param pksma .- Clase que implementa las acciones que se pueden hacer sobre el Key Store
	 */
    private KSManagerDialog(Frame own, boolean modal, IPKStoreManager pksm, IPKStoreMaintainer pksma) {
		super(own, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_57), modal); // Almacén de certificados MITyC
		this.owner = own;
		dialogInit(pksm, pksma);
	}
	
    /**
     * <p>Inicializa y conecta con el panel de administración, el diálogo.</p>
     * @param pksm .- Clase que implementa el acceso al Key Store
	 * @param pksma .- Clase que implementa las acciones que se pueden hacer sobre el Key Store
     */
    protected void dialogInit(final IPKStoreManager pksm, final IPKStoreMaintainer pksma) {
    	try {
    	// Panel de administración
    		ksmp = new KSManagerPanel(owner, pksm, pksma);
    		
    	// Acciones
    		// Abre un certificado alternativo (en P12)
    		Action loadAction = new AbstractAction("load") {
				public void actionPerformed(final ActionEvent arg0) {
					File fichero = null;
					// Configuración a cargar
					FileDialog fd = new FileDialog(ksm, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_58), FileDialog.LOAD);
					fd.setFilenameFilter(new PropFilter());
					fd.setVisible(true);
					try {
						fichero = new File(fd.getFile());
					} catch (NullPointerException e) {
						// Cancelado por el usuario
						return;
					}
			    	if (fichero != null && fichero.exists()) {
			    		try {
			    			MITyCStore ksMityc = new MITyCStore(new FileInputStream(fichero.getAbsolutePath()), false);
			    			ksmp = new KSManagerPanel(owner, (IPKStoreManager) ksMityc, (IPKStoreMaintainer) ksMityc);
			    			ksmp.repaint();
			    		} catch (CertStoreException e) {
			    			// No se pudo inicializar el almacén. Compruebe su configuración
			    			// Faltan parámetros
			    			JOptionPane.showMessageDialog(ksm,
			    					I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_59),
			    					I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15),
			    					JOptionPane.ERROR_MESSAGE);
			    			return;
			    		} catch (FileNotFoundException e) {
			    			// No se pudo inicializar el almacén. Compruebe su configuración
			    			// Faltan parámetros
			    			JOptionPane.showMessageDialog(ksm,
			    					I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_59),
			    					I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15),
			    					JOptionPane.ERROR_MESSAGE);
			    			return;						}
			    	}
				}
            };
    		// Cierra el diálogo
         // Sale del diálogo
    		Action quitAction = new AbstractAction("quit") {
    			public void actionPerformed(final ActionEvent e) {
    				ksm.setVisible(false);
    				ksm.dispose();
    			}
    		};
    		// Muestra la ayuda
    		Action showHelpAction = new AbstractAction("showHelp") {
				public void actionPerformed(final ActionEvent arg0) {
				}
            };
    		
    		// Menu
    		menuBar = new JMenuBar();
    		menuBar.setName("menuBar");

    		fileMenu = new JMenu();
    		// Archivo
            fileMenu.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_60));
            fileMenu.setName("fileMenu");
            
            loadItem = new JMenuItem();
            loadItem.setAction(loadAction);
            // Cargar configuración
            loadItem.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_61));
            loadItem.setName("LoadMenuItem");
            fileMenu.add(loadItem);
            
            fileMenu.addSeparator();
            
            exitMenuItem = new JMenuItem();
            exitMenuItem.setAction(quitAction);
            // Salir
            exitMenuItem.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_62));
            exitMenuItem.setName("exitMenuItem");
            fileMenu.add(exitMenuItem);

            menuBar.add(fileMenu);

            helpMenu = new JMenu();
            // Ayuda
            helpMenu.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_63));
            helpMenu.setName("helpMenu");
            
            showHelpMenuItem = new JMenuItem();
            showHelpMenuItem.setAction(showHelpAction);
            showHelpMenuItem.setName("exitMenuItem");
            // Mostrar
            showHelpMenuItem.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_64));
            helpMenu.add(showHelpMenuItem);

            menuBar.add(helpMenu);
    		
            acceptBtn = new JButton();
    		acceptBtn.setAction(null);
    		acceptBtn.setMnemonic(KeyEvent.VK_ENTER);
    		// Otro botón
    		acceptBtn.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_65));
    		// FIXME: Invisibilizado hasta nueva funcionalidad
    		acceptBtn.setVisible(false);
    		
    		cancelBtn = new JButton();
    		cancelBtn.setAction(quitAction);
    		cancelBtn.setMnemonic(KeyEvent.VK_ESCAPE);
    		// Salir
    		cancelBtn.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_62));
    		
    		// Barra de estado
    		statusPanel = new JPanel();
    		statusPanelSeparator = new JSeparator();
    		progressBar = new JProgressBar();
    		
   		// Layouts
    		statusPanel.setLayout(new GridBagLayout());
    		
    		GridBagConstraints statusGrid = new GridBagConstraints();
    		statusGrid.gridx = 0;
    		statusGrid.gridy = 0;
    		statusGrid.gridwidth = 6;
    		statusGrid.fill = GridBagConstraints.HORIZONTAL;
    		statusGrid.weightx = 1.0;
    		statusGrid.insets = new Insets(0, 10, 0, 10);
    		statusPanel.add(statusPanelSeparator, statusGrid);
    		
    		GridBagConstraints progressGrid = new GridBagConstraints();
    		progressGrid.gridx = 0;
    		progressGrid.gridy = 1;
    		progressGrid.insets = new Insets(8, 480, 0, 10);
    		progressGrid.ipadx = 70;
    		statusPanel.add(progressBar, progressGrid);	
            
            setLayout(new GridBagLayout());
    		GridBagConstraints mainPanelGrid = new GridBagConstraints();
    		mainPanelGrid.gridx = 0;
    		mainPanelGrid.gridy = 0;
    		mainPanelGrid.gridwidth = 4;
    		mainPanelGrid.insets = new Insets(10, 10, 10, 10);
    		mainPanelGrid.fill = GridBagConstraints.BOTH;
    		mainPanelGrid.weightx = 1.0;
    		mainPanelGrid.weighty = 1.0;
    		add(ksmp, mainPanelGrid);
    		
    		GridBagConstraints accBtnGrid = new GridBagConstraints();
    		accBtnGrid.gridx = 2;
    		accBtnGrid.gridy = 1;
    		accBtnGrid.insets = new Insets(10, 130, 10, 10);
    		add(acceptBtn, accBtnGrid);
    		
    		GridBagConstraints cancBtnGrid = new GridBagConstraints();
    		cancBtnGrid.gridx = 3;
    		cancBtnGrid.gridy = 1;
    		cancBtnGrid.insets = new Insets(10, 20, 10, 10);
    		add(cancelBtn, cancBtnGrid);
    		
    		GridBagConstraints statusPanelGrid = new GridBagConstraints();
    		statusPanelGrid.gridx = 0;
    		statusPanelGrid.gridy = 2;
    		statusPanelGrid.gridwidth = 4;
    		statusPanelGrid.fill = GridBagConstraints.HORIZONTAL;
    		statusPanelGrid.weightx = 1.0;
    		statusPanelGrid.ipady = 10;
    		add(statusPanel, statusPanelGrid);
            
    	// Dialog
    		setJMenuBar(menuBar);
    		setBackground(ksmp.getBackground());
    		setLocationRelativeTo(owner);
    		setSize(WIDTH, HEIGHT);
    		if (owner == null) {
        		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
    			setLocation(screenSize.width / 2 - getWidth() / 2, screenSize.height / 2 - getHeight() / 2);
        	}
    		setResizable(false);
    		setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
    		addWindowListener(new WindowAdapter() {
    			@Override
    			public void windowClosing(final WindowEvent e) {
    				ksm.setVisible(false);
    				ksm.dispose();
    			}
    		});
    		
    		this.doLayout();
    		
    	} catch (Exception ex) {
    		ex.printStackTrace();
    		LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_66, ex.getMessage()));
    		if (LOG.isDebugEnabled()) {
    			LOG.debug(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_66), ex);
    		}
    	}
    }
    
    /**
     * Filtro de configuraciones para el MITyC Key Store Manager.
     */
    private class PropFilter implements FilenameFilter {
    	/**
    	 * Se aceptan ficheros de configuración con extensión .properties.
    	 * @param dir .- Ruta a el directorio
    	 * @param name .- Nombre del fichero
    	 * @return <code>true</code> si pasa el filtro
    	 */
		public boolean accept(final File dir, final String name) {
			return (name.endsWith(".properties"));
		}
	}

    /**
     * <p>Main de pruebas.</p>
     * @param args Fichero de configuración
     */
    public static void main(final String[] args) {
    	
    	File ficheroConf = new File(args[0]);
    	
    	try {
    		MITyCStore mks = MITyCStore.getInstance(ficheroConf, true);
    		KSManagerDialog manager = KSManagerDialog.getInstance(null, true, (IPKStoreManager) mks, (IPKStoreMaintainer) mks);
    		manager.setVisible(true);
    	} catch (CertStoreException e) {
    		e.printStackTrace();
    	}
    }
}
