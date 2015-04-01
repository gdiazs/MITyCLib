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
import java.awt.EventQueue;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.TransferHandler;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreMaintainer;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.mitycstore.PKHandlers.PlainPassHandler;

/**
 * <p>Componente para la presentación de un panel de administración de certificados.
 * Emplea el almacén de certificados del Ministrio de Industria.</p>
 * 
 */
public class KSManagerPanel extends JPanel {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(KSManagerDialog.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Interfaz para el Key Store. */
	private IPKStoreManager pksm = null;
	/** Interfaz para el administrador del Key Store. */
	private IPKStoreMaintainer pksma = null;
	
	/** Lista de certificados de firma. */
	private List<X509Certificate> signCerts = new ArrayList<X509Certificate>();
	/** Lista de certificados de autenticación. */
	private List<X509Certificate> authCerts = new ArrayList<X509Certificate>();
	
	// Componentes del panel.
	/** Panel de certificados de firma. */
	private JPanel signPanel = null;
	/** Panel de certificados de autenticación. */
	private JPanel authPanel = null;
	/** Paner para el botón de preferencias. */
	private JPanel prefPanel = null;
	/** Pestañas. */
	private JTabbedPane tabs = null;
	/** ScrollPane para el panel de certificados de firma. */
	private JScrollPane scrollPaneSign = null;
	/** ScrollPane para el panel de certificados de autenticación. */
	private JScrollPane scrollPaneAuth = null;
	/** Tabla de certificados de firma. */
	private JTable signCrtTbl = null;
	/** Tabla de certificados de autenticación. */
	private JTable authCrtTbl = null;
	/** Botón de actualización de certificados de firma. */
	private JButton updateSignBtn = null;
	/** Botón para borrar certificados de firma. */
	private JButton deleteSignBtn = null;
	/** Botón para importar un certificado de firma. */
	private JButton addSignBtn = null;
	/** Botón de actualización de certificados de autenticaciön. */
	private JButton updateAuthBtn = null;
	/** Botón para borrar certificados de autenticación. */
	private JButton deleteAuthBtn = null;
	/** Botón para importar un certificado de autenticación. */
	private JButton addAuthBtn = null;
	/** Botón para mostrar las preferencias de configuración. */
	private JButton showPreferences = null;
    
	/** Diálogo de información de certificados. */
    private DialogoCert dc = null;
    
    /** Instancia del padre. */
    private Frame ownerFrame = null;
    
    /** Instancia propia. */
    private KSManagerPanel ksmp = null;
    
    /**
	 * Enumerado para referirse a acciones para firma o para autenticación.
	 */
	public enum ACTION_FOR {
		/** Firma. */
		SIGN, 
		/** Autenticación. */
		AUTH
	};
	
	/**
	 * <p>Constructor del panel de administración de certificados.</p>
	 * @param owner .- Padre del panel
	 * @param pksManager .- Clase que implementa el acceso al Key Store
	 * @param pksMaintainer .- Clase que implementa las acciones que se pueden hacer sobre el Key Store
	 */
    public KSManagerPanel(Frame owner, IPKStoreManager pksManager, IPKStoreMaintainer pksMaintainer) {
		super();
		this.ownerFrame = owner;
		this.pksm = pksManager;
		this.pksma = pksMaintainer;
		loadKeyStore();
		panelInit();
	}
    
    /**
     * <p> Indica cual es la lista de certificado a mostrar en "Personales".</p>
     * @param certs Lista de certificados para firma.
     */
    public void setSignCertificates(final List<X509Certificate> certs) {
    	this.signCerts = certs;
    	signCrtTbl.setModel(new CertTblModel(certs));
    	repaint();
    	
    	ksmp = this;
    }
    
    /**
     * <p> Indica cual es la lista de certificados a mostrar en "Autoridades".</p>
     * @param certs Lista de certificados para autenticación.
     */
    public void setAuthCertificates(final List<X509Certificate> certs) {
    	this.authCerts = certs;
    	authCrtTbl.setModel(new CertTblModel(certs));
    	repaint();
    }
    
    /**
     * <p>Inicializa el panel.</p>
     */
    protected void panelInit() {
    	// Sale del adminsitrador
		Action cancelAction = new AbstractAction("cancel") {
			public void actionPerformed(final ActionEvent e) {
				signCrtTbl.clearSelection();
				authCrtTbl.clearSelection();
			}
		};
		// Abre el diálogo de información de certificados
		Action showInfo = new AbstractAction("showInfo") {
			public void actionPerformed(final ActionEvent e) {
				JTable source = (JTable) e.getSource();
				X509Certificate cert = ((CertTblModel) source.getModel()).getCertificate(source.getSelectedRow());
				dc.muestraInfo(cert);
			}
		};
    	
    	 // Diálogo de certificados
        dc = new DialogoCert(ownerFrame);

		// Paneles
		signPanel = new JPanel();
		authPanel = new JPanel();
		prefPanel = new JPanel();
		
		// Pestañas
		tabs = new JTabbedPane();
		// Certificados propios
		tabs.addTab(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_67), signPanel);
		// Autoridades de confianza
		tabs.addTab(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_68), authPanel);
		
		// Tabla de certificados personales 
		signCrtTbl = new JTable();
		signCrtTbl.setDefaultRenderer(Object.class, new CertCellRenderer());
		signCrtTbl.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		signCrtTbl.setPreferredScrollableViewportSize(new Dimension(500, 200));
		signCrtTbl.setModel(new CertTblModel(signCerts));
		signCrtTbl.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		signCrtTbl.getColumnModel().getColumn(2).setPreferredWidth(100);
		signCrtTbl.getColumnModel().getColumn(2).setMaxWidth(100);
		signCrtTbl.getColumnModel().getColumn(2).setMinWidth(100);
		signCrtTbl.getColumnModel().getColumn(2).setWidth(100);
		scrollPaneSign = new JScrollPane(signCrtTbl);
		signCrtTbl.getActionMap().put(showInfo.getValue(Action.NAME), showInfo);
		signCrtTbl.getActionMap().put(cancelAction.getValue(Action.NAME), cancelAction);
		signCrtTbl.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), showInfo.getValue(Action.NAME));
		signCrtTbl.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), cancelAction.getValue(Action.NAME));
		signCrtTbl.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(final MouseEvent evt) {
				if (evt.getClickCount() == 2) {
    				X509Certificate cert = ((CertTblModel) signCrtTbl.getModel()).getCertificate(signCrtTbl.getSelectedRow());
    				dc.muestraInfo(cert);
				}
			}
		});
		signCrtTbl.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(final ListSelectionEvent e) {
				X509Certificate cert = ((CertTblModel) signCrtTbl.getModel()).getCertificate(signCrtTbl.getSelectedRow());
				deleteSignBtn.setEnabled(pksma.isDeletable(cert));					
			}
		});
		
		// Tabla de certificados de autoridades
		authCrtTbl = new JTable();
		authCrtTbl.setDefaultRenderer(Object.class, new CertCellRenderer());
		authCrtTbl.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		authCrtTbl.setPreferredScrollableViewportSize(new Dimension(500, 200));
		authCrtTbl.setModel(new CertTblModel(authCerts));
		authCrtTbl.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		authCrtTbl.getColumnModel().getColumn(2).setPreferredWidth(100);
		authCrtTbl.getColumnModel().getColumn(2).setMaxWidth(100);
		authCrtTbl.getColumnModel().getColumn(2).setMinWidth(100);
		authCrtTbl.getColumnModel().getColumn(2).setWidth(100);
		scrollPaneAuth = new JScrollPane(authCrtTbl);
		authCrtTbl.getActionMap().put(showInfo.getValue(Action.NAME), showInfo);
		authCrtTbl.getActionMap().put(cancelAction.getValue(Action.NAME), cancelAction);
		authCrtTbl.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), showInfo.getValue(Action.NAME));
		authCrtTbl.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), showInfo.getValue(Action.NAME));
		authCrtTbl.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), cancelAction.getValue(Action.NAME));
		authCrtTbl.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(final MouseEvent evt) {
				if (evt.getClickCount() == 2) {
    				X509Certificate cert = ((CertTblModel) authCrtTbl.getModel()).getCertificate(authCrtTbl.getSelectedRow());
    				dc.muestraInfo(cert);
				}
			}
		});
		authCrtTbl.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(final ListSelectionEvent e) {
				X509Certificate cert = ((CertTblModel) authCrtTbl.getModel()).getCertificate(authCrtTbl.getSelectedRow());
				deleteAuthBtn.setEnabled(pksma.isDeletable(cert));					
			}
		});
		
		// Botones
		// Actualizar
		updateSignBtn = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_69));
		updateSignBtn.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
                jButtonUpdateActionPerformed(ACTION_FOR.SIGN);
            }
        });
		// Borrar
		deleteSignBtn = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_70));
		deleteSignBtn.setEnabled(false);
		deleteSignBtn.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
            	jButtonDelActionPerformed(ACTION_FOR.SIGN);
            }
        });
		// Añadir
		addSignBtn = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_71));
		addSignBtn.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
            	jButtonAddActionPerformed(ACTION_FOR.SIGN);
            }
        });
		
		// Actualizar
		updateAuthBtn = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_69));
		updateAuthBtn.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
            	jButtonUpdateActionPerformed(ACTION_FOR.AUTH);
            }
        });
		updateAuthBtn.setEnabled(false); // Deshabilitado
		
		// Borrar
		deleteAuthBtn = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_70));
		deleteAuthBtn.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
                jButtonDelActionPerformed(ACTION_FOR.AUTH);
            }
        });
		
		// Añadir
		addAuthBtn = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_71));
		addAuthBtn.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
                jButtonAddActionPerformed(ACTION_FOR.AUTH);
            }
        });
		
		// Mostrar preferencias
		showPreferences = new JButton(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_84));
		showPreferences.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent evt) {
                jButtonShowPrefActionPerformed();
            }
        });
		
	// Drag & Drop
		signPanel.setTransferHandler(new DragDropHandler());
		signCrtTbl.setDragEnabled(false);
		
		authPanel.setTransferHandler(new DragDropHandler());
		authCrtTbl.setDragEnabled(false);
				
	// Layouts		
		signPanel.setLayout(new GridBagLayout());
		
		GridBagConstraints signTblGrid = new GridBagConstraints();
		signTblGrid.gridx = 0;
		signTblGrid.gridy = 0;
		signTblGrid.gridwidth = 6;
		signTblGrid.fill = GridBagConstraints.BOTH;
		signTblGrid.weightx = 1.0;
		signTblGrid.weighty = 0.8;
		signPanel.add(scrollPaneSign, signTblGrid);
		
		GridBagConstraints signAddBtnGrid = new GridBagConstraints();
		signAddBtnGrid.gridx = 1;
		signAddBtnGrid.gridy = 1;
		signAddBtnGrid.insets = new Insets(10, 80, 10, 75);
		signPanel.add(addSignBtn, signAddBtnGrid);
		
		GridBagConstraints signDelBtnGrid = new GridBagConstraints();
		signDelBtnGrid.gridx = 2;
		signDelBtnGrid.gridy = 1;
		signDelBtnGrid.insets = new Insets(10, 0, 10, 75);
		signPanel.add(deleteSignBtn, signDelBtnGrid);
		
		GridBagConstraints signUpdBtnGrid = new GridBagConstraints();
		signUpdBtnGrid.gridx = 3;
		signUpdBtnGrid.gridy = 1;
		signUpdBtnGrid.insets = new Insets(10, 0, 10, 50);
		signPanel.add(updateSignBtn, signUpdBtnGrid);
		
		authPanel.setLayout(new GridBagLayout());
		
		GridBagConstraints authTblGrid = new GridBagConstraints();
		authTblGrid.gridx = 0;
		authTblGrid.gridy = 0;
		authTblGrid.gridwidth = 6;
		authTblGrid.fill = GridBagConstraints.BOTH;
		authTblGrid.weightx = 1.0;
		authTblGrid.weighty = 0.8;
		authPanel.add(scrollPaneAuth, authTblGrid);
		
		GridBagConstraints authAddBtnGrid = new GridBagConstraints();
		authAddBtnGrid.gridx = 1;
		authAddBtnGrid.gridy = 1;
		authAddBtnGrid.insets = new Insets(10, 80, 10, 75);
		authPanel.add(addAuthBtn, authAddBtnGrid);
		
		GridBagConstraints authDelBtnGrid = new GridBagConstraints();
		authDelBtnGrid.gridx = 2;
		authDelBtnGrid.gridy = 1;
		authDelBtnGrid.insets = new Insets(10, 0, 10, 75);
		authPanel.add(deleteAuthBtn, authDelBtnGrid);
		
		GridBagConstraints authUpdBtnGrid = new GridBagConstraints();
		authUpdBtnGrid.gridx = 3;
		authUpdBtnGrid.gridy = 1;
		authUpdBtnGrid.insets = new Insets(10, 0, 10, 50);
		authPanel.add(updateAuthBtn, authUpdBtnGrid);
		
		// Panel de preferencias
		prefPanel.setLayout(new GridBagLayout());
		
		GridBagConstraints prefGrid = new GridBagConstraints();
		prefGrid.gridx = 0;
		prefGrid.gridy = 0;
		prefGrid.gridwidth = 4;
		prefGrid.insets = new Insets(3, 20, 3, 20);
		prefGrid.anchor = GridBagConstraints.CENTER;
		prefPanel.add(showPreferences, prefGrid);
		
		prefPanel.setBorder(new TitledBorder(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_84))); // Preferencias
		
		//Panel principal
		
		setLayout(new GridBagLayout());
		
		GridBagConstraints tabsGrid = new GridBagConstraints();
		tabsGrid.gridx = 0;
		tabsGrid.gridy = 0;
		tabsGrid.gridwidth = 4;
		tabsGrid.insets = new Insets(3, 3, 0, 3);
		tabsGrid.fill = GridBagConstraints.BOTH;
		tabsGrid.weightx = 1.0;
		tabsGrid.weighty = 1.0;
		add(tabs, tabsGrid);
		
		GridBagConstraints prefPanelGrid = new GridBagConstraints();
		prefPanelGrid.gridx = 0;
		prefPanelGrid.gridy = 1;
		prefPanelGrid.gridwidth = 4;
		prefPanelGrid.insets = new Insets(3, 3, 10, 3);
		prefPanelGrid.fill = GridBagConstraints.HORIZONTAL;
		prefPanelGrid.weightx = 1.0;
		prefPanelGrid.ipady = 5;
		add(prefPanel, prefPanelGrid);
		
		// Almacén de certificados
		setBorder(new TitledBorder(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_72)));
    }
    
    /**
     * <p>Listener para el botón de inclusión de certificados.</p>
     * @param action Indicativo para discernir si es acción para firma o autenticación
     */
    protected void jButtonAddActionPerformed(final ACTION_FOR action) {
    	Thread th = new Thread(new Runnable() {
    		public void run() {
    			JFileChooser chooser = new JFileChooser();
    			// Añadir certificado
    			chooser.setDialogTitle(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_73));
    	        chooser.setDialogType(JFileChooser.OPEN_DIALOG);
    	        chooser.setFileFilter(new CertsFilter(ACTION_FOR.SIGN.equals(action)));
    		    int returnVal = chooser.showOpenDialog(ksmp);
    		    if (returnVal == JFileChooser.APPROVE_OPTION) {
    		    	addCertFromPath(chooser.getSelectedFile().getAbsolutePath(), action);
    		    } else {
    		    	return;
    		    }
    		}
    	});

    	th.run();
    }
    
    /**
     * <p>Listener para el botón de borrado de certificados.</p>
     * @param action Indicativo para discernir si es acción para firma o autenticación
     */
    protected void jButtonDelActionPerformed(final ACTION_FOR action) {
    	Thread th = new Thread(new Runnable() {
    		public void run() {
    			int row = 0;    	
    			if (action.equals(ACTION_FOR.SIGN)) {
    				row = signCrtTbl.getSelectedRow();
    				deleteSignCert(row);
    				if (signCrtTbl.getModel().getRowCount() > 0) {
    					signCrtTbl.setRowSelectionInterval(0, 0);
    				}
    			} else {
    				row = authCrtTbl.getSelectedRow();
    				deleteTrustCert(row);
    				if (authCrtTbl.getModel().getRowCount() > 0) {
    					authCrtTbl.setRowSelectionInterval(0, 0);
    				}
    			}
    		}
    	});

    	th.run();
    }

    /**
     * <p>Listener para el botón de actualización de certificados.</p>
     * @param action Indicativo para discernir si es acción para firma o autenticación
     */
    protected void jButtonUpdateActionPerformed(final ACTION_FOR action) {
    	
    	if (action.equals(ACTION_FOR.AUTH)) {
    		// No hay correspondencia para los certificados de autenticación
    		return;
    	}

    	JFileChooser chooser = new JFileChooser();
    	// Añadir certificado
		chooser.setDialogTitle(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_73));
        chooser.setDialogType(JFileChooser.OPEN_DIALOG);
	    chooser.setFileFilter(new CertsFilter(true));
	    int returnVal = chooser.showOpenDialog(ksmp);
	    if (returnVal == JFileChooser.APPROVE_OPTION) {
	    	addCertFromPath(chooser.getSelectedFile().getAbsolutePath(), null);
			deleteSignCert(signCrtTbl.getSelectedRow());
			if (signCrtTbl.getModel().getRowCount() > 0) {
				signCrtTbl.setRowSelectionInterval(0, 0);
			}
	    } else {
	    	return;
	    }
    }
    
    /**
     * <p>Listener para el botón que muestra las preferencias.</p>
     */
    protected void jButtonShowPrefActionPerformed() {
    	JDialog pref = new JDialog(ownerFrame);
    	JPanel panel = pksma.getPreferencesPanel();
    	
    	pref.add(panel);

        // Diálogo
    	pref.setSize(panel.getSize());
    	pref.setTitle(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_90));
    	pref.setLocationRelativeTo(ownerFrame);
    	if (ownerFrame == null) {
    		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
			pref.setLocation(screenSize.width / 2 - pref.getWidth() / 2, screenSize.height / 2 - pref.getHeight() / 2);
    	}
    	
    	pref.setModal(true);
    	pref.setResizable(false);    	
    	pref.setVisible(true);
    }
    
    /**
     * <p>Inicializa y accede al almacén de certificados.</p>
     */
    protected void loadKeyStore() {
    	try {
    		if (pksm == null) {
    			// No se pudo inicializar el almacén. Compruebe su configuración
    			// Faltan parámetros
    			JOptionPane.showMessageDialog(this,
    					I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_59),
    					I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15),
    					JOptionPane.ERROR_MESSAGE);
    			return;
    		}
			signCerts = pksm.getSignCertificates();
			authCerts = pksm.getTrustCertificates();
		} catch (CertStoreException e) {
			e.printStackTrace();
		}
    }
    
    /**
     * <p>Introduce un certificado de firma en el almacén de certificados.</p>
     * 
     * @param pk Clave privada del certificado
     * @param cert Certificado de firma
     * @param password Contraseña que protegerá el certificado
     */
    private void addSignCert(final PrivateKey pk, final X509Certificate cert, final char[] password) {
    	if (pksm == null) {
			return;
		}
    	try {
			pksma.importSignCert(pk, cert, password);
			refreshTbl();
		} catch (CertStoreException e) {
			// No se pudo añadir el certificado
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_74), e);
			return;			
		}
    }
    
	/**
     * <p>Introduce un certificado de confianza en el almacén de certificados.</p>
     * 
     * @param cert Certificado de confianza
     */
    public void addTrustCert(final X509Certificate cert) {
    	if (pksm == null) {
			return;
		}
    	try {
			pksma.addTrustCert(cert);
			refreshTbl();
		} catch (CertStoreException e) {
			// No se pudo añadir el certificado
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_74), e);
			return;
		} 
    }
    
	/**
	 * <p>Elimina un certificado del almacén de certificados que esté asociado a una clave privada, junto con la clave privada.</p>
	 * 
	 * @param row Fila de la tabla cuyo certificado se va a borrar
	 */
    private void deleteSignCert(final int row) {
    	if (pksm == null) {
			return;
		}
    	if (row != -1) {
    		try {
    			pksma.removeSignCert(((CertTblModel) signCrtTbl.getModel()).getCertificate(row));
    			refreshTbl();
    		} catch (CertStoreException e) {
    			JOptionPane.showMessageDialog(this,
						e.getMessage(),
						I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_19),
    					JOptionPane.WARNING_MESSAGE);
    		}
    	} else {
    		LOG.debug("No se puede borrar, no hay certificado seleccionado.");
    	}
    }
    
    /**
     * <p>Borra un certificado del almacén de certificados.</p>
     * 
     * @param row Fila de la tabla cuyo certificado se va a borrar
     */
    private void deleteTrustCert(final int row) { 
    	if (pksm == null) {
			return;
		}
    	if (row != -1) {
    		try {
    			pksma.removeTrustCert(((CertTblModel) authCrtTbl.getModel()).getCertificate(row));
    			refreshTbl();
    		} catch (CertStoreException e) {
    			JOptionPane.showMessageDialog(this,
						e.getMessage(),
						I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_19),
    					JOptionPane.WARNING_MESSAGE);
    		}
    	} else {
    		LOG.debug("No se puede borrar, no hay certificado seleccionado.");
    	}
    	
    }
    
    /**
	 * <p>Actualiza el certificado asociado a una clave privada, reemplazando el anterior asociado.</p>
	 *  
	 * @param cert certificado actual
	 */
    private void updateSignCert(final X509Certificate cert) {
    	if (pksm == null) {
			return;
		}
    	try {
			pksma.updateSignCert(cert);
			refreshTbl();
		} catch (CertStoreException e) {
			e.printStackTrace();
		} finally {
			
		}
    }
    
    /**
     * <p>Actualiza el contenido de las tablas.</p>
     */
    private void refreshTbl() {
    	try {
			signCerts = pksm.getSignCertificates();
			authCerts = pksm.getTrustCertificates();
		} catch (CertStoreException e) {
			e.printStackTrace();
		}
		
    	signCrtTbl.setModel(new CertTblModel(signCerts));
    	authCrtTbl.setModel(new CertTblModel(authCerts));
    	
    	signCrtTbl.repaint();
    	authCrtTbl.repaint();
    }
	
	/**
	 * Devuelve el certificado personal seleccionado.
	 * 
	 * @return <c>null</c> si no está seleccionado ningún certificado
	 */
	public X509Certificate getSignCertificate() {
		int sel = signCrtTbl.getSelectedRow();
		if ((sel > -1) && (sel < signCerts.size())) {
			return signCerts.get(sel);
		} else {
			return null;
		}
	}
	
	/**
	 * Devuelve el certificado de autoridades seleccionado.
	 * 
	 * @return <c>null</c> si no está seleccionado ningún certificado
	 */
	public X509Certificate getAuthCertificate() {
		int sel = authCrtTbl.getSelectedRow();
		if ((sel > -1) && (sel < authCerts.size())) {
			return authCerts.get(sel);
		} else {
			return null;
		}
	}
	
	/**
	 * <p>Recupera un certificado de una ruta. Dicho fichero puede ser un .cer o un .p12.</p>
	 * @param path Ruta al fichero que contiene el ceritficado
	 * @param action Indica si es un certificado para firma o autenticación. Con <code>null</code> se toma como una sustitución.
	 */
	private void addCertFromPath(final String path, final ACTION_FOR action) {
		if (!new File(path).exists()) {
			// El fichero indicado no existe o no se encuentra
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_75));
			return;
		}
		// Variables de proceso de uso común
		FileInputStream fis = null;
		// Resultados esperados
		X509Certificate cert = null;
		PrivateKey pk12 = null;
		char[] passwordP12 = null;

		if (path.endsWith("p12")) {
			// Se carga el P12
			try {
				KeyStore ks12 = KeyStore.getInstance("PKCS12");
				passwordP12 = null;
				try {
					fis = new FileInputStream(path);
					PlainPassHandler passHandler = new PlainPassHandler();
					passwordP12 = passHandler.getPassword(null, path.substring(path.lastIndexOf(File.separator) + 1));
					try {
						ks12.load(fis, passwordP12);
					} catch (IOException e) {
						// La contraseña no es válida. No se pudo acceder al contenedor P12
						LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_76));
						JOptionPane.showMessageDialog(this,
								I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_76),
								I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_77),
		    					JOptionPane.WARNING_MESSAGE);
						return;
					}

					// Se accede al contenido
					Enumeration<String> contenidoP12 = ks12.aliases();
					String alias = null;
					if (ks12.size() == 1) {
						alias = contenidoP12.nextElement();
						LOG.debug("P12.- Alias del certificado: " + alias);
					} else {
						// El contenedor P12 está vacío
						JOptionPane.showMessageDialog(this,
								I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_78),
								I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_77),
		    					JOptionPane.WARNING_MESSAGE);
						return;
					}

					// Carga el certificado
					try {
						cert = (X509Certificate) ks12.getCertificate(alias);
					} catch (KeyStoreException e1) {
						e1.printStackTrace();
						return;
					} 

					// Carga la private Key
					if (ks12.isKeyEntry(alias)) {
						// obtener la clave privada
						passwordP12 = passHandler.getPassword(null, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_80));
						KeyStore.PasswordProtection kpp12 = new KeyStore.PasswordProtection(passwordP12);
						KeyStore.PrivateKeyEntry pkEntry12 = null;
						try {
							pkEntry12 = (KeyStore.PrivateKeyEntry) ks12.getEntry(alias, kpp12);
						} catch (NoSuchAlgorithmException e1) {
							e1.printStackTrace();
						} catch (UnrecoverableEntryException e) {
							// La contraseña no es válida. No se pudo acceder a la clave privada
							JOptionPane.showMessageDialog(this,
									I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_79),
									I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_77),
			    					JOptionPane.WARNING_MESSAGE);
							return;
						}
						if (pkEntry12 != null) {
							pk12 = pkEntry12.getPrivateKey();
						} else {
							LOG.debug("P12.- No se encontró la clave privada");
						}
					}
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
					return;
				} catch (CertificateException e) {
					e.printStackTrace();
					return;
				} catch (FileNotFoundException e) {
					e.printStackTrace();
					return;
				} finally {
					if (fis != null) {
						try {
							fis.close();
						} catch (IOException e) { /* No se hace nada */ }
					}
				}
			} catch (KeyStoreException e1) {
				e1.printStackTrace();
				return;
			}
		} else if (path.endsWith("cer") || path.endsWith("crt")) {
			try {
				CertificateFactory cfTemporal = CertificateFactory.getInstance("X.509");	
				cert = (X509Certificate) cfTemporal.generateCertificate(new FileInputStream(new File(path)));
			} catch (IOException e) {
				e.printStackTrace();
				return;
			} catch (CertificateException e) {
				e.printStackTrace();
				return;
			}
		}
		
		if (action == null) {
			updateSignCert(cert);
		} else if (action.equals(ACTION_FOR.SIGN)) {
			addSignCert(pk12, cert, passwordP12);
		} else {
			addTrustCert(cert);
		}
	}
	
	/**
     * <p>Clase para acciones de Drag&Drop.</p>
     */
    private class DragDropHandler extends TransferHandler {

		/**
		 * <p>Indica qué ficheros se pueden importar.</p>
		 * @param comp componente que pide el drop
		 * @param transferFlavors savores disponibles del drop
		 * @return <code>true</code> si se puede importar el fichero indicado
		 */
		@Override
		public boolean canImport(JComponent comp, DataFlavor[] transferFlavors) {
			boolean res = false;

			for (DataFlavor dataFlavor : transferFlavors) {
				if (dataFlavor.isFlavorJavaFileListType()) {
					res = true;
					break;
				}
			}
			
			return (res) ? true : super.canImport(comp, transferFlavors);
		}
		
		/**
		 * <p>Carga los datos arrastrados en la acción de Drop.</p>
		 * @param comp componente que recibe el drop
		 * @param t objeto que contiene el objeto dropeado
		 * @return <code>true</code> si se puede importar el fichero indicado
		 */
		@Override
		public boolean importData(JComponent comp, Transferable t) {
			boolean res = false;
			DataFlavor[] trasnferFlavors = t.getTransferDataFlavors();
			File file = null;
			for (DataFlavor dataFlavor : trasnferFlavors) {
				if (dataFlavor.isFlavorJavaFileListType()) {
					try {
						List< ? > files = (List< ? >) t.getTransferData(dataFlavor);
						if (files.size() > 0) {
							file = (File) files.get(0);
							if (file.exists()) {
				    			if (file.getName().endsWith("cer") || 
				    					file.getName().endsWith("crt") ||
				    					file.getName().endsWith("p12")) {
				    				// Se lanza la validación de certificados
				    				if (signPanel.equals(comp)) {
				    					addCertFromPath(file.getAbsolutePath(), ACTION_FOR.SIGN);
				    				} else {
				    					addCertFromPath(file.getAbsolutePath(), ACTION_FOR.AUTH);
				    				}
				    			} else {
				    				// No se puede importar un fichero que no sea un certificado
				    				EventQueue.invokeLater(new Runnable() {
										public void run() {
											JOptionPane.showMessageDialog(tabs,
													I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_56),  
													I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_77),  
													JOptionPane.ERROR_MESSAGE);
										}
									});
				    			}
							} else {
								EventQueue.invokeLater(new Runnable() {
									public void run() {
										JOptionPane.showMessageDialog(tabs,  
												I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_75),  
												I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_77),  
												JOptionPane.ERROR_MESSAGE);
									}
								});
							}					
							
							res = true;
							break;
						}
					} catch (UnsupportedFlavorException ex) {
					} catch (IOException ex) {
					}
				}
			}
			return (res) ? true : super.importData(comp, t);
		}
		
		/**
		 * <p>No implementado.</p>
		 */
		@Override
		public void exportAsDrag(JComponent comp, InputEvent e, int action) {
			LOG.warn("Not implemented yet.");
		}
    }
}
