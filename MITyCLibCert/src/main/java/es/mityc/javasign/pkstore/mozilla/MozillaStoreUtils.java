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

import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.jss.util.PasswordCallback;

import es.mityc.javasign.exception.CopyFileException;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable.MESSAGES_MODE;
import es.mityc.javasign.utils.CopyFilesTool;
import es.mityc.javasign.utils.OSTool;
import es.mityc.javasign.utils.WinRegistryUtils;

/**
 * <p>Facade de acceso a los servicios del almacén de certificados de Mozilla mediante el uso de JSS.</p>
 * 
 */
public class MozillaStoreUtils {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(MozillaStoreUtils.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/** Modos de inicialización de la librería jss. */
	public enum LIB_MODE { FULL, ONLY_JSS, ONLY_PKCS11 };
    
	/** Nombre del recurso que contiene la configuración. */
	private static final String STR_MOZILLA = "mozilla";
	/** Nombre de la propiedad que indica la clase que se utiliza para recoger contraseñas. */
    private static final String STR_PASS_HANDLER = "passCallbackHandler";

	/** Ruta al temporal donde se copiaron las librerías. */
	private static String tmpDir = "";
	
	/**
	 * Constructor.
	 */
	public MozillaStoreUtils() throws CertStoreException {

	}

	/**
	 *<p> Inicializa el manager general de JSS.</p>
	 * 
	 * @param profile ruta donde se encuentra el perfil de usuario
	 */
	protected static synchronized String initialize(String profile, LIB_MODE mode) throws CertStoreException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Inicializando CSP Firefox. Profile: " + profile + "\nModo: " + mode);
		}
		
		if (profile == null) {
			try {
				profile = getMozillaUserProfileDirectory();
				if (LOG.isDebugEnabled()) {
					LOG.debug("Encontrada ruta al perfil de firefox: " + profile);
				}
			} catch (Exception e) {
				LOG.debug("No se encontró la ruta al perfil", e);
			}
		}
		
		// Se busca la ruta al NSS original empleado por el usuario
		String rutaFirefox = null;
		try {
			rutaFirefox = getSystemNSSLibDir();
			if (LOG.isDebugEnabled()) {
				LOG.debug("Encontrada ruta al NSS de firefox: " + rutaFirefox);
			}
		} catch (Exception e) {
			LOG.debug("No se pudo encontrar la ruta al NSS de Firefox", e);
		}
		
		Vector<String> arrayACargar = new Vector<String>();
		
		if (rutaFirefox != null) {
			int i = rutaFirefox.indexOf("firefox.exe");
			if (i != -1) {
				if ((rutaFirefox = rutaFirefox.substring(0, i)).startsWith("\""))
					rutaFirefox = rutaFirefox.substring(1);
				tmpDir = rutaFirefox;
			}
			
			arrayACargar = getNSSDependencies(rutaFirefox);
			// Se copia la librería del enlace con NSS
			Vector<String> dlls = copyLibraries(mode, rutaFirefox);
			if (dlls != null)
				arrayACargar.addAll(dlls);
			else
				throw new CertStoreException("No se pudo copiar la librería de enlace con NSS");
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("No se detectó NSS.- Se provee de una copia interna");
			}
			arrayACargar.add("NeedCopy");
		}
		
		try {
			load(arrayACargar);
			
			return tmpDir;
		} catch (Throwable ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_2, ex.getMessage()), ex);
			throw new CertStoreException(ex);
		}
	}
	
    /**
     * <p>Copia las librerías de puente a mozilla.</p>
     */
    private static synchronized Vector<String> copyLibraries(LIB_MODE mode, String dir) {
		try {
			CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_MZ_PROPERTIES, MozillaStoreUtils.class.getClassLoader());
			switch (mode) {
				case FULL: 
				tmpDir = cft.copyFilesOS(dir, ConstantsCert.CP_MOZILLA_CLIENTE, true); 
				if (LOG.isDebugEnabled()) 
					LOG.debug("Librerías copiadas: " + cft.getCopiedLibraries() + " en dir " + tmpDir);
				break;
				case ONLY_JSS: 
					tmpDir = cft.copyFilesOS(dir, ConstantsCert.CP_MOZILLA_JSS_ONLY, true);
					if (LOG.isDebugEnabled()) 
						LOG.debug("Librería copiada: " + cft.getCopiedLibraries() + " en dir " + tmpDir);
					break;
				case ONLY_PKCS11: 
					tmpDir = cft.copyFilesOS(dir, ConstantsCert.CP_MOZILLA_PKCS11_ONLY, true); 
					if (LOG.isDebugEnabled()) 
						LOG.debug("Librería copiada: " + cft.getCopiedLibraries() + " en dir " + tmpDir);
					break;
				default:
					if (LOG.isDebugEnabled()) 
						LOG.debug("Modo de librerías no soportado");
					break;
			}
    		if (LOG.isDebugEnabled()) {
    			LOG.debug("Se terminaron de copiar las dependencias para el CSP de Mozilla");
    		}
    		
    		if (tmpDir != null && !tmpDir.trim().equals("")) {
    			if (!tmpDir.endsWith(File.separator)) {
    			    tmpDir = tmpDir + File.separator;
    			}
    			Vector<String> copiedLibraries = cft.getCopiedLibraries();
    			Vector<String> absoluteLibraries = new Vector<String>();
    			for (int i = 0; i < copiedLibraries.size(); ++i) {
    				absoluteLibraries.add(tmpDir + copiedLibraries.get(i));
    			}
    			return absoluteLibraries;
    		} else {
    			return cft.getCopiedLibraries();
    		}
		} catch (SecurityException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_1, ex.getMessage()), ex);
		} catch (UnsatisfiedLinkError ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_1, ex.getMessage()), ex);
		} catch (CopyFileException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_1, ex.getMessage()), ex);
		} catch (Throwable e) {
			LOG.debug("No se pudo cargar la instancia de la librería: " + e.getMessage(), e);
    	}
		
		return null;
    }
    
    private static void load(Vector<String> keys) throws Exception {
    	if (keys == null || keys.size() == 0) throw new IOException("La cadena de librerias a cargar está vacía");
    	try {
    		String key = null;
    		for (int i = 0; i < keys.size(); ++i) {
    			key = keys.get(i);
				if (key != null) {
					if (LOG.isDebugEnabled()) {
						LOG.debug("Cargando la librería: " + key);
					}
					if (new File(key).exists())
						System.load(key);
					else {
						try {
							System.loadLibrary(key.substring(key.lastIndexOf(File.separator) + 1)); // Requiere que el Library Path actual apunte al lugar apropiado
						} catch (Exception e) {
							throw new FileNotFoundException(key);
						}
					}
				}
    		}
    	} catch (Throwable e) {
    		LOG.debug("No se pudo cargar la instancia de la pasarela con Firefox: " + e.getMessage(), e);
    		try {
    			keys = copyLibraries(LIB_MODE.FULL, null);
    			String key = null;
    			for (int i = 0; i < keys.size(); ++i) {
    				key = keys.get(i);
    				if (key != null) {
    					if (LOG.isDebugEnabled()) {
    						LOG.debug("Cargando la librería: " + key);
    					}
    					File lib = new File(key);
    					if (lib.exists())
    						System.load(lib.getAbsolutePath()); // Debe ser una ruta absoluta al fichero
    					else {
    						int j = -1;
    						if ((j = key.indexOf(".")) != -1) {
    							key = key.substring(0, j);
    						}
    						if (key.startsWith("lib")) {
    							key = key.substring(3);
    						}

    						try {
    							System.loadLibrary(key.substring(key.lastIndexOf(File.separator) + 1)); // Requiere que el Library Path actual apunte al lugar apropiado
    						} catch (Exception ex) {
    							throw new FileNotFoundException(key);
    						}
    					}
    				} else {
    					LOG.error("No se pudieron copiar las dependencias de NSS para Firefox");
    					break;
    				}
    			}
    		} catch (Throwable e2) {
    			try { // Se reintenta el proceso de copia con sufijo aleatorio para evitar conflictos con instancias previas
    				LOG.debug("No se han cargado las dependencias tal cual, se intenta con un nombre alternativo.");
    				String random = new Long(System.currentTimeMillis()).toString();
    				CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_MZ_PROPERTIES, MozillaStoreUtils.class.getClassLoader());
    				tmpDir = cft.copyFilesOS(null, ConstantsCert.CP_MOZILLA_CLIENTE, true, random);
    				keys = cft.getCopiedLibraries();
    				String key = null;
    				for (int i = 0; i < keys.size(); ++i) {
    					key = keys.get(i);
    					if (key != null) {
    						File lib = new File(tmpDir + File.separator + key);
        					if (lib.exists()) {
            					if (LOG.isDebugEnabled()) {
            						LOG.debug("Cargando la librería alternativa: " + lib.getAbsolutePath());
            					}
        						System.load(lib.getAbsolutePath()); // Debe ser una ruta absoluta al fichero
        					} else {
    							int j = -1;
    							if ((j = key.indexOf(".")) != -1) {
    								key = key.substring(0, j);
    							}	    				
    							try {
                					if (LOG.isDebugEnabled()) {
                						LOG.debug("Cargando la librería alternativa dos: " + key.substring(key.lastIndexOf(File.separator) + 1));
                					}
    								System.loadLibrary(key.substring(key.lastIndexOf(File.separator) + 1)); // Requiere que el Library Path actual apunte al lugar apropiado
    							} catch (Exception e3) {
    								throw new FileNotFoundException(key);
    							}
    						}
    					} else {
    						LOG.error("No se pudieron copiar las dependencias de NSS para Firefox");
    						break;
    					}
    				}
    			} catch (Throwable e3) {
    				LOG.debug("No se pudo cargar definitivamente la instancia de las librerías de Firefox: " + e3.getMessage(), e3);
    				throw new Exception(e3);
    			}
    		}
    	}
    }
    
    /**
     * <p>Carga la clase encargada de obtener las contraseñas pedidas por el almacén de Mozilla.</p>
     * 
     * @param mode Modo en el que se mostrarán los títulos en la ventana (@see {@link MESSAGES_MODE}}
     * @param title Título de la ventana de PIN
     * @param pinMessage Mensaje de petición de PIN
     * @return instancia de la clase configurada (instancia de {@link PassStoreMozilla} si no está correctamente configurado) 
     */
    protected static PasswordCallback getPassHandler(MESSAGES_MODE mode, String title, String pinMessage) {
    	PasswordCallback handler = null;
    	try {
    		if (LOG.isTraceEnabled()) {
    			LOG.trace("Obteniendo Passhandler...");
    		}
    		ResourceBundle rb = ResourceBundle.getBundle(STR_MOZILLA);
    		String handlerClass = rb.getString(STR_PASS_HANDLER);
    		if (LOG.isTraceEnabled()) {
    			LOG.trace("Nombre de ventana de pin: " + handlerClass);
    		}
    		handler = (PasswordCallback) Class.forName(handlerClass).newInstance();
    		((IPINDialogConfigurable) handler).setMessagesMode(mode);
    		if (title != null) {
    			((IPINDialogConfigurable) handler).setTitle(title);
    		}
    		if (pinMessage != null) {
    			((IPINDialogConfigurable) handler).setPINMessage(pinMessage);
    		}
    		if (LOG.isTraceEnabled()) {
    			LOG.trace("Pashandler configurado");
    		}
    	} catch (MissingResourceException ex) {
    		LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_3, ex.getMessage()));
    		handler = new PassStoreMozilla();
    	} catch (InstantiationException ex) {
    		LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_3, ex.getMessage()));
    		if (LOG.isDebugEnabled()) {
    			LOG.error(ex);
    		}
    		handler = new PassStoreMozilla();
		} catch (IllegalAccessException ex) {
    		LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_3, ex.getMessage()));
    		if (LOG.isDebugEnabled()) {
    			LOG.error(ex);
    		}
    		handler = new PassStoreMozilla();
		} catch (ClassNotFoundException ex) {
    		LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_3, ex.getMessage()));
    		if (LOG.isDebugEnabled()) {
    			LOG.error(ex);
    		}
    		handler = new PassStoreMozilla();
		} catch (ClassCastException ex) {
    		LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_3, ex.getMessage()));
    		if (LOG.isDebugEnabled()) {
    			LOG.error(ex);
    		}
    		handler = new PassStoreMozilla();
		}
    	return handler;
    }

    /**
     * <p>Convierte un certificado del tipo JSS mozilla en uno de java (especie de typecasting).</p>
     * 
     * @param certificate el certificado en la clase org.mozilla.jss.crypto.X509Certificate
     * @return el certificado en la clase java.security.cert.X509Certificate, <code>null</code> si no lo consigue convertir
     */
    protected static X509Certificate convert(org.mozilla.jss.crypto.X509Certificate certificate) {
		try {
			if (LOG.isTraceEnabled()) {
				LOG.trace("Convirtiendo certificado JSS: " + certificate.getSubjectDN());
			}
			byte[] certFirma = certificate.getEncoded();
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certFirma));
		} catch (CertificateEncodingException ex) {
        	LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_4, ex.getMessage()), ex);
		} catch (CertificateException ex) {
        	LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_4, ex.getMessage()), ex);
		}
		return null;
    }
    
    /**
     * <p>Convierte un certificado del tipo PKCS11 mozilla en uno de java (especie de typecasting).</p>
     * 
     * @param certificate el certificado en la clase iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate
     * @return el certificado en la clase java.security.cert.X509Certificate, <code>null</code> si no lo consigue convertir
     */
    protected static X509Certificate convert(X509PublicKeyCertificate certificate) {
		try {
			if (LOG.isTraceEnabled()) {
				LOG.trace("Convirtiendo certificado PKCS11: " + certificate.getLabel());
			}
			byte[] encCert = certificate.getValue().getByteArrayValue(); 
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(encCert));
		} catch (CertificateEncodingException ex) {
        	LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_4, ex.getMessage()), ex);
		} catch (CertificateException ex) {
        	LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_4, ex.getMessage()), ex);
		}
		return null;
    }


    // Bibliotecas Windows de Firefox
    private static final String SOFTOKN3_DLL = "softokn3.dll";
    //private static final String PLC4_DLL = "plc4.dll";
    //private static final String PLDS4_DLL = "plds4.dll";
    //private static final String NSPR4_DLL = "nspr4.dll";
    //private static final String MOZSQLITE3_DLL = "mozsqlite3.dll";
    //private static final String MOZCRT19_DLL = "mozcrt19.dll";
    //private static final String NSSUTIL3_DLL = "nssutil3.dll";
    //private static final String FREEBL3_DLL = "freebl3.dll";
    //private static final String NSSDBM3_DLL = "nssdbm3.dll";
    //private static final String SQLITE3_DLL = "sqlite3.dll";
    private static final String MSVCR100_DLL = "msvcr100.dll";
    private static final String MOZGLUE_DLL = "mozglue.dll";
    
    private static final String NSS3_DLL = "nss3.dll";
    //private static final String SMIME3_DLL = "smime3.dll";
    //private static final String SSL3_DLL = "ssl3.dll";
    //private static final String NSSCKBI_DLL = "nssckbi.dll";

    private static final String NSPR4_SO = "/lib/libnspr4.so";

    /** Directorio con las bibliotecas de NSS. */
    private static String nssLibDir = null;

    /** Crea las l&iacute;neas de configuraci&oacute;n para el uso de las
     * bibliotecas NSS como m&oacute;dulo PKCS#11 por el proveedor de Sun.
     * @param userProfileDirectory
     *        Directorio donde se encuentra el perfil de usuario de Mozilla
     *        Firefox
     * @param libDir
     *        Directorio que contiene las bibliotecas NSS
     * @return Fichero con las propiedades de configuracion del proveedor
     *         PKCS#11 de Sun para acceder al KeyStore de Mozilla v&iacute;a
     *         NSS. */
    static String createPKCS11NSSConfigFile(final String userProfileDirectory, final String libDir) {
        String softoknLib = "libsoftokn3.so";
        if (OSTool.getSO().isWindows()) {
            softoknLib = SOFTOKN3_DLL;
        }
        else if (OSTool.getSO().isMacOsX()) {
            softoknLib = "libsoftokn3.dylib";
        }       
        if (libDir == null) {
        	LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9));
        	return "";
        }
        if (!libDir.endsWith(File.separator)) {
        	libDir.concat(File.separator);
        }

        final StringBuilder buffer = new StringBuilder("name=NSS-PKCS11\r\n");

        // Java 1.5 tenia un metodo indocumentado para acceder a NSS,
        // http://docs.sun.com/app/docs/doc/819-3671/gcsoc?a=view

        buffer.append("library=")
              .append(libDir)
              .append(softoknLib)
              .append("\r\n")
              .append("attributes=compatibility\r\n")
              .append("configdir='")
              .append(userProfileDirectory)
              .append("' ")
              .append("certPrefix='' ")
              .append("keyPrefix='' ")
              .append("secmod='secmod.db' ")
              .append("flags=readOnly");

        return buffer.toString();
    }
    
    /** Obtiene el directorio de las bibliotecas NSS (<i>Netscape Security
     * Services</i>) del sistema.
     * @return Directorio de las bibliotecas NSS del sistema
     * @throws FileNotFoundException Si no se puede encontrar NSS en el sistema */
    static String getSystemNSSLibDir() throws Exception {
        if (nssLibDir != null) {
            return nssLibDir;
        }

        if (OSTool.getSO().isWindows()) {
            return getSystemNSSLibDirWindows();
        }
        if (OSTool.getSO().isLinux() || OSTool.getSO().getVersion().contains("olaris")) {
            return getSystemNSSLibDirUnix();
        }
        if (OSTool.getSO().isMacOsX()) {
            return getSystemNSSLibDirMacOsX();
        }

        LOG.debug("No se han encontrado bibliotecas NSS instaladas en su sistema operativo");
        return null;
    }

    private static String getSystemNSSLibDirWindows() throws Exception {
        // Se intenta extraer la ruta de instalacion de Firefox del registro
        String dir = WinRegistryUtils.readString(WinRegistryUtils.HKEY_CURRENT_USER, 
        		"Software\\Classes\\FirefoxURL\\shell\\open\\command", "");
        if (dir == null) {
            dir = WinRegistryUtils.readString(WinRegistryUtils.HKEY_LOCAL_MACHINE, 
            		"SOFTWARE\\Classes\\FirefoxURL\\shell\\open\\command", "");
            if (dir == null) {
                throw new FileNotFoundException("No se ha podido localizar el directorio de Firefox a traves del registro de Windows"); //$NON-NLS-1$
            }
        }

        final String regKeyLowCase = dir.toLowerCase();
        final int pos = regKeyLowCase.indexOf("firefox.exe");
        if (pos != -1) {
            dir = dir.substring(0, pos);
            if (dir.startsWith("\"")) {
                dir = dir.substring(1);
            }
            if (dir.endsWith(File.separator)) {
                dir = dir.substring(0, dir.length() - 1);
            }

            File tmpFile = new File(dir);
            if (tmpFile.exists() && tmpFile.isDirectory()) {
                tmpFile = new File(dir + File.separator + SOFTOKN3_DLL);
                if (tmpFile.exists()) {
                    try {
                        dir = tmpFile.getParentFile().getCanonicalPath();
                    } catch (final Exception e) {
                        if (dir.contains("\u007E")) {
                            throw new FileNotFoundException("No se ha podido obtener el nombre del directorio del modulo PKCS#11," +
                            		" parece estar establecido como un nombre corto (8+3): " + e);
                        }
                    }

                    // Ruta del NSS, se comprueba su adecuacion por bugs de Java
                    boolean illegalChars = false;
                    for (final char c : dir.toCharArray()) {
            			if (P11_CONFIG_VALID_CHARS.indexOf(c) == -1) {
            				illegalChars = true;
            				break;
            			}
            		}
                    // El caracter "tilde" (unicode 007E) es valido para perfil de usuario pero no
                    // para bibliotecas en java inferior a 6u30
                    if (illegalChars || dir.contains("\u007E")) {
                        // Configuracion de SunPKCS#11 por el bug 6581254:
                        // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6581254
                    	LOG.error("Si esta version de JRE esta afectada por el error 6581254 de Java es posible que no pueda cargarse: " + dir);
                    }

            		for (final char c : dir.toCharArray()) {
            			if (P11_CONFIG_VALID_CHARS.indexOf(c) == -1) {
            				dir = dir.replace(System.getProperty("user.home"),
            						getShort(System.getProperty("user.home")));
            				break;
            			}
            		}
                    return dir;
                }
            }
        }

		if (LOG.isDebugEnabled()) {
			LOG.debug("No se ha encontrado un NSS compatible en Windows");
		}
		
		return null;
    }
    
    private static final String DIR_TAG = "<DIR>";
    
    /** Obtiene el nombre corto (8+3) del &uacute;ltimo directorio de una ruta sobre la misma ruta de directorios (es decir,
	 * que solo se pasa a nombre corto al &uacute;timo directorio, el resto de elementos de la ruta se dejan largos).
	 * Es necesario asegurarse de estar sobre MS-Windows antes de llamar a este m&eacute;todo. */
	private static String getShort(final String longPath) {
		if (longPath == null) {
			return longPath;
		}

		final File dir = new File(longPath);
		if (!dir.exists() || !dir.isDirectory()) {
			return longPath;
		}

		try {
			final Process p = new ProcessBuilder(
				"cmd.exe", "/c", "dir /ad /x \"" + longPath + "\\..\\?" + longPath.substring(longPath.lastIndexOf('\\') + 2) + "\""
			).start();
			
			InputStream is = p.getInputStream();
			if (is == null) {
	            return null;
	        }
	        int nBytes = 0;
	        final byte[] buffer = new byte[4096];
	        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        while ((nBytes = is.read(buffer)) != -1) {
	            baos.write(buffer, 0, nBytes);
	        }

			final BufferedReader br = new BufferedReader(new InputStreamReader(
					new ByteArrayInputStream(baos.toByteArray())));
			String line = br.readLine();
			while (line != null) {
				if (line.contains(DIR_TAG)) {
					final String path = longPath.substring(0, longPath.lastIndexOf('\\') + 1);
					final String filenames = line.substring(line.indexOf(DIR_TAG) + DIR_TAG.length()).trim();
					int index = filenames.indexOf(" ");
					String shortName = null;
					if (index > 0) {
						shortName = filenames.substring(0, filenames.indexOf(" "));
					} else {
						shortName = filenames.substring(0);
					}

					if (!"".equals(shortName)) {
						return path + shortName;
					}
					return longPath;
				}
				line = br.readLine();
			}
		} catch(final Exception e) {
			LOG.error("No se ha podido obtener el nombre corto de " + longPath, e);
		}
		return longPath;
	}


    private static String getSystemNSSLibDirMacOsX() throws FileNotFoundException {
        final String[] posiblesRutas = new String[] {
                "/Applications/Firefox.app/Contents/MacOS",
                "/lib",
                "/usr/lib",
                "/usr/lib/nss",
                "/Applications/Minefield.app/Contents/MacOS"
            };

        for (final String path : posiblesRutas) {
            if (new File(path + "/libsoftokn3.dylib").exists()) {
                nssLibDir = path;
            }
        }

        if (nssLibDir == null) {
            throw new FileNotFoundException("No se ha podido determinar la localizacion de NSS en Mac OS X");
        }

        return nssLibDir;
    }

    private static String getSystemNSSLibDirUnix() throws FileNotFoundException {
        // Fedora.- Se comprueba el caso especifico de NSS partido entre /usr/lib y /lib
        if (new File("/usr/lib/libsoftokn3.so").exists() && new File(NSPR4_SO).exists()) {
            try {
                System.load(NSPR4_SO);
                nssLibDir = "/usr/lib";
            } catch (final Exception e) {
                nssLibDir = null;
                LOG.debug("Se descarta el NSS situado entre /lib y /usr/lib. No puede ser cargado: " + e);
            }
            if (nssLibDir != null) {
                return nssLibDir;
            }
        }

        final String[] posiblesRutas = new String[] {
                    "/usr/lib/firefox-" + searchLastFirefoxVersion("/usr/lib/"),
                    "/usr/lib/firefox",
                    "/opt/firefox",
                    "/opt/firefox-" + searchLastFirefoxVersion("/opt/"),
                    "/lib",
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/opt/fedora-ds/clients/lib"
                };

        for (final String path : posiblesRutas) {
            if (new File(path + "/libsoftokn3.so").exists() && new File(path + "/libnspr4.so").exists()) {
                try {
                    System.load(path + "/libnspr4.so");
                    nssLibDir = path;
                } catch (final Exception e) {
                    nssLibDir = null;
                    LOG.error("Se descarta el NSS situado en '" + path
                            + "' porque no puede cargarse adecuadamente: " + e);
                }
                if (nssLibDir != null) {
                    return nssLibDir;
                }
            }
        }

        if (nssLibDir == null) {
            throw new FileNotFoundException("No se ha podido determinar la localizacion de NSS en UNIX");
        }

        return nssLibDir;
    }

    /** Busca la última versión de firefox instalada en un sistema
     * Linux o Solaris
     * @return &Uacute;ltima versi&oacute;n instalada en el sistema */
    private static String searchLastFirefoxVersion(final String startDir) {
        final File directoryLib = new File(startDir);
        if (directoryLib.isDirectory()) {
            final String filenames[] = directoryLib.list();
            final List<String> firefoxDirectories = new ArrayList<String>();
            for (final String filename : filenames) {
                if (filename.startsWith("firefox-")) {
                    firefoxDirectories.add(filename.replace("firefox-", ""));
                }
            }
            if (firefoxDirectories.isEmpty()) {
                return "";
            }
            for (int i = 0; i < firefoxDirectories.size(); i++) {
                try {
                    Integer.getInteger(firefoxDirectories.get(i));
                }
                catch (final Exception e) {
                    firefoxDirectories.remove(i);
                }
            }
            if (firefoxDirectories.size() == 1) {
                return firefoxDirectories.get(0);
            }
            Collections.sort(firefoxDirectories, new Comparator<String>() {
                public int compare(final String o1, final String o2) {
                    return o1.compareTo(o2);
                }
            });
            return firefoxDirectories.get(0);
        }
        return "";
    }

    /** Carga las dependencias de la biblioteca "softokn3" necesaria para acceder
     * al almac&eacute;n de certificados. Se realiza autom&aacute;ticamente si las dependencias
     * estan en el PATH del sistema.
     * @param nssDirectory Directorio en donde se encuentran las bibliotecas de NSS. 
     */
    static private Vector<String> getNSSDependencies(final String nssDirectory) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Buscando dependencias NSS");
		}
    	Vector<String> dependList = new Vector<String>();

        // Fedora: Se comprueba el caso especifico de NSS partido entre /usr/lib y /lib
        if (OSTool.getSO().isLinux() && new File("/usr/lib/libsoftokn3.so").exists() 
        		&& new File(NSPR4_SO).exists()) { 
        	dependList.add(NSPR4_SO);
        	dependList.add("/lib/libplds4.so");
        	dependList.add("/usr/lib/libplds4.so");
        	dependList.add("/lib/libplc4.so");
        	dependList.add("/usr/lib/libplc4.so");
        	dependList.add("/lib/libnssutil3.so");
        	dependList.add("/usr/lib/libnssutil3.so");
        	dependList.add("/lib/libsqlite3.so");
        	dependList.add("/usr/lib/libsqlite3.so");
        	dependList.add("/lib/libmozsqlite3.so");
        	dependList.add("/usr/lib/libmozsqlite3.so");
			if (LOG.isDebugEnabled()) {
				LOG.debug("Encontrado NSS Fedora: " + dependList);
			}
        } else {
        	final String path = nssDirectory + (nssDirectory.endsWith(File.separator) ? "" : File.separator);
        	String[] dependList2 = getSoftkn3Dependencies(path);
        	dependList.addAll(Arrays.asList(dependList2));
			if (LOG.isDebugEnabled()) {
				LOG.debug("Encontrado NSS: " + dependList);
			}
        }
    	
    	return dependList;
    }

    /** Recupera el listado de dependencias de la biblioteca "softkn3" para el
     * sistema operativo en el que se est&aacute; ejecutando la
     * aplicaci&oacute;n. Los nombres apareceran ordenados de tal forma las
     * bibliotecas no tengan dependencias de otra que no haya aparecido
     * anterioremente en la lista.
     * @param path Ruta al directorio de NSS (terminado en barra).
     * @return Listado con los nombres de las bibliotecas. 
     */
    private static String[] getSoftkn3Dependencies(final String path) {

        if (path == null) {
            return new String[0];
        }

        if (OSTool.getSO().isMacOsX()) {
			LOG.error("NSS MacOS no soportado: ");
            return new String[0];
        }
        
        String nssPath = (!path.endsWith(File.separator) ? path + File.separator : path);

        if (OSTool.getSO().isWindows()) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("NSS Windows");
			}
			if (OSTool.getSO().is64bits()) {
                return new String[] {
                        nssPath + MSVCR100_DLL,
                        nssPath + MOZGLUE_DLL,
                        nssPath + NSS3_DLL,
                        nssPath + SOFTOKN3_DLL
                };
			} else {
				return new String[] {
						nssPath + MSVCR100_DLL,
						nssPath + MOZGLUE_DLL,
		                //nssPath + NSPR4_DLL,      // Firefox 2 y superior
		                //nssPath + PLC4_DLL,       // Firefox 2 y superior
		                //nssPath + PLDS4_DLL,      // Firefox 2 y superior
		                //nssPath + NSSUTIL3_DLL,   // Firefox 3 y superior
		                nssPath + NSS3_DLL,
		                //nssPath + MOZSQLITE3_DLL,
		                //nssPath + SMIME3_DLL,
						//nssPath + SSL3_DLL,
		                nssPath + SOFTOKN3_DLL
				};
/*			} else {
				return new String[] {
						//nssPath + MOZUTILS_DLL,   // Firefox 9
						nssPath + MOZCRT19_DLL,   // Firefox desde 3 hasta 8
						nssPath + NSPR4_DLL,      // Firefox 2 y superior
						nssPath + PLDS4_DLL,      // Firefox 2 y superior
						nssPath + PLC4_DLL,       // Firefox 2 y superior
						nssPath + NSSUTIL3_DLL,   // Firefox 3 y superior
						(new File(nssPath + MOZSQLITE3_DLL).exists())?(nssPath + MOZSQLITE3_DLL):(nssPath + SQLITE3_DLL), // MozSqlite Firefox 4 y superior. Sqlite Firefox 3
								nssPath + NSSDBM3_DLL,    // Firefox 3 y superior
								nssPath + NSS3_DLL,
								nssPath + FREEBL3_DLL,     // Firefox 3 y superior
								nssPath + SMIME3_DLL,
								nssPath + SSL3_DLL,
								nssPath + NSSCKBI_DLL,
								nssPath + SOFTOKN3_DLL     // Firefox 3 y superior                
				};
		*/	}
        } else if (OSTool.getSO().isLinux() || OSTool.getSO().getVersion().contains("olaris")) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("NSS Linux");
			}
            return new String[] {
                nssPath + "libnspr4.so",     // Firefox 2 y superior
                nssPath + "libplds4.so",     // Firefox 2 y superior
                nssPath + "libplc4.so",      // Firefox 2 y superior
                nssPath + "libnssutil3.so",  // Firefox 2 y superior
                nssPath + "libsqlite3.so",   // Firefox 2
                nssPath + "libmozsqlite3.so", // Firefox 3 y superior
                nssPath + "libsoftokn3.so" // Firefox 3 y superior
            };
        }

        LOG.error("Plataforma no soportada para la precarga de las bibliotecas NSS: " + OSTool.getSO()
              + " + Java " + OSTool.getSO().getVersion());
        return new String[0];
    }

	private static final String P11_CONFIG_VALID_CHARS = ":\\0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.\u007E"; //$NON-NLS-1$


	/** Obtiene el directorio del perfil de usuario de Mozilla / Firefox.
     * @return Ruta completa del directorio del perfil de usuario de Mozilla Firefox 
     */
    public static String getMozillaUserProfileDirectory() throws Exception {
        if (OSTool.getSO().isWindows()) {
        	return getMozillaUserProfileDirectoryWindows();
        } else if (OSTool.getSO().isMacOsX()) {
        	return getMozillaUserProfileDirectoryMacOsX();
        } else {
        	return getMozillaUserProfileDirectoryUnix();
        }
    }
    
	private static String getMozillaUserProfileDirectoryUnix() {
        // Se busca "profiles.ini" en el directorio de Firefox
        final File regFile = new File(System.getProperty("user.home") + "/.mozilla/firefox/profiles.ini");
        try {
            if (regFile.exists()) {
                return getFireFoxUserProfileDirectory(regFile);
            }
        } catch (final Exception e) {
            LOG.error("Error obteniendo el directorio de perfil de Firefox (UNIX): " + e);
        }
        return null;
	}

	private static String getMozillaUserProfileDirectoryWindows() throws Exception {
        final String appDataDir = WinRegistryUtils.readString(WinRegistryUtils.HKEY_CURRENT_USER,
             "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", "AppData");
        
        if (appDataDir != null) {
            String finalDir = null;
            // En Firefox se utiliza preferentemente profiles.ini
            File regFile = new File(appDataDir + "\\Mozilla\\Firefox\\profiles.ini");
            try {
                if (regFile.exists()) {
                    finalDir = getFireFoxUserProfileDirectory(regFile);
                }
            } catch (final Exception e) {
                LOG.error("Error obteniendo el directorio de perfil de Firefox: " + e);
                return null;
            }
            if (finalDir != null) {
        		for (final char c : finalDir.toCharArray()) {
        			if (P11_CONFIG_VALID_CHARS.indexOf(c) == -1) {
        				finalDir = finalDir.replace(System.getProperty("user.home"), 
        						getShort(System.getProperty("user.home")));
        				break;
        			}
        		}
                return finalDir.replace('\\', '/');
            }
        }
        LOG.error("Error obteniendo el directorio de perfil de usuario de Mozilla Firefox (Windows)");
        return null;

	}

	private static String getMozillaUserProfileDirectoryMacOsX() {
        // Si es Mac OS X, profiles.ini se encuentra en otra ruta
        final File regFile = new File(System.getProperty("user.home") + "/Library/Application Support/Firefox/profiles.ini");
        try {
            if (regFile.exists()) {
                return getFireFoxUserProfileDirectory(regFile);
            }
        } catch (final Exception e) {
            LOG.error("Error obteniendo el directorio de perfil de Firefox (" + regFile.getAbsolutePath() + "): " + e);
        }
        return null;
	}

    static void configureMacNSS(final String binDir) throws Exception {

        if (!OSTool.getSO().isMacOsX()) {
        	LOG.error("No se ha detectado MacOS: " + OSTool.getSO());
            return;
        }

        if (binDir == null) {
            LOG.error("El directorio de NSS para configurar proporcionado es nulo, no se realizara ninguna accion"); //$NON-NLS-1$
            return;
        }

        final String nssBinDir = (binDir.endsWith("/")) ? binDir : binDir + "/";

        // Se intenta la carga, por si no fuera necesaria la reconfiguracion
        try {
            System.load(nssBinDir + "libsoftokn3.dylib");
            return; // Si funciona salimos sin hacer nada
        } catch (final Exception e) {
            // Se ignora el error
        } catch(final UnsatisfiedLinkError e) {
        	// Se ignora el error
        }

        final String[] libs = new String[] {
            "libmozutils.dylib", // Firefox 9 y superiores
            "libnspr4.dylib",
            "libplds4.dylib",
            "libplc4.dylib",
            "libmozsqlite3.dylib",
            "libnssutil3.dylib"
        };

        // Creamos enlaces simbolicos via AppleScript
        final StringBuilder sb = new StringBuilder();
        for (final String lib : libs) {
            if (new File(nssBinDir + lib).exists()) {
                sb.append("ln -s ");
                sb.append(nssBinDir);
                sb.append(lib);
                sb.append(" /usr/lib/");
                sb.append(lib);
                sb.append("; ");
            }
        }
        try {
            final Class<?> scriptEngineManagerClass = Class.forName("javax.script.ScriptEngineManager");
            final Object scriptEngineManager = scriptEngineManagerClass.newInstance();
            final Method getEngineByNameMethod = scriptEngineManagerClass.getMethod("getEngineByName", String.class);
            final Object scriptEngine = getEngineByNameMethod.invoke(scriptEngineManager, "AppleScript");
            final Class<?> scriptEngineClass = Class.forName("javax.script.ScriptEngine");
            final Method evalMethod = scriptEngineClass.getMethod("eval", String.class);
            evalMethod.invoke(scriptEngine, "do shell script \"" + sb.toString() + "\" with administrator privileges"); //$NON-NLS-1$ //$NON-NLS-2$

            //new ScriptEngineManager().getEngineByName("AppleScript").eval("do shell script \"" + sb.toString() + "\" with administrator privileges");
        } catch(final Exception e) {
            LOG.error("No se ha podido crear los enlaces simbolicos para NSS: " + e);
        }

        // Se reintenta la carga, para comprobar que funcione
        try {
            System.load(nssBinDir + "libsoftokn3.dylib");
        } catch (final Exception e) {
            throw new Exception("La configuracion de NSS para Mac OS X ha fallado por motivos de seguridad: " + e);
        } catch(final UnsatisfiedLinkError e) {
        	throw new Exception("La configuracion de NSS para Mac OS X ha fallado: " + e);
        }
    }
	
    /** Devuelve el directorio del perfil activo de Firefox. Si no hubiese perfil
     * activo, devolver&iacute;a el directorio del perfil por defecto y si
     * tampoco lo hubiese el del primer perfil encontrado. Si no hubiese
     * perfiles configurados, devolver&iacute;a {@code null}.
     * @param iniFile Fichero con la informaci&oacute;n de los perfiles de Firefox.
     * @return Directorio con la informaci&oacute;n del perfil.
     * @throws IOException Cuando ocurre un error abriendo o leyendo el fichero. */
    private static String getFireFoxUserProfileDirectory(final File iniFile) throws IOException {
        if (iniFile == null) {
            throw new IllegalArgumentException("El fichero INI es nulo y no se podra determinar el directorio del usuario de firefox");
        } else if (!iniFile.exists() || !iniFile.isFile()) {
            throw new IOException("No se ha encontrado el fichero con los perfiles de firefox");
        }

        String currentProfilePath = null;

        // Se leen los perfiles y se busca el activo (que esta bloqueado)
        final FirefoxProfile[] profiles = readProfiles(iniFile);
        for (final FirefoxProfile profile : profiles) {
            if (isProfileLocked(profile)) {
                currentProfilePath = profile.getAbsolutePath();
                break;
            }
        }

        // Si no hay ninguno activo, se toma por defecto
        if (currentProfilePath == null) {
            for (final FirefoxProfile profile : profiles) {
                if (profile.isDefault()) {
                    currentProfilePath = profile.getAbsolutePath();
                    break;
                }
            }
        }

        // Si no hay ninguno por defecto, se toma el primero
        if (profiles.length > 0) {
            currentProfilePath = profiles[0].getAbsolutePath();
        }

        return currentProfilePath;
    }
    
    /** Parsea la informacion de los perfiles declarada en el fichero
     * "profiles.ini". Para identificar correctamente los perfiles es necesario
     * que haya al menos una l&iacute;nea de separaci&oacute;n entre los bloques
     * de informaci&oacute;n de cada perfil.
     * @param iniFile
     *        Fichero con lainformaci&oacute;n de los perfiles.
     * @return Listado de perfiles completos encontrados.
     * @throws IOException
     *         Cuando se produce un error durante la lectura de la
     *         configuraci&oacute;n. */
    private static FirefoxProfile[] readProfiles(final File iniFile) throws IOException {

        final String nameAtr = "name=";
        final String isRelativeAtr = "isrelative=";
        final String pathProfilesAtr = "path=";
        final String isDefaultAtr = "default=";

        String line = null;
        final List<FirefoxProfile> profiles = new ArrayList<FirefoxProfile>();
        final BufferedReader in = new BufferedReader(new FileReader(iniFile));
        try {
            while ((line = in.readLine()) != null) {

                // Se busca un nuevo bloque de perfil
                if (!line.trim().toLowerCase().startsWith("[profile")) {
                    continue;
                }

                final FirefoxProfile profile = new FirefoxProfile();
                while ((line = in.readLine()) != null && line.trim().length() > 0 && !line.trim().toLowerCase().startsWith("[profile")) {
                    if (line.trim().toLowerCase().startsWith(nameAtr)) {
                        profile.setName(line.trim().substring(nameAtr.length()));
                    } else if (line.trim().toLowerCase().startsWith(isRelativeAtr)) {
                        profile.setRelative(line.trim().substring(isRelativeAtr.length()).equals("1"));
                    } else if (line.trim().toLowerCase().startsWith(pathProfilesAtr)) {
                        profile.setPath(line.trim().substring(pathProfilesAtr.length()));
                    } else if (line.trim().toLowerCase().startsWith(isDefaultAtr)) {
                        profile.setDefault(line.trim().substring(isDefaultAtr.length()).equals("1"));
                    } else {
                        break;
                    }
                }

                if (profile.getName() != null || profile.getPath() != null) {
                    profile.setAbsolutePath(profile.isRelative() ? new File(iniFile.getParent(), profile.getPath()).toString() : profile.getPath());
                    profiles.add(profile);
                }
            }
        } catch (final Exception e) {
            throw new IOException("Error al leer la configuracion de los perfiles de Firefox: " + e);
        } finally {
            try { in.close(); } catch (final Exception e) { }
        }

        return profiles.toArray(new FirefoxProfile[profiles.size()]);
    }

    /** Comprueba que un perfil de Firefox est&eacute; bloqueado. Un perfil esta
     * bloqueado cuando en su directorio se encuentra el fichero "parent.lock".
     * @param profile
     *        Informaci&oacute;n del perfil de Firefox.
     * @return Devuelve {@code true} si el perfil esta bloqueado, {@code false} en caso contrario. */
    private static boolean isProfileLocked(final FirefoxProfile profile) {
        return new File(profile.getAbsolutePath(), "parent.lock").exists() || // Windows
               new File(profile.getAbsolutePath(), "lock").exists(); // UNIX
    }

    /** Clase que almacena la configuraci&oacute;n para la identificacion de un
     * perfil de Mozilla Firefox. */
    private static final class FirefoxProfile {
        private String name = null;
        
        String getName() {
            return this.name;
        }
        void setName(final String n) {
            this.name = n;
        }
        
        private boolean relative = true;
        
        boolean isRelative() {
            return this.relative;
        }
        void setRelative(final boolean r) {
            this.relative = r;
        }
        
        private String path = null;
        
        String getPath() {
            return this.path;
        }
        void setPath(final String p) {
            this.path = p;
        }
        
        private String absolutePath = null;
        
        String getAbsolutePath() {
            return this.absolutePath;
        }
        void setAbsolutePath(final String ap) {
            this.absolutePath = ap;
        }
        
        private boolean def = false;
        
        boolean isDefault() {
            return this.def;
        }
        void setDefault(final boolean d) {
            this.def = d;
        }
    }
}
