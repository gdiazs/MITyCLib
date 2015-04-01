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
package es.mityc.javasign.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.ConstantsAPI;

/**
 * <p>Clase de utilidades para obtener información sobre los sistemas operativos/navegadores.</p>
 *
 */
public final class OSTool { 
	
	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(OSTool.class);
	
	/** Cadena vacía. */
    private static final String STRING_EMPTY = ""; 
	/** Separador \. */
    private static final String STRING_BACKSLASH = "\\";
	/** Propiedad de sistema que tiene el nombre del sistema operativo. */
    private static final String OS_NAME = "os.name";
    /** Propiedad de sistema que tiene la versión del sistema operativo. */
    private static final String OS_VERSION = "os.version";
    /** Propiedad de sistema que tiene la arquitectura del sistema operativo. */
    private static final String OS_ARCH = "os.arch";
    /** Propiedad de sistema alternativa que tiene la arquitectura del sistema operativo. */
    private static final String OS_ARCH_ALTERNATIVE = "sun.arch.data.model";
    /** Cadena identificativa de Windows. */
    private static final String WIN = "win";
    /** Cadena identificativa de Linux. */
    private static final String LINUX = "linux";
    /** Cadena identificativa de Mac. */
    private static final String MAC_OS = "mac os x";
    /** Propiedad de sistema que indica la versión del plugin que ejecuta la máquina virtual. */
    private static final String JAVAPLUGIN_VERSION = "javaplugin.version";
    /** Propiedad de sistema que tiene el nombre del usuario de la sesión. */
    private static final String USER_NAME = "user.name";
    /** Propiedad de sistema que tiene el separador de rutas del sistema de ficheros. */
    private static final String FILE_SEPARATOR = "file.separator";

	/** Nombres de sistemas operativos Windows de tipo 4.0. */
	public static final String[] WINDOWS4_NAMES = {"windows 95", "windows 98", "windows 2000", "windows 9x" };
	/** Nombres de sistemas operativos Windows de tipo 5.0. */
	public static final String[] WINDOWS5_NAMES = {"windows 2000", "windows xp", "windows 2003", "windows nt"};
	/** Nombres de sistemas operativos Windows de tipo 6.0. */
	public static final String[] WINDOWS6_NAMES = {"windows vista", "windows 7", "windows server 2008", "windows server 2008 r2"};
	/** Versiones de sistemas operativos Windows. */
	public static final String[] WINDOWS_VERSIONS = { "4", "5", "6" };
	/** Arquitecturas de 64 bits de windows. */
	public static final String[] WINDOWS_ARCHS_64BITS = { "ia64", "amd64" };
	/** Cuando no es capaz de encontrar la versión de windows devuelve este valor: 5. */
	private static final int WINDOWS_DEFAULT_VERSION = 5;
	/** Versiones de sistemas operativos Linux. */
	public static final String[] LINUX_VERSIONS = {"24", "26"};
	/** Versiones de sistemas operativos Mac OS X. */
	public static final String[] MACOSX_VERSIONS = {"104", "105", "106" };
	/** Arquitecturas de 64 bits de Mac OS X. */
	public static final String[] MACOSX_ARCHS_64BITS = { "x86_64" };
	/** Arquitecturas de 64 bits de la máquina virtual. */
	public static final String[] SUN_ARCHS = { "32", "64" };
	/** Enumerado de sistemas operativos reconocidos. */
	public enum OS_NAMES { UNKNOWN, WINDOWS, LINUX, MAC_OS_X };
	/** Enumerado de versión en bits del sistema operativo. */
	public enum OS_BITS { UNKNOWN, OS32BITS, OS64BITS };
	
	/** Enumerado de sistemas operativos reconocidos. */
	public enum OS {
		/** Sistema operativo desconocido. */
		UNKNOWN(OS_NAMES.UNKNOWN, STRING_EMPTY, OS_BITS.UNKNOWN, "unknown"),
		/** Windows 4.x 32 bits. */
		WIN_4_32(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[0], OS_BITS.OS32BITS, "Windows 4.0 32bits"),
		/** Windows 4.x 64 bits. */
		WIN_4_64(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[0], OS_BITS.OS64BITS, "Windows 4.0 64bits"),
		/** Windows 5.x 32 bits. */
		WIN_5_32(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[1], OS_BITS.OS32BITS, "Windows 5.0 32bits"),
		/** Windows 5.x 64 bits. */
		WIN_5_64(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[1], OS_BITS.OS64BITS, "Windows 5.0 64bits"),
		/** Windows 5.x 32 bits. */
		WIN_6_32(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[1], OS_BITS.OS32BITS, "Windows 6.0 32bits"),
		/** Windows 5.x 64 bits. */
		WIN_6_64(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[1], OS_BITS.OS64BITS, "Windows 6.0 64bits"),
		/** Linux 2.4 32 bits. */
		LIN_24_32(OS_NAMES.LINUX, LINUX_VERSIONS[0], OS_BITS.OS32BITS, "Linux 2.4 32bits"),
		/** Linux 2.4 64 bits. */
		LIN_24_64(OS_NAMES.LINUX, LINUX_VERSIONS[0], OS_BITS.OS64BITS, "Linux 2.4 64bits"),
		/** Linux 2.6 32 bits. */
		LIN_26_32(OS_NAMES.LINUX, LINUX_VERSIONS[1], OS_BITS.OS32BITS, "Linux 2.6 32bits"),
		/** Linux 2.6 64 bits. */
		LIN_26_64(OS_NAMES.LINUX, LINUX_VERSIONS[1], OS_BITS.OS64BITS, "Linux 2.6 64bits"),
		/** Mac OS X  10.4 32 bits. */
		MACOSX_104_32(OS_NAMES.MAC_OS_X, MACOSX_VERSIONS[0], OS_BITS.OS32BITS, "Mac OS X 10.4 32bits"),
		/** Mac OS X  10.4 64 bits. */
		MACOSX_104_64(OS_NAMES.MAC_OS_X, MACOSX_VERSIONS[0], OS_BITS.OS64BITS, "Mac OS X 10.4 64bits"),
		/** Mac OS X  10.5 32 bits. */
		MACOSX_105_32(OS_NAMES.MAC_OS_X, MACOSX_VERSIONS[1], OS_BITS.OS32BITS, "Mac OS X 10.5 32bits"),
		/** Mac OS X  10.5 64 bits. */
		MACOSX_105_64(OS_NAMES.MAC_OS_X, MACOSX_VERSIONS[1], OS_BITS.OS64BITS, "Mac OS X 10.5 64bits"),
		/** Mac OS X  10.6 32 bits. */
		MACOSX_106_32(OS_NAMES.MAC_OS_X, MACOSX_VERSIONS[1], OS_BITS.OS32BITS, "Mac OS X 10.6 32bits"),
		/** Mac OS X  10.6 64 bits. */
		MACOSX_106_64(OS_NAMES.MAC_OS_X, MACOSX_VERSIONS[1], OS_BITS.OS64BITS, "Mac OS X 10.6 64bits");
		
		
		/** Nombre genérico del sistema operativo. */
		private OS_NAMES osvalue;
		/** Versión del kernel del sistema operativo. */
		private String version;
		/** Bits de compilación del kernel del sistema operativo. */
		private OS_BITS bits;
		/** Cadena descriptiva del sistema operativo.*/
		private String desc;
		
		/**
		 * <p>Constructor.</p>
		 * @param osname Familia del sistema operativo
		 * @param osversion Versión del kernel del sistema operativo
		 * @param osbits Bits de la compilación del kernel
		 * @param description Cadena descriptiva del sistema operativo
		 */
		private OS(final OS_NAMES osname, final String osversion, final OS_BITS osbits, final String description) {
			this.osvalue = osname;
			this.version = osversion;
			this.bits = osbits;
			this.desc = new String(description);
		}
		/**
		 * <p>Indica si el sistema operativo pertenece a la familia Windows.</p>
		 * @return <code>true</code> si es de la familia Windows, <code>false</code> en otro caso
		 */
		public boolean isWindows() {
			if (OS_NAMES.WINDOWS.equals(osvalue)) {
				return true;
			}
			return false;
		}
		/**
		 * <p>Indica si el sistema operativo pertenece a la familia Linux.</p>
		 * @return <code>true</code> si es de la familia Linux, <code>false</code> en otro caso
		 */
		public boolean isLinux() {
			if (OS_NAMES.LINUX.equals(osvalue)) {
				return true;
			}
			return false;
		}
		/**
		 * <p>Indica si el sistema operativo pertenece a la familia Mac OS X.</p>
		 * @return <code>true</code> si es de la familia Mac OS X, <code>false</code> en otro caso
		 */
		public boolean isMacOsX() {
			if (OS_NAMES.MAC_OS_X.equals(osvalue)) {
				return true;
			}
			return false;
		}
		/**
		 * <p>Indica si el kernel del sistema operativo es de 32 bits.</p>
		 * @return <code>true</code> si el kernel es de 32 bits, <code>false</code> en otro caso
		 */
		public boolean is32bits() {
			if (OS_BITS.OS32BITS.equals(bits)) {
				return true;
			}
			return false;
		}
		/**
		 * <p>Indica si el kernel del sistema operativo es de 64 bits.</p>
		 * @return <code>true</code> si el kernel es de 64 bits, <code>false</code> en otro caso
		 */
		public boolean is64bits() {
			if (OS_BITS.OS64BITS.equals(bits)) {
				return true;
			}
			return false;
		}
		/**
		 * <p>Devuelve la versión del sistema operativo dentro de la familia.</p>
		 * @return Cadena con la versión del sistema operativo
		 */
		public String getVersion() {
			return version;
		}
		
		/**
		 * <p>Devuelve una cadena descriptiva del sistema operativo descrito por el enumerado.</p>
		 * @return cadena descriptiva del SO
		 */
		@Override
		public String toString() {
			return desc;
		}
	}
	
	
	/**
	 * <p>Constructor.</p>
	 */
	private OSTool() {
	}
	
	/** Variable estática con el sistema operativo de la actual ejecución. */
	private static OS actualSO = askSO();
	
	/**
	 * <p>Comprueba si el windows es de 64 bits.</p>
	 * @return <code>true</code> si el windows es reconocido de 64bits, <code>false</code> en otro caso
	 */
	private static boolean isWindows64bits() {
		boolean res = isSun64bits();
		if (!res) {
			String osArch = System.getProperty(OS_ARCH).toLowerCase();
			for (int i = 0; i < WINDOWS_ARCHS_64BITS.length; i++) {
				if (osArch.startsWith(WINDOWS_ARCHS_64BITS[i])) {
					res = true;
					break;
				}
			}
		}
		return res;
	}
	
	/**
	 * <p>Comprueba si el Mac OS X es de 64 bits.</p>
	 * @return <code>true</code> si el Mac OS X es reconocido de 64bits, <code>false</code> en otro caso
	 */
	private static boolean isMacosx64bits() {
		boolean res = isSun64bits();
		if (!res) {
			String osArch = System.getProperty(OS_ARCH).toLowerCase();
			for (int i = 0; i < MACOSX_ARCHS_64BITS.length; i++) {
				if (osArch.startsWith(MACOSX_ARCHS_64BITS[i])) {
					res = true;
					break;
				}
			}
		}
		return res;
	}

	/**
	 * <p>Comprueba si la máquina virtual es de 64 bits.</p>
	 * @return <code>true</code> si la propiedad <code>sun.arch.data.model</code>
	 */
	protected static boolean isSun64bits() {
		boolean res = false;
		String osArch = System.getProperty(OS_ARCH_ALTERNATIVE).toLowerCase();
		if (osArch != null && osArch.startsWith(SUN_ARCHS[1])) {
			res = true;
		}
		return res;
	}

	/**
	 * <p>Recupera el número de versiós mayor de windows.</p>
	 * @return en la versión <code>major.minor</code> de windows devuelve <code>major</code>
	 */
	private static int getWindowsMajorVersion() {
		int version = WINDOWS_DEFAULT_VERSION; 
		String osVersion = System.getProperty(OS_VERSION);
		try {
			version = Integer.parseInt(osVersion.substring(0, osVersion.indexOf(".")));
		} catch (NumberFormatException ex) {
		}
		return version;
	}
	
	/**
	 * <p>Recupera el sustema operativo en el que se ejecuta la máquina virtual.</p>
	 * @return enumerado SO con el sistema operativo detectado
	 */
	public static OS askSO() {
    	OS res = OS.UNKNOWN;
		// Obtiene el sistema operativo de las propiedades de sistema
		String osName = System.getProperty(OS_NAME);
		LOGGER.debug("SO: " + osName);
        if (osName.toLowerCase().startsWith(WIN)) {
        	switch (getWindowsMajorVersion()) {
	    		case 5:
	    			if (isWindows64bits()) {
	    				res = OS.WIN_5_64;
	    			} else {
	    				res = OS.WIN_5_32;
	    			}
	    			break;
	    		case 6:
	    			if (isWindows64bits()) {
	    				res = OS.WIN_6_64;
	    			} else {
	    				res = OS.WIN_6_32;
	    			}
	    			break;
        		case 4:
    			default:
        			if (isWindows64bits()) {
        				res = OS.WIN_4_64;
        			} else {
        				res = OS.WIN_4_32;
        			}
        			break;
        	}
        	LOGGER.trace("Es un windows: " + res);
        } else if (osName.toLowerCase().startsWith(LINUX)) {
        	LOGGER.trace("Es un linux");
        	String osVersion = System.getProperty(OS_VERSION);
        	if (osVersion.startsWith(LINUX_VERSIONS[0])) {
        		if (isSun64bits()) {
        			res = OS.LIN_24_64;
        		} else {
        			res = OS.LIN_24_32;
        		}
			} else if (osVersion.startsWith(LINUX_VERSIONS[1])) {
        		if (isSun64bits()) {
        			res = OS.LIN_26_64;
        		} else {
        			res = OS.LIN_26_32;
        		}
			} else {
				// Si no encuentra qué versión es, le aplica la última conocida
        		if (isSun64bits()) {
        			res = OS.LIN_26_64;
        		} else {
        			res = OS.LIN_26_32;
        		}
			}
        } else if (osName.toLowerCase().startsWith(MAC_OS)) {
        	LOGGER.trace("Es un Mac OS X");
        	String osVersion = System.getProperty(OS_VERSION);
        	if (osVersion.startsWith(MACOSX_VERSIONS[0])) {
        		if (isMacosx64bits()) {
        			res = OS.MACOSX_104_64;
        		} else {
        			res = OS.MACOSX_104_32;
        		}
        	} else if (osVersion.startsWith(MACOSX_VERSIONS[1])) {
        		if (isMacosx64bits()) {
        			res = OS.MACOSX_105_64;
        		} else {
        			res = OS.MACOSX_105_32;
        		}
        	} else if (osVersion.startsWith(MACOSX_VERSIONS[2])) {
        		if (isMacosx64bits()) {
        			res = OS.MACOSX_106_64;
        		} else {
        			res = OS.MACOSX_106_32;
        		}
        	} else {
				// Si no encuentra qué versión es, le aplica la última conocida
        		if (isMacosx64bits()) {
        			res = OS.MACOSX_106_64;
        		} else {
        			res = OS.MACOSX_106_32;
        		}
        	}
        }
		return res;
	}
	
	/**
	 * <p>Devuelve el sistema operativo en el que se ejecuta la aplicación.</p>
	 * @return elemento del enumerado con los datos del sistema operativo
	 */
	public static OS getSO() {
		return actualSO;
	}
    
    /** Indica si se está ejecutando bajo un plugin de Java. */
	private static boolean javaplugin = false;
    static {
        String pluginVersion = System.getProperty(JAVAPLUGIN_VERSION);
        if (pluginVersion != null) {
			javaplugin = true;
		}
    }
    /**
     * <p>Indica si la clase se está ejecutando desde un plugin (applet, jsdl, etc).</p>
     * @return <code>true</code> si se está ejecutando desde un plugin, <code>false</code> en otro caso
     */
    public static boolean isPlugin() {
    	return javaplugin;
    }
    
    /**
     * <p>Indica si el sistema operativo en el que se ejecuta la clase es Linux.</p>
     * @return <code>true</code> si el sistema operativo es Linux, <code>false</code> en otro caso
     * @deprecated Utilizar el enumerado OS obtenido a través de {@link OSTool#getSO()}
     * @see es.mityc.javasign.utils.OSTool#getSO()
     */
    public static boolean isOSLinux() {
        if (System.getProperty(OS_NAME).toLowerCase().startsWith(LINUX)) {
			return true;
		}
        return false;
    }
    
    /**
     * <p>Indica si el sistema operativo en el que se ejecuta la clase es Windows.</p>
     * @return <code>true</code> si el sistema operativo es Windows, <code>false</code> en otro caso
     * @deprecated Utilizar el enumerado OS obtenido a través de {@link OSTool#getSO()}
     * @see es.mityc.javasign.utils.OSTool#getSO()
     */
    public static boolean isOSWindows() {
        if (System.getProperty(OS_NAME).toLowerCase().startsWith(WIN)) {
			return true;
		}
        return false;
    }
    
    /**
     * <p>Devuelve el directorio raíz del usuario.</p>
     * @return directorio raíz del usuario
     */
    public static String getUserHome() {
        String home = System.getProperty(ConstantsAPI.SYSTEM_PROPERTY_USER_HOME);
        if (isOSWindows()) {
            // encontrar la unidad de instalación
            String path = home.substring(0, home.indexOf(STRING_BACKSLASH));
            return path.replace('\\', '/');
        } else {
			return home;
		}
    }
    
    /**
     * <p>Devuelve el nombre del usuario.</p>
     * @return Nombre del usuario
     */
    public static String getUserName() {
        return System.getProperty(USER_NAME);
    }
    
    /**
     * <p>Devuelve el separador de ficheros.</p>
     * @return caracter de separacion de ficheros
     * @deprecated utilizar File.Separator;
     */
    public static String getFileSeparator() {
        if (isOSWindows()) {
			return System.getProperty(FILE_SEPARATOR).replace('\\', '/');
		} else {
			return System.getProperty(FILE_SEPARATOR);
		}
    }
    
    /**
     * <p>Devuelve el directorio temporal.</p>
     * @return directorio temporal
     */
    public static String getTempDir() {
        return System.getProperty(ConstantsAPI.SYSTEM_PROPERTY_TMP_DIR);
    }
    
    /**
     * <p>Devuelve el directorio Home.</p>
     * @return directorio Home 
     */
    public static String getHomeDir() {
        return getUserHome();
    }
}
