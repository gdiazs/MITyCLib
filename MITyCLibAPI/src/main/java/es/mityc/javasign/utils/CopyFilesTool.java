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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.zip.Adler32;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.exception.CopyFileException;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.trust.TrustFactory;
import es.mityc.javasign.utils.OSTool.OS;

/**
 * <p>Utilidad para el copiado de ficheros con integridad.</p>
 * 
 * <p>Esta librería accede a un fichero de propiedades donde se relaciona una clave con un conjunto de recursos. Bajo petición puede copiar
 * esos recursos a un lugar físico. En caso de ya existir comprueba la integridad de esos ficheros y si no la cumple procede a su
 * sustitución.</p>
 * 
 * <h3>Formato del fichero de propiedades</h3>
 * <p>En primer lugar se asocia un conjunto de ficheros a una clave. Cuando se indique que se quiere copiar la clave indicada se copiarán
 * todos los ficheros referenciados en la clave. En el caso de ser una copia en función del sistema operativo se deberán crear tantas
 * claves (relacionadas con los ficheros específicos del SO) como sistemas operativos se quiera atender. Las claves reconocidas son:
 * <ul><li>windows:
 * 	<ul>
 * 		<li>windows4: familia 4.0 de Windows</li>
 * 		<li>windows5: familia 5.0 de Windows</li>
 * 		<li>windows6: familia 5.0 de Windows</li>
 * 		<li>windows: familia Windows</li>
 * 	</ul></li>
 * <li>linux:
 * 	<ul>
 * 		<li>linux24: familia 2.4 de Linux</li>
 * 		<li>linux26: familia 2.6 de Linux</li>
 * 		<li>linux: familia de Linux</li>
 * 	</ul></li>
 * <li>Mac OS X:
 * 	<ul>
 * 		<li>macosx104: familia Mac OS X 10.4</li>
 * 		<li>macosx105: familia Mac OS X 10.5</li>
 * 		<li>macosx106: familia Mac OS X 10.6</li>
 * 		<li>macosx: familia Mac OS X</li>
 * 	</ul></li>
 * </ul></p>
 * <p>En segundo lugar, cada fichero indicado en una clave ha de tener un conjunto de 4 valores que definen:<ul>
 * <li><code>file.<i>[clave]</i>.name</code>: Nombre del fichero que se quiere copiar/reemplazar</li>
 * <li><code>file.<i>[clave]</i>.res</code>: Localización del recurso que se copiará</li>
 * <li>Uno de los dos valores en función de la comprobación que quiera:<ul>
 * <li><code>file.<i>[clave]</i>.Adler32</code>: Valor del CRC32 con el algoritmo Adler del fichero</li>
 * <li><code>file.<i>[clave]</i>.SHA2</code>: Digest del fichero con el algoritmo SHA-2, en hexadecimal</li></ul>
 * <li><code>file.<i>[clave]</i>.size</code>: Tamaño en bytes del fichero</li>
 * </ul></p>
 * <h3>Ejemplo</h3>
 * <pre>
 * windows5.explorer=CSPBridge
 * file.CSPBridge.name=DLLFirmaVC.dll
 * file.CSPBridge.res=libs/DLLFirmaVC.dll
 * file.CSPBridge.Adler32=1206082769
 * file.CSPBridge.SHA2=6c53a450dc95a3ce17e494631b00beffa0c0a01718849402d5ec4f82b9f8ea56
 * file.CSPBridge.size=45056
 * </pre>
 * <p><b>Nota</b>: En el caso de la partícula de windows además se permite indicar recursos específicos para
 * entornos de 64bits indicando la partícula <code>_64</code> detrás del nombre de SO. V.G.:
 * <code>windows6_64.explorer=CSPBridge</code></p>  
 * 
 */
public class CopyFilesTool {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(CopyFilesTool.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsAPI.LIB_NAME);
	
	/** Tamaño en bytes del buffer interno de lectura. */
	private static final int BUFFER_IN_SIZE = 32000;
	/** Tamaño en bytes del buffer interno de escritura. */
	private static final int BUFFER_OUT_SIZE = 4096;
	/** Identificador del digester SHA-2. */
	private static final String DIGEST_SHA_256 = "SHA-256";
	/** Nombre del campo del ClassLoader relacionado con los paths de sistema. */
	private static final String FIELD_SYS_PATHS = "sys_paths";

	/** Prefijo de propiedad de fichero. */
	private static final String STR_FILE_DOT = "file.";
	/** Sufijo de nombre de fichero. */
	private static final String STR_DOT_NAME = ".name";
	/** Sufijo de nombre de recurso. */
	private static final String STR_DOT_RES = ".res";
	/** Sufijo de CRC Adler32 del recurso. */
	private static final String STR_DOT_ADLER32 = ".Adler32";
	/** Sufijo de CRC SHA-2 del recurso. */ 
	private static final String STR_DOT_SHA2 = ".SHA2";
	/** Sufijo de tamaño en bytes del recurso. */
	private static final String STR_DOT_SIZE = ".size";
	/** Propiedad de separador de ficheros englobados. */ 
	private static final String STR_FILE_SEPARATOR = ",";
	
	/** Prefijo de propiedades relacionadas con recursos para windows. */
	private static final String STR_OS_NAME_WIN = "windows";
	/** Prefijo de propiedades relacionadas con recursos para linux. */
	private static final String STR_OS_NAME_LIN = "linux";
	/** Prefijo de propiedades relacionadas con recursos para mac os x. */
	private static final String STR_OS_NAME_MACOSX = "macosx";
	/** Partícula para indicar que el recurso es para un SO de 64 bits. */
	private static final String STR_OS_64BITS = "_64";
	
	/** Propiedades de configuración que utilizar esta instancia para obtener los recursos. */
	private Properties props = null;
	/** ClassLoader utilizado para recuperar las propiedades y los recursos. */
	private ClassLoader internalClassLoader = null;
	/** . */
	private Vector<String> vCopiedLibraries= new Vector<String>();
	
	/** Tipos de CRC admitidos para el cálculo de integridad. */
	public enum CrcIntegrityEnum { ADLER32, SHA2 };
	
	/**
	 * <p>Clase que define la base de los esquemas de integridad.</p>
	 * <p>Cada tipo concreto de integridad deberá tener una clase que extienda de esta.</p>
	 */
	private abstract class CRCInfo {
		/**
		 * <p>Procesa la cadena indicada para obtener el valor CRC que se espera.</p>
		 * @param value Cadena que tiene el valor CRC esperado
		 * @throws CopyFileException Lanzada si la cadena no se ajusta al CRC que admite esta clase
		 */
		protected abstract void processValue(String value) throws CopyFileException;
		/**
		 * <p>Devuelve el tipo de CRC implementado.</p>
		 * @return tipo del enumerado {@link CrcIntegrityEnum} que implementa
		 */
		protected abstract CrcIntegrityEnum getCrcType();
		/**
		 * <p>Chequea que el fichero indicado tenga el crc esperado.</p>
		 * @param file Fichero que se quiere comprobar
		 * @return <code>true</code> si el fichero se ajusta al valor esperado, <code>false</code> en otro caso
		 * @throws CopyFileException Lanzada si no ha podido calcular el crc del fichero
		 */
		public abstract boolean checkFile(File file) throws CopyFileException;
	}
	/**
	 * <p>Implementación del cálculo de CRC mediante Adler32.</p>
	 */
	private class Adler32Info extends CRCInfo {
		/** CRC esperado. */
		private long crc;
		/**
		 * <p>Procesa la cadena indicada recuperando el valor numérico Int32 que señala un CRC Adler32.</p>
		 * @param value Cadena que tiene el valor CRC esperado en forma de número int32
		 * @throws CopyFileException Lanzada si la cadena no se ajusta al CRC que admite esta clase
		 * @see es.mityc.javasign.utils.CopyFilesTool.CRCInfo#processValue(java.lang.String)
		 */
		@Override
		public void processValue(final String value) throws CopyFileException {
			try {
				crc = Long.parseLong(value);
			} catch (NumberFormatException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_5), ex);
				throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_5));
			}
		}
		/**
		 * <p>Devuelve el tipo Adler32.</p>
		 * @return CrcIntegrityEnum.ADLER32
		 * @see es.mityc.javasign.utils.CopyFilesTool.CRCInfo#getCrcType()
		 */
		@Override
		public CrcIntegrityEnum getCrcType() {
			return CrcIntegrityEnum.ADLER32;
		}
		/**
		 * <p>Devuelve el crc esperado.</p>
		 * @return crc esperado
		 */
		public long getCrcValue() {
			return crc;
		}
		/**
		 * <p>Chequea que el fichero indicado tenga el crc Adler32 esperado.</p>
		 * @param file Fichero que se quiere comprobar
		 * @return <code>true</code> si el fichero se ajusta al valor esperado, <code>false</code> en otro caso
		 * @throws CopyFileException Lanzada si no ha podido calcular el crc del fichero
		 * @see es.mityc.javasign.utils.CopyFilesTool.CRCInfo#checkFile(java.io.File)
		 */
		@Override
		public boolean checkFile(final File file) throws CopyFileException {
			try {
				Adler32 crcAdler = new Adler32();
		        @SuppressWarnings("resource")
				InputStream in = new BufferedInputStream(new FileInputStream(file), BUFFER_IN_SIZE);
				byte[] buffer = new byte[BUFFER_OUT_SIZE];
				int readed = in.read(buffer);
				while (readed > 0) {
					crcAdler.update(buffer, 0, readed);
					readed = in.read(buffer);
				}
				if (LOG.isTraceEnabled()) {
					LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_13, crcAdler.getValue(), getCrcValue()));
				}
				if (crcAdler.getValue() != getCrcValue()) {
					return false;
				}
				return true;
			} catch (IOException ex) {
				throw new CopyFileException(ex);
			}
		}
	}
	/**
	 * <p>Implementación del cálculo de CRC mediante SHA-2.</p>
	 */
	private class SHA2Info extends CRCInfo {
		/** CRC esperado. */
		private String crc; 
		/**
		 * <p>Procesa la cadena indicada recuperando el valor numérico Int32 que señala un CRC Adler32.</p>
		 * @param value Cadena que tiene el valor CRC esperado en forma de número int32
		 * @throws CopyFileException Lanzada si la cadena no se ajusta al CRC que admite esta clase
		 * @see es.mityc.javasign.utils.CopyFilesTool.CRCInfo#processValue(java.lang.String)
		 */
		@Override
		public void processValue(final String value) throws CopyFileException {
			// TODOLARGO: eliminar los leadings zeros
			crc = new String(value);
		}
		/**
		 * <p>Devuelve el tipo SHA-2.</p>
		 * @return CrcIntegrityEnum.SHA2
		 * @see es.mityc.javasign.utils.CopyFilesTool.CRCInfo#getCrcType()
		 */
		@Override
		public CrcIntegrityEnum getCrcType() {
			return CrcIntegrityEnum.SHA2;
		}
		/**
		 * <p>Devuelve el crc esperado.</p>
		 * @return crc esperado
		 */
		public String getCrcValue() {
			return crc;
		}
		/**
		 * <p>Chequea que el fichero indicado tenga el crc SHA-2 esperado.</p>
		 * @param file Fichero que se quiere comprobar
		 * @return <code>true</code> si el fichero se ajusta al valor esperado, <code>false</code> en otro caso
		 * @throws CopyFileException Lanzada si no ha podido calcular el crc del fichero
		 * @see es.mityc.javasign.utils.CopyFilesTool.CRCInfo#checkFile(java.io.File)
		 */
		@Override
		public boolean checkFile(final File file) throws CopyFileException {
			try {
				MessageDigest md = MessageDigest.getInstance(DIGEST_SHA_256);
		        @SuppressWarnings("resource")
				InputStream entrada = new BufferedInputStream(new FileInputStream(file), BUFFER_IN_SIZE);
				byte[] buffer = new byte[BUFFER_OUT_SIZE];
				int readed = entrada.read(buffer);
				while (readed > 0) {
					md.update(buffer, 0, readed);
					readed = entrada.read(buffer);
				}
				String crcRes = toHexString(md.digest());
				if (LOG.isTraceEnabled()) {
					LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_13, crcRes, getCrcValue()));
				}
	
				if (!crcRes.equalsIgnoreCase(getCrcValue())) {
					return false;
				}
				return true;
			} catch (IOException ex) {
				throw new CopyFileException(ex);
			} catch (NoSuchAlgorithmException ex) {
				throw new CopyFileException(ex);
			}
		}
	}
	
	/**
	 * <p>Crea una instancia de la herramienta de copia de ficheros tomando como fuente de la información el recurso de propiedades indicado.</p>
	 * 
	 * @param fileProperties Nombre del recurso que contiene las propiedades de los ficheros que puede copiar
	 */
	public CopyFilesTool(final String fileProperties) {
		this(fileProperties, getClassLoader());
	}
	
	/**
	 * <p>Crea una instancia de la herramienta de copia de ficheros tomando como fuente de la información el recurso de propiedades indicado.</p>
	 * 
	 * @param fileProperties Nombre del recurso que contiene las propiedades de los ficheros que puede copiar
	 * @param cl ClassLoader que se utilizará para el acceso al recurso de propiedades y a los recursos allí indexados
	 */
	public CopyFilesTool(final String fileProperties, final ClassLoader cl) {
		this.internalClassLoader = cl;
		loadProperties(fileProperties);
	}
	
	/**
	 * <p>Carga el recurso de propiedades indicado.</p>  
	 * @param fileProperties nombre del recurso que contiene las propiedades
	 */
	private void loadProperties(final String fileProperties) {
		try {
			// cambia el orden del listado de recursos
			ArrayList<URL> resources = new ArrayList<URL>();
			Enumeration<URL> en = internalClassLoader.getResources(fileProperties);
			while (en.hasMoreElements()) {
				resources.add(0, en.nextElement());
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_17, resources.size(), fileProperties));
			}
			// carga cada conjunto de propiedades de atrás hacia adelante para respetar el orden del classpath
			Properties base = null;
			Iterator<URL> itResources = resources.iterator();
			while (itResources.hasNext()) {
				URL url = itResources.next();
				try {
					InputStream is = url.openStream();
					Properties properties = new Properties(base);
					properties.load(is);
					base = properties;
				} catch (IOException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_1, url, ex.getMessage()));
				}
			}
			props = base;
		} catch (IOException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_1, fileProperties, ex.getMessage()));
		}
	}
	
	/**
	 * <p>Recupera el ClassLoader de contexto si está disponible.</p>
	 * <p>Si no está disponible el de contexto devuelve el propio de la clase.</p>
	 * @return ClassLoader
	 */
	private static ClassLoader getClassLoader() {
		try {
			ClassLoader cl = AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
			    public ClassLoader run() {
					ClassLoader classLoader = null;
					try {
					    classLoader = Thread.currentThread().getContextClassLoader();
					} catch (SecurityException ex) {
					}
					return classLoader;
			    }
			});
			if (cl != null) {
				return cl;
			}
		} catch (Exception ex) {
		}
		return TrustFactory.class.getClassLoader();
	}
	
	/**
	 * <p>Busca la clave más completa disponible.</p>
	 * <p>Busca las claves formándolas de la siguente manera:
	 * 	<ul>
	 * 		<li>so+version+arch</li>
	 * 		<li>so+arch</li>
	 * 		<li>so+verion</li>
	 * 		<li>so</li>
	 * 	</ul>
	 * </p>
	 * 
	 * @param so Nombre del sistema operativo
	 * @param version Version del kernel del sistema operativo
	 * @param arch Arquitectura (32 o 64 bits)
	 * @param addendum sufijo que se busca
	 * @return Propiedad que se haya encontrado más completa
	 */
	private String getKeyOS(final String so, final String version, final String arch, final String addendum) {
		String res = addStrings(so, version, arch, addendum);
		if (!hasProp(res)) { // Si no existe se recupera la clave sin tener en cuenta la arquitectura
			res = addStrings(so, arch, addendum);
			if (!hasProp(res)) {
				res = addStrings(so, version, addendum);
				if (!hasProp(res)) {
					res = addStrings(so + addendum);
				}
			}
		}
		return res;
	}
	
	/**
	 * <p>Devuelve un valor de cadena aunque la cadena esté nulificada.</p>
	 * @param varargs Cadenas a concatenar
	 * @return las cadenas concatenadas, cambiando las cadenas nulificadas por cadenas vacías
	 */
	private String addStrings(String... varargs) {
		StringBuffer sb = new StringBuffer("");
		for (String phrase : varargs) {
			if (phrase != null) {
				sb.append(phrase);
			}
		}
		return sb.toString();
	}
	
	/**
	 * <p>Comprueba si hay ficheros relacionados con el sistema operativo y si los hay, comprueba si es necesario volver a copiarlos
	 * (comprobando su integridad).</p>
	 * 
	 * <p>Para buscar los ficheros relacionados con el sistema operativo compone un nombre dependiente del sistema operativo y le añade
	 * el addendum indicado. Sistemas operativos que busca:
	 * <ul>
	 *   <li>Windows</li>
	 *   <li>Linux</li>
	 *   <li>Mac OS X</li>
	 * </ul></p>
	 * 
	 * @param dir Directorio donde se copiarán los ficheros (si su valor en null se copiará al directorio temporal)
	 * @param addendum Nombre de la clave que identifica los ficheros que se copiarán.
	 * @param updateLibraryPath indica si se debe actualizar la variable LibraryPath de java con la ubicación de los ficheros copiados
	 * @return devuelve el directorio donde se hizo la copia de los recursos
	 * @throws CopyFileException si no existe la clave indicada o algunos de los ficheros como recurso
	 */
	public String copyFilesOS(final String dir, final String addendum, final boolean updateLibraryPath) throws CopyFileException {
		return copyFilesOS(dir, addendum, updateLibraryPath, null);
	}
	
	/**
	 * <p>Comprueba si hay ficheros relacionados con el sistema operativo y si los hay, comprueba si es necesario volver a copiarlos
	 * (comprobando su integridad).</p>
	 * 
	 * <p>Para buscar los ficheros relacionados con el sistema operativo compone un nombre dependiente del sistema operativo y le añade
	 * el addendum indicado. Sistemas operativos que busca:
	 * <ul>
	 *   <li>Windows</li>
	 *   <li>Linux</li>
	 *   <li>Mac OS X</li>
	 * </ul></p>
	 * 
	 * @param dir Directorio donde se copiarán los ficheros (si su valor en null se copiará al directorio temporal)
	 * @param addendum Nombre de la clave que identifica los ficheros que se copiarán.
	 * @param updateLibraryPath indica si se debe actualizar la variable LibraryPath de java con la ubicación de los ficheros copiados
	 * @param suffix Sufijo a concatenar en el nombre de la dll a copiar
	 * @return devuelve el directorio donde se hizo la copia de los recursos
	 * @throws CopyFileException si no existe la clave indicada o algunos de los ficheros como recurso
	 */
	public String copyFilesOS(final String dir, final String addendum, final boolean updateLibraryPath, String suffix) throws CopyFileException {
		String key;
		OS so = OSTool.getSO();
		if (LOG.isTraceEnabled()) {
			LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_14, so.toString()));
			LOG.trace("Arquitectura 64b?" + OSTool.isSun64bits());
		}
		if (so.isWindows()) {
			key = getKeyOS(STR_OS_NAME_WIN, so.getVersion(), (OSTool.isSun64bits()) ? STR_OS_64BITS : null, (addendum != null) ? "." + addendum : null);
		} else if (so.isLinux()) {
			key = getKeyOS(STR_OS_NAME_LIN, so.getVersion(), (OSTool.isSun64bits()) ? STR_OS_64BITS : null, (addendum != null) ? "." + addendum : null);
		} else if (so.isMacOsX()) {
			key = getKeyOS(STR_OS_NAME_MACOSX, so.getVersion(), (OSTool.isSun64bits()) ? STR_OS_64BITS : null, (addendum != null) ? "." + addendum : null);
		} else {
			throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_2));
		}

		// si no se ha indicado directorio busca uno entre los disponibles del path
		String newDir = null;
		try {
			newDir = (dir != null && !dir.trim().equals("")) ? dir : new File(OSTool.getTempDir()).getCanonicalPath();
		} catch (IOException e) {
			LOG.error("No se puede canonicalizar la ruta: " + OSTool.getTempDir());
			newDir = (dir != null && !dir.trim().equals("")) ? dir : new File(OSTool.getTempDir()).getAbsolutePath();
		}
		if (updateLibraryPath) {
			if (LOG.isTraceEnabled()) {
				LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_16, newDir));
			}
			updateLibraryPath(newDir);
		}

		if (LOG.isTraceEnabled()) {
			LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_10, key, newDir));
		}
		
		if (suffix == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Se carga la librería " + key);
			}
			try{
			    copyFiles(newDir, key);
			} catch (CopyFileException e) {
			    if(dir != null) {
			        return copyFilesOS(null, addendum, updateLibraryPath, suffix);
			    } else {
			        throw e;
			    }
			}
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Se carga la librería alternativa con el sufijo " + suffix);
			}
			copyFiles(newDir, key, suffix);
		}
		
		return newDir;
	}
	
	/**
	 * <p>Comprueba si la propiedad indicada está disponible.</p>
	 * @param prop Nombre de la propiedad
	 * @return <code>true</code> si la propiedad existe con algún valor asignado, <code>false</code> en otro caso
	 */
	private boolean hasProp(final String prop) {
		if ((props != null) && (prop != null)) {
			return (props.getProperty(prop) != null);
		}
		return false;
	}
	
	/**
	 * <p>Actualiza la variable <code>java.library.path</code> con la nueva ruta indicada.</p>
	 * <p>Esta variable permite indicar dónde se encuentran las librerías JNI de usuario que se van a utilizar.</p>
	 * @param path Nueva ruta a incluir
	 */
	public void updateLibraryPath(final String path) {
		String libPath = System.getProperty(ConstantsAPI.SYSTEM_PROPERTY_LIBRARY_PATH);
		File fileDir = new File(path);
		if (!libPath.contains(fileDir.getAbsolutePath())) {
			libPath = fileDir.getAbsolutePath() + File.pathSeparator + libPath;
			System.setProperty(ConstantsAPI.SYSTEM_PROPERTY_LIBRARY_PATH, libPath);
			try {
    			Field fieldSysPath = ClassLoader.class.getDeclaredField(FIELD_SYS_PATHS);
    			fieldSysPath.setAccessible(true);
    			if (fieldSysPath != null) {
    				fieldSysPath.set(System.class.getClassLoader(), null);
    			}
			} catch (NoSuchFieldException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_3), ex);
			} catch (IllegalAccessException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_3), ex);
			}
		}
	}
	
	/**
	 * <p>Comprueba si hay ficheros relacionados con la clave indicada y si los hay, comprueba si es necesario volver a copiarlos
	 * (comprobando su integridad).</p>
	 * 
	 * @param dir Directorio donde se copiarán los ficheros
	 * @param clave Clave donde se agrupan los ficheros que se comprobarán/copiarán
	 * @throws CopyFileException si no existe la clave indicada o algunos de los ficheros como recurso
	 */
	public void copyFiles(final String dir, final String clave) throws CopyFileException {
		copyFiles(dir, clave, null);
	}
	
	/**
	 * <p>Comprueba si hay ficheros relacionados con la clave indicada y si los hay, comprueba si es necesario volver a copiarlos
	 * (comprobando su integridad).</p>
	 * 
	 * @param dir Directorio donde se copiarán los ficheros
	 * @param clave Clave donde se agrupan los ficheros que se comprobarán/copiarán
	 * @param ficheroDestino Nombre del fichero de destino
	 * @throws CopyFileException si no existe la clave indicada o algunos de los ficheros como recurso
	 */
	public void copyFiles(final String dir, final String clave, String sufijo) throws CopyFileException {
		if (props != null) {
			try {
				String conjunto = props.getProperty(clave);
				if (LOG.isTraceEnabled()) {
					LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_15, conjunto));
				}
				if (conjunto == null) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_4, clave));
					throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_4, clave));
				}
				StringTokenizer st = new StringTokenizer(conjunto, STR_FILE_SEPARATOR);
				boolean hasMore = st.hasMoreTokens();
				String finalFicheroDestino = "";
				while (hasMore) {
					// Recupera los datos relacionados con ese fichero. AppPerfect: falsos positivos, las expresiones no son constantes
					String fichero = st.nextToken();
					hasMore = st.hasMoreTokens();
					if (fichero == null) {
						continue;
					}
					String nombreFichero = props.getProperty(STR_FILE_DOT + fichero + STR_DOT_NAME);
					String resname = props.getProperty(STR_FILE_DOT + fichero + STR_DOT_RES);
					CRCInfo crcInfo = getCRC(fichero);
					try {
						long size = Long.parseLong(props.getProperty(STR_FILE_DOT + fichero + STR_DOT_SIZE));
						
						if (sufijo != null) {
							finalFicheroDestino = nombreFichero.substring(0, nombreFichero.indexOf('.')) + sufijo + nombreFichero.substring(nombreFichero.indexOf('.'));
						} else {
							finalFicheroDestino = nombreFichero; 
						}
LOG.trace("*********DATOS COPIA. nombreFichero="+nombreFichero+",sufijo="+sufijo+",ficheroDestino="+finalFicheroDestino+",dir="+dir);
						copyRes(dir, nombreFichero, finalFicheroDestino, resname, crcInfo, size);
                        vCopiedLibraries.add(finalFicheroDestino);
					} catch (NumberFormatException e) {
						LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_4, STR_FILE_DOT + fichero + STR_DOT_SIZE));
						throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_4, STR_FILE_DOT + fichero + STR_DOT_SIZE));
					}
				}
			} catch (MissingResourceException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_4, clave));
				throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_4, clave));
			} 
		} else {
			LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_6));
			throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_6));
		}
	}
	
	/**
	 * <p>Devuelve el CRC indicado para calcular la integridad de este fichero.</p>
	 * 
	 * @param fichero nombre del fichero
	 * @return CRCInfo con los datos del CRC configurado
	 * @throws CopyFileException Si no hay ningun CRC disponible o esta mal configurado
	 */
	private CRCInfo getCRC(final String fichero) throws CopyFileException {
		String value;
		// intenta obtener el valor adler32
		try {
			value = props.getProperty(STR_FILE_DOT + fichero + STR_DOT_ADLER32);
			if (value == null) {
				throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_5));
			}
			Adler32Info crc = new Adler32Info();
			crc.processValue(value);
			return crc;
		} catch (MissingResourceException ex) { }
		// intenta obtener el valor sha2
		try {
			value = props.getProperty(STR_FILE_DOT + fichero + STR_DOT_SHA2);
			if (value == null) {
				throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_5));
			}
			SHA2Info crc = new SHA2Info();
			crc.processValue(value);
			return crc;
		} catch (MissingResourceException ex) { }
		throw new CopyFileException(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_4));
	}
	
	/**
	 * <p>Comprueba si existe el fichero indicado en la ruta y si no existe o no está íntegro procede a volverlo a copiar.</p>
	 * <p>El recurso es de nuevo copiado si se detecta que su longitud ha cambiado o el CRC no se corresponde con el esperado.</p>
	 * @param dir Directorio donde se buscará/copiará el fichero
	 * @param fichero Nombre del fichero a copiar
	 * @param ficheroDestino Nombre para el fichero a copiar
	 * @param resname Nombre del recurso que tiene el fichero original
	 * @param crcValue valor CRC que debería tener el fichero
	 * @param size Tamaño en bytes que debería tener el fichero
	 * @throws CopyFileException Excepción lanzada si no ha podido sustituir el fichero debido a problemas de acceso al sistema de ficheros o de recursos
	 */
	private void copyRes(final String dir, final String fichero, final String ficheroDestino, final String resname, final CRCInfo crcValue, final long size) throws CopyFileException {
        InputStream entrada = null;
        OutputStream salida = null;
        try {
    		File dirFile = new File(dir); 
    		if (!dirFile.exists()) {
    			LOG.warn(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_21, dir));
    			dirFile.mkdirs();			
    		}
	    	File file = new File(dir, fichero);
	    	File fileDestino = new File(dir, ficheroDestino);
	    	if ((!file.exists()) || (!checkIntegrityFile(file, crcValue, size)) || !fichero.equals(ficheroDestino)) {
	    		if (LOG.isTraceEnabled()) {
					LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_11, file.getAbsolutePath()));
				}
	        	entrada = new BufferedInputStream(internalClassLoader.getResourceAsStream(resname), BUFFER_IN_SIZE);
	        	salida = new BufferedOutputStream(new FileOutputStream(fileDestino));
				LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_22, resname,fileDestino));
	    		byte[] buffer = new byte[BUFFER_OUT_SIZE];
				int readed = entrada.read(buffer);
				while (readed > 0) {
					salida.write(buffer, 0, readed);
					readed = entrada.read(buffer);
				}
				salida.flush();
				if (fileDestino.exists() && dir.contains(OSTool.getTempDir())) {
					fileDestino.deleteOnExit();
				}
	    	}
        } catch (FileNotFoundException ex) {
        	LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_7), ex);
        	throw new CopyFileException(ex);
        } catch (IOException ex) {
        	LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_8, fichero, dir), ex);
        	throw new CopyFileException(ex);
		}
    	finally {
        	if (entrada != null) {
        		try {
        			entrada.close();
        		} catch (IOException e) {
        			LOG.error(e.getMessage());
        		}
        	}
        	if (salida != null) {
        		try {
        			salida.close();
        		} catch (IOException e) {
        			LOG.error(e.getMessage());
        		}
        	}
        }
	}
	
	/**
	 * <p>Comprueba si el fichero indicado es íntegro.</p>
	 * 
	 * @param file Fichero del que hay que comprobar la integridad
	 * @param crcValue Valor CRC que se espera que el fichero cumpla
	 * @param size Tamaño esperado del fichero en bytes
	 * @return <code>true</code> si el fichero se ajusta a las condiciones esperadas, <code>false</code> en otro caso
	 * @throws IOException 
	 * <ul>
	 * 	<li>{@link IOException} lanzada si ocurre algún error en el acceso al fichero indicado</li>
	 * 	<li>{@link FileNotFoundException} lanzada si no se encuentra el fichero indicado</li>
	 * </ul>
	 * @throws CopyFileException Lanzada si no se puede calcular el CRC que se espera
	 */
	private boolean checkIntegrityFile(final File file, final CRCInfo crcValue, final long size) throws IOException, CopyFileException {
		if (LOG.isTraceEnabled()) {
			LOG.trace(I18N.getLocalMessage(ConstantsAPI.I18N_TOOLS_CP_12, file.getAbsolutePath()));
		}
		if (!file.exists()) {
			return false;
		}
		// Primero comprueba el tamaño
		if (file.length() != size) {
			return false;
		}
		// después comprueba el crc
		return crcValue.checkFile(file);
	}
	
	/**
	 * <p>Convierte un array de bytes en su representación de texto hexadecimal correspondiente.</p>
	 * 
	 * @param data array de bytes a convertir
	 * @return cadena de texto hexadecimal
	 */
	private String toHexString(final byte[] data) {
		StringBuffer sb = new StringBuffer();
		int pos = data.length;
		while (pos > 0) {
			sb.append(Integer.toHexString(data[--pos]));
		}
		return sb.toString();
	}

	/**
	 * <p>Devuelve un listado de las librerías que han sido copiadas.</p>
	 * @return Vector<String> nombres de las librerías copiadas (Ver el fichero de propiedades)
	 */
	public Vector<String> getCopiedLibraries() {
		return vCopiedLibraries;
	}
}
