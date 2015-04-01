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
package es.mityc.javasign.pass;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;

import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.utils.HexUtils;

/**
 * <p>Gestiona la seguridad de las contraseñas mediante un sistema PBE.</p>
 * <p>Los parámetros de configuración utilizados por este manager son:
 * 	<ul>
 * 		<li>filePBE.URI: Ruta donde se encuentra el fichero de clave maestra.
 * 		Si la URI es relativa se resolverá contra el directorio de trabajo.</li>
 * 	</ul>
 * </p>
 * <p>Este fichero deberá tener formato de un fichero de propiedades con los
 * valores:
 * 	<ul>
 * 		<li>simplePBE.salt: cadena en hexadecimal de 8 bytes que indica el salt del PBE.</li>
 * 		<li>simplePBE.iteration: número decimal que indica el número de iteración del PBE.</li>
 * 		<li>simplePBE.masterkey: cadena de texto con la contraseña maestra base del PBE.</li>
 * 	</ul>
 * </p>
 */
public class PBEFileSecurity extends PBESecurity {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsAPI.LIB_NAME); 
	
	/** Propiedad con la URI del fichero de configuración. */
	private static final String PROP_FILE_CONF = "filePBE.URI";
	/** Ruta por defecto del fichero de configuración. */
	private static final String PROP_DEFAULT_FILE = "./pbesec.properties";
	/** Nombre de la propiedad de configuraciòn salt. */
	private static final String PROP_FILE_SALT = "simplePBE.salt=";
	/** Nombre de la propiedad de configuraciòn iteration. */
	private static final String PROP_FILE_ITERATION = "simplePBE.iteration=";
	/** Nombre de la propiedad de configuraciòn clave maestra. */
	private static final String PROP_FILE_MASTERKEY = "simplePBE.masterkey=";
	/** Número máximo de bits que tendrá el número aleatorio generado para iteraciones. */
	private static final int MAX_VALUE_ITER = 4096;
	/** Número de caracteres que tendrá la contraseña maestra generada aleatoriamente. */
	private static final int MAX_SIZE_MASTER_KEY = 20;
	/** Número máximo de bytes que tendrá la salt. */
	private static final int MAX_SIZE_BYTES_SALT = 8;


	/**
	 * <p>Constructor.</p>
	 * @throws PassSecurityException Lanzada si sucede un error en la configuración
	 */
	public PBEFileSecurity() throws PassSecurityException {
		super();
	}

	/**
	 * <p>Constructor.</p>
	 * @param props Propiedades de configuración del manager
	 * @throws PassSecurityException Lanzada si sucede un error en la configuración
	 */
	public PBEFileSecurity(Properties props) throws PassSecurityException {
		super(props);
	}
	
	/**
	 * <p>Evita la inicialización con la configuración interna.</p>
	 * @throws PassSecurityException No se lanza nunca
	 * @see es.mityc.javasign.pass.PBESecurity#init()
	 */
	@Override
	protected void init() throws PassSecurityException {
		init(PROP_DEFAULT_FILE);
	}
	
	/**
	 * <p>Carga la configuración de de seguridad disponible en la ruta indicada.</p>
	 * <p>Si la ruta configurada es relativa, se construirá con respecto al directorio de trabajo.</p>
	 * @param path Ruta donde se encuentra la configuración
	 * @throws PassSecurityException Lanzada si no se puede cargar la configuración indicada
	 */
	protected void init(final String path) throws PassSecurityException {
		try {
			URI uri = new URI(path);
			if (!uri.isAbsolute()) {
				uri = new File("./").toURI().resolve(uri);
			}
			InputStream is = null;
			try {
				is = uri.toURL().openStream();
			} catch (IOException ex) {
				if ("file".equals(uri.getScheme())) {
					File file = new File(uri);
					if (!file.exists()) {
						file.getParentFile().mkdirs();
						createSecFile(file);
						is = new FileInputStream(file);
					}
				}
			}
			if (is != null) {
				Properties props = new Properties();
				props.load(is);
				super.init(props);
			} else {
				throw new PassSecurityException(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_4, path));
			}
		} catch (URISyntaxException ex) {
			throw new PassSecurityException(ex.getMessage(), ex);
		} catch (MalformedURLException ex) {
			throw new PassSecurityException(ex.getMessage(), ex);
		} catch (IOException ex) {
			throw new PassSecurityException(ex.getMessage(), ex);
		}
	}
	
	/**
	 * <p>Inicializa el objeto buscando el fichero de configuración en las propiedades.</p>
	 * @param props Configuración
	 * @throws PassSecurityException Lanzada si hay un error en la búsqueda del fichero de configuración
	 * @see es.mityc.javasign.pass.PBESecurity#init(java.util.Properties)
	 */
	@Override
	protected void init(final Properties props) throws PassSecurityException {
		// Recupera la dirección del fichero de configuración
		String file = props.getProperty(PROP_FILE_CONF);
		if ((file != null) && (file.trim().length() > 0)) {
			init(file);
		} else {
			init();
		}
	}
	
	/**
	 * <p>Crea un fichero de propiedades con los valores de clave maestra aleatorios.</p>
	 * @param file Fichero donde se guardarán las propiedades
	 * @throws IOException Lanzada cuando no se puede generar el fichero
	 */
	protected void createSecFile(File file) throws IOException {
		SecureRandom random = null;
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException ex) {
			throw new IOException(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_9, ex.getMessage()));
		}
		if (file.createNewFile()) {
			PrintWriter pw = new PrintWriter(file);
			pw.println(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_6));
			pw.print(PROP_FILE_SALT);
			byte[] data = new byte[MAX_SIZE_BYTES_SALT];
			random.nextBytes(data);
			pw.println(HexUtils.convert(data));
			pw.println(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_7));
			pw.print(PROP_FILE_ITERATION);
			pw.println(random.nextInt(MAX_VALUE_ITER));
			pw.println(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_8));
			pw.print(PROP_FILE_MASTERKEY);
			for (int i = 0; i < MAX_SIZE_MASTER_KEY; i++) {
				char c = (char) (random.nextInt(94) + 33);
				pw.print(c);
			}
			pw.println();
			pw.flush();
			pw.close();
		} else {
			throw new IOException(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_5, file.getAbsolutePath()));
		}
	}

}
