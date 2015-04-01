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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.mityc.javasign.ConstantsAPI;

public class Utils {

	/** Sistema de traceo. */
	private static Log logger = LogFactory.getLog(Utils.class);

	/**
	 * <p>Lee los bytes del fichero indicado.</p>
	 * @param file Fichero a leer
	 * @return El contenido del fichero como array de bytes
	 * @throws IOException En caso de que no se pueda leer el fichero
	 */
	public static byte[] getFileBytes(File file) throws IOException {
		if (!file.exists()) {
			throw new IOException("El fichero indicado: " + file.getAbsolutePath() + " no existe.");
		}
	    return Utils.getStreamBytes(new FileInputStream(file));
	}

	/**
	* <p>Escribe datos en formato byte[] a disco.</p>
	* @param fileData Datos del fichero a escribir
	* @param file Nombre del fichero en el que escribir el primer parámetro. 
	* 			  Si es <code>null</code> se escribe en System.out
	* @throws IOException En caso de que el fichero no pueda ser escrito.
	*/
	public static void writeFile(byte[] fileData, String fileName) throws IOException {
	    File file = null;
	    if(fileName != null) {
	        file = new File(fileName);
	    }
	    Utils.writeFile(fileData, file);
	}

	/**
	 * <p>Escribe datos en formato byte[] a disco.</p>
	 * @param fileData Datos del fichero a escribir
	 * @param file Fichero en el que escribir el primer parámetro. 
	 * 			   Si es <code>null</code> se escribe en System.out
	 * @throws IOException En caso de que el fichero no pueda ser escrito.
	 */
	public static void writeFile(byte[] fileData, File file) throws IOException {
		OutputStream os = null;
		if (fileData == null || fileData.length <= 0) {
			throw new IOException("Los datos a escribir son nulos o estan vacíos");
		}
	
		if(file == null) { // En caso de que el fichero sea nulo, se escribe en stdOut
			os = System.out;
		} else {
			os = new FileOutputStream(file);
		}
		if (os == null) {
			throw new IOException("No se pudo recuperar un handler para el fichero: " + file.getAbsolutePath());
		}
		os.write(fileData);
		os.close();
	}

	/**
	 * <p>Lee los bytes del fichero indicado.</p>
	 * @param InputStream Stream a leer
	 * @return El contenido del fichero como array de bytes
	 * @throws IOException En caso de que no se pueda leer el fichero
	 */
	public static byte[] getStreamBytes(InputStream is) throws IOException {
	    final int BUF_SIZE = 512;
	    ByteArrayOutputStream bos = null;
	    int bytesRead = 0;
	    byte[] data = null;
	
	    data = new byte[BUF_SIZE];
	    bos = new ByteArrayOutputStream();
	
	    while((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
	    	bos.write(data, 0, bytesRead);
	    }
	
	    is.close();
	    bos.close();
	
	    return bos.toByteArray();
	}

	public static void addBCProvider() {
		if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) == null) {
			AccessController.doPrivileged(new PrivilegedAction<Integer>() {
				public Integer run() {
					try {
						Provider p = new BouncyCastleProvider();
						ProvidersUtil.registerProvider(p.getClass().getName());
						if (logger.isDebugEnabled()) {
							logger.debug("Agregando el proveedor BC");
						}
						Integer res = Security.addProvider(p);
						return res;
					} catch (Throwable e) {
						if (logger.isDebugEnabled()) {
							logger.debug("Error al agregar el proveedor BC", e);
						}
						return null;
					}
				}
			});
		}
	}

}
