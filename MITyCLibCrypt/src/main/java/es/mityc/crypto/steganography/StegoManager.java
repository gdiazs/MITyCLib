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
package es.mityc.crypto.steganography;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.crypto.Utils;
import es.mityc.crypto.symetric.TripleDESManager;

public class StegoManager {

	/** Sistema de traceo. */
	static Log logger = LogFactory.getLog(StegoManager.class);

	/**
	 * Clase encargada de embeber y extraer información.
	 */
	private StegoData sd = null;

	/**
	 * Constructor por defecto
	 */
	public StegoManager() {
		this.sd = new StegoData(); 
	}

	/**
	 * <p>Permite embeber un fichero en una imagen.</p>
	 * @param msgFile Fichero con los datos a embeber.
	 * @param coverFile Imagen en la cual los datos serán embebidos
	 * @return Bytes de la imagen esteganografiada
	 * @throws StegoException En caso de error.
	 */
	public byte[] ocultarInfo(File msgFile, File coverFile) throws StegoException {
		if (logger.isDebugEnabled()) {
			logger.debug("Insertando datos en " + coverFile);
		}
		InputStream is = null;

		if (msgFile == null || !msgFile.exists()) {
			throw new StegoException(new Exception("La imagen indicada: " + msgFile.getAbsolutePath() + " no existe."));
		}

		if (coverFile == null || !coverFile.exists()) {
			throw new StegoException(new Exception("El fichero indicado: " + coverFile.getAbsolutePath() + " no existe."));
		}

		try {
			if(msgFile != null) {
				is = new FileInputStream(msgFile);
			}

			return ocultarInfo(es.mityc.javasign.utils.Utils.getStreamBytes(is), msgFile.getName(),
					coverFile == null ? null : es.mityc.javasign.utils.Utils.getFileBytes(coverFile), 
							coverFile == null ? null : coverFile.getAbsolutePath());
		} catch (StegoException soEx) {
		    throw soEx;
		} catch(Exception ioEx) {
			logger.error(ioEx);
			return null;
		}
	}

	/**
	 * <p>Permite embeber un fichero en una imagen.</p>
	 * @param msgFile Array de bytes a embeber.
	 * @param msgFileName Nombre del fichero que contenía los datos a embeber (util durante la recuperación de los datos)
	 * @param coverFile Bytes de la imagen en la cual los datos serán embebidos
	 * @param imagenFileFormat Formato de la imagen utilizada
	 * @return Bytes de la imagen esteganografiada
	 * @throws StegoException En caso de error.
	 */
	public byte[] ocultarInfo(byte[] datos, String msgFileName, byte[] imagen, String imagenFileFormat) throws StegoException {
		try {
			// Previamente, se comprimen los datos en ZIP en caso de que esté configurado
			if(sd.config.isComprimir()) {
				try {
					datos = StegoUtils.zipData(datos);
				} catch (Exception e) {
					if (logger.isDebugEnabled()) {
						logger.debug("Se continúa sin comprimir");
					}
				}
			}

			// Se encriptan los datos en caso de que esté así configurado
			if(sd.config.isEncriptar()) {
				if (logger.isDebugEnabled()) {
					logger.debug("Encriptando " + datos.length + " bytes");
				}
				TripleDESManager crypto = new TripleDESManager();
				datos = new String(crypto.protectTripleDES(datos, sd.config.getPassword())).getBytes();
			}

			return sd.embeberDatos(datos, msgFileName, imagen, imagenFileFormat, sd.config.getPassword());
		} catch(StegoException osEx) {
			logger.error(osEx);
			throw osEx;
		} catch(Exception ex) {
			logger.error(ex);
			return null;
		}
	}

	/**
	 * <p>Permite extraer los datos embebidos en una imagen esteganografiada.</p>
	 * @param stegoData Bytes de la imagen esteganografiada de la cual se van a extraer los datos
	 * @return Datos extraidos en forma de array, formando duplas NombreFichero-Datos
	 */
	public List<Object> extraerDatos(byte[] stegoData) {
		byte[] msg = null;
		List<Object> output = new ArrayList<Object>();

		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Extrayendo datos: ");
			}
		
			// Se obtiene la información oculta stegoData.length
			msg = sd.extraerDatos(stegoData, sd.config.getPassword());

			// Se indica el nombre del fichero como primer dato de la lista de salida
			output.add(sd.getStegoFileName());

			// Se desencriptan los datos si se indicó contraseña
			if(sd.config.isEncriptar())  {
				if (logger.isDebugEnabled()) {
					logger.debug("Desencriptando " + msg.length + " bytes");
				}
				TripleDESManager crypto = new TripleDESManager();
				msg = crypto.recoverTripleDES(new String(msg).toCharArray(), sd.config.getPassword());
			}

			// Se descomprimen los datos en ZIP, si es necesario 
			if(sd.config.isComprimir())  {
				try {
					msg = StegoUtils.unzipData(msg);
				} catch(IOException ioEx) {
					logger.error("No se inflaron los datos");
				}
			}

			// Se incluyen los datos recuperados como segundo elemento de la lista
			output.add(msg);
		} catch(StegoException osEx) {
			logger.debug(osEx);
		} catch(IndexOutOfBoundsException ex) { 
			if (msg.length == 0) {
				logger.warn("La imagen no contiene datos");
			} else {
				logger.error(ex);
			}
		} catch(Exception ex) {
			logger.debug(ex);
		}

		return output;
	}

	/**
	 * <p>Permite extraer los datos embebidos en una imagen esteganografiada.</p>
	 * @param stegoData Fichero que contiene la imagen esteganografiada de la cual se van a extraer los datos
	 * @return Datos extraidos en forma de array, formando duplas NombreFichero-Datos
	 */
	public List<Object> extraerDatos(File stegoFile) throws IOException {
		return extraerDatos(es.mityc.javasign.utils.Utils.getFileBytes(stegoFile));
	}

	 /**
     * Contraseña para encriptar.
     */
	public void setPassword(String password) {
		sd.config.setEncriptar(true);
		sd.config.setPassword(password);
		if (logger.isDebugEnabled()) {
			logger.debug("Contraseña establecida");
		}
	}

	/**
     * Flag para comprimi. Con <code>true</code> se realiza un ZIP en los datos a embeber.
     */
	public void setComprimir(boolean f) {
		sd.config.setComprimir(f);
		if (logger.isDebugEnabled()) {
			logger.debug("Uso de compresión: " + f);
		}
	}

	public static void main(String[] args) {
		StegoManager ssg = new StegoManager();
		ssg.setPassword("Caracola");
		ssg.setComprimir(true);
		try {
			byte[] stego = ssg.ocultarInfo(new File("resources/DocumentoA.pdf"), new File("resources/imagen.png"));

			es.mityc.javasign.utils.Utils.writeFile(stego, "./Steganografriado.png");
			List<Object> lista = ssg.extraerDatos(new File("./Steganografriado.png"));
			es.mityc.javasign.utils.Utils.writeFile((byte[])lista.get(1), new String((byte[])lista.get(0)));
		} catch (IOException e) {
			e.printStackTrace();
		} catch (StegoException e) {
			e.printStackTrace();
		}
	}
}
