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

import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <p>Esta clase maneja imágenes esteganografiadas según RandomLSB permitiendo realizar tareas de backup.</p> 
 */
public class StegoSign {
	
	/** Looger. */
	static Log logger = LogFactory.getLog(StegoSign.class);

	private BufferedImage image = null;

	private Random rand = null;
	private final static int BUF_SIZE = 512;

	private int imgWidth = 0;
	private int imgHeight = 0;
	private int channelBitsUsed = 1;
	private CabeceraLSB cabecera = null;
	private String fileName = null;

	/**
	 * Lleva la cuenta de cuales han sido los bits por canal de color, por cada pixel de la imagen utilizados, evitando sobreescrituras.
	 */
	private boolean matrizMaestra[][][][];
	private static StegoConfig config = new StegoConfig();
	
	/**
	 * <p>Devuelve una array que contiene los bits originales de la imagen permitiendo que
	 * sea posible recuperar la imagen original tras un proceso esteganográfico (que los sobreescribe).</p>
	 * @param imagenOriginal Fichero que contiene la imagen a emplear como cubierta.
	 * @param datos Fichero con los datos que serán embebidos dentro de la imagen. Se comprimen antes de calcular los datos de recuperación.
	 * @param password Contraseña.
	 * @return Bytes de la imagen esteganografiada
	 * @throws Exception En caso de error
	 */
	public byte[] getRestaurationData(File imagenOriginal, File datos, String password) throws Exception {
		rand = new Random(StegoUtils.hashPassLong(password));
		// Se lee la imagen origen
		InputStream is = null;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ByteArrayOutputStream bosFirma = new ByteArrayOutputStream();
		int bytesRead = 0;
		byte[] data = new byte[BUF_SIZE];
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo imagen original");
			}
			is = new FileInputStream(imagenOriginal);
			while((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
				bos.write(data, 0, bytesRead);
			}
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo datos a ocultar");
			}
			is = new FileInputStream(datos);
			while((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
				bosFirma.write(data, 0, bytesRead);
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Calculando datos de recuperación");
			}
			
			byte[] datosZip = null;
			try {
				// Se utiliza un margen para que los datos de recuperación sean más grandes que los datos a embeber
				datosZip = StegoUtils.zipData(bosFirma.toByteArray());
				datosZip = new byte[datosZip.length + 50];
			} catch (Exception e) {
				if (logger.isDebugEnabled()) {
					logger.debug("Se continúa sin comprimir");
				}
			}
			
			return getRestoreData(datosZip, datos.getName(), bos.toByteArray(), password!=null?password.getBytes():null);	
		} catch (Exception e) {
			logger.error(e);
			throw e;
		} finally {
			try {
				is.close();
				bos.close();
			} catch (IOException e) {
				if (logger.isDebugEnabled()) {
					logger.debug(e);
				}
			}
		}
	}
	
	/**
	 * <p>Restaura la la imagen original tras haber sido empleada en un proceso esteganográfico.</p>
	 * @param imagen Imagen esteganografiada que ha sido empleada como cubierta.
	 * @param restaurationData Datos de recuperación que se obtuvieron empleando el método getRestaurationData sobre la imagen original.
	 * @param destino Fichero destino donde se salvará la imagen recuperada.
	 * @param password Contraseña.
	 * @throws Exception
	 */
	public void restoreOriginal(File imagen, byte[] restaurationData, File destino, String password) throws Exception {
		InputStream is = null;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int bytesRead = 0;
		byte[] data = new byte[BUF_SIZE];
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo imagen original");
			}
			is = new FileInputStream(imagen);
			while((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
				bos.write(data, 0, bytesRead);
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Restaurando imagen");
			}
			byte[] res = new StegoData().embeberDatos(restaurationData, null, bos.toByteArray(),
					imagen.getName(), password);

			if (logger.isDebugEnabled()) {
				logger.debug("Escribiendo el resultado");
			}
			BufferedOutputStream fos = new BufferedOutputStream(new FileOutputStream(destino));
			fos.write(res);
			fos.flush();
			fos.close();
		} catch (Exception e) {
			logger.error(e);
			throw e;
		} finally {
			try {
				is.close();
				bos.close();
			} catch (IOException e) {
				if (logger.isDebugEnabled()) {
					logger.debug(e);
				}
			}
		}
	}
	
	private byte[] getRestoreData(byte msg[], String msgFileName, byte cover[], byte[] pass) throws Exception {
		this.image = StegoUtils.byteArrayToImage(cover);
		if (this.image == null) {
			throw new Exception("No se pudo leer la imagen.");
		}
		imgWidth = image.getWidth();
		imgHeight = image.getHeight();
		fileName = msgFileName;
		// Se inicializa la matriz maestra
		matrizMaestra = new boolean[imgWidth][imgHeight][3][config.getMaxBitsPorCanal()];
		for(int i = 0; i < imgWidth; i++) {
			for(int j = 0; j < imgHeight; j++) {
				for(int k = 0; k < config.getMaxBitsPorCanal(); k++) {
					matrizMaestra[i][j][0][k] = false;
					matrizMaestra[i][j][1][k] = false;
					matrizMaestra[i][j][2][k] = false;
				}
			}
		}
			
		byte[] r = calculateHeader(msg.length, pass);
		byte[] data = getRestaurationBytes(msg.length);
		byte[] res = new byte[r.length + data.length];
		System.arraycopy(r, 0, res, 0, r.length);
		System.arraycopy(data, 0, res, r.length, data.length);
		
		return res;
	}

	private byte[] calculateHeader(int dataLength,  byte[] pass) throws StegoException {
		int noOfPixels = imgWidth * imgHeight;
		int headerSize = 0;
		try {
			cabecera = new CabeceraLSB(dataLength, channelBitsUsed, fileName, config);
			for (headerSize = cabecera.getLongitudCabecera(); (double)(noOfPixels * 3 * channelBitsUsed) / 8D < (double)(headerSize + dataLength);)
				if(++channelBitsUsed > config.getMaxBitsPorCanal())
					throw new StegoException("Los datos no caben. Se han utilizado más bits por canal que el máximo permitido.");

			cabecera.setBitsUtilizados(channelBitsUsed);
			
			// Se recupera la cabecera
			return getRestaurationBytes(cabecera.getDatosCabecera(pass).length);
		} catch(Exception ex) {
			throw new StegoException(ex);
		}
	}
	
	private byte[] getRestaurationBytes(int b) throws IOException {
		return getRestaurationBytes(0, b);
	}

	private byte[] getRestaurationBytes(int off, int len) throws IOException {
		if ((off < 0) || (len <= 0) ||
				((off + len) < 0)) {
			if (logger.isDebugEnabled()) {
				logger.debug("Posición fuera de rango");
			}
			throw new IndexOutOfBoundsException();
		} else if (len == 0) {
			if (logger.isDebugEnabled()) {
				logger.debug("Longitud de entrada nula");
			}
			return null;
		} else if (image == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("No se pudo leer la imagen de entrada");
			}
			return null;
		}
		byte[] res = new byte[len];
		for (int i = 0 ; i < len ; i++) {
			res[i] = (byte)getRestoreByte();
		}
		
		return res;
	}

	private int getRestoreByte() throws IOException {
		int x = 0;
		int y = 0;
		int channel = 0;
		int bit = 0;
		byte bitSet[] = new byte[8];
		for(int i = 0; i < 8; i++) {
			do {
				x = rand.nextInt(imgWidth);
				y = rand.nextInt(imgHeight);
				channel = rand.nextInt(3);
				bit = rand.nextInt(channelBitsUsed);
			} while(matrizMaestra[x][y][channel][bit]);
			matrizMaestra[x][y][channel][bit] = true;
			bitSet[i] = (byte)getPixelBit(x, y, channel, bit);
		}

		return (bitSet[0] << 7) + (bitSet[1] << 6) + (bitSet[2] << 5) + (bitSet[3] << 4) + (bitSet[4] << 3) + (bitSet[5] << 2) + (bitSet[6] << 1) + (bitSet[7] << 0);
	}
	
	private int getPixelBit(int x, int y, int channel, int bit) {
		return image.getRGB(x, y) >> (channel * 8 + bit) & 1;
	}
}
