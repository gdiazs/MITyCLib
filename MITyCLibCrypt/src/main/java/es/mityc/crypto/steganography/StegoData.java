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
import java.awt.image.IndexColorModel;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.crypto.Utils;

/**
 * <p>Esta clase maneja imágenes esteganografiadas según RandomLSB permitiendo realizar tareas de backup.</p> 
 */
public class StegoData {
	
	/** Looger. */
	static Log logger = LogFactory.getLog(StegoData.class);

	private BufferedImage image = null;

	private Random rand = null;
	private final static int BUF_SIZE = 512;

	private int imgWidth = 0;
	private int imgHeight = 0;
	private int channelBitsUsed = 1;
	private CabeceraLSB header = null;

	private boolean matrizMaestra[][][][];

	// Estructura de datos para facilitar labores de Debug 
	private int matrizDebug[][];
	private BufferedImage imageDebug = null;

	protected StegoConfig config = null;
	
	public StegoData() {
		config = new StegoConfig();
	}
	
	/**
	 * <p>Devuelve una array de bits que contiene los datos embebidos en la imagen.</p>
	 * @param imagen Imagen esteganografiada.
	 * @param datos Datos que serán embebidos dentro de la imagen.
	 * @param password Contraseña.
	 * @return
	 * @throws Exception
	 */
	public byte[] extraerDatos(File imagen, String password) throws Exception {
		// Se lee la imagen origen
		InputStream is = null;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int bytesRead = 0;
		byte[] data = new byte[BUF_SIZE];
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo imagen estaganografiada");
			}
			is = new FileInputStream(imagen);
			while((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
				bos.write(data, 0, bytesRead);
			}
			
			return bos.toByteArray();
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
		
	public byte[] extraerDatos(byte[] img, String password) throws Exception {
		rand = new Random(StegoUtils.hashPassLong(password));
		if (logger.isDebugEnabled()) {
			logger.debug("Extrayendo datos");
		}
		header = new CabeceraLSB();
		return getEmbeddedData(img,  password!=null?password.getBytes():null);
	}
	
	/**
	 * <p>Devuelve una array de bits que contiene los datos embebidos en la imagen.</p>
	 * @param imagen Imagen esteganografiada.
	 * @param datos Datos que serán embebidos dentro de la imagen.
	 * @param password Contraseña.
	 * @return
	 */
	public byte[] getStegoFileName() {
		return header.getFileName().getBytes();
	}

	private byte[] getEmbeddedData(byte cover[], byte[] password) throws Exception {
		this.image = StegoUtils.byteArrayToImage(cover);
		if (this.image == null) {
			throw new Exception("No se pudo leer la imagen.");
		}
		
		imgWidth = image.getWidth();
		imgHeight = image.getHeight();
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
		
		return getBytes(cover, password);
	}
	
	private byte[] getBytes(byte b[], byte[] pass) throws IOException {
		return getBytes(b, 0, pass);
	}

	private byte[] getBytes(byte b[], int off, byte[] password) throws IOException {
		if (b == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("Byte de entrada nulo");
			}
			throw new NullPointerException();
		} else if ((off < 0) || (off > b.length)) {
			if (logger.isDebugEnabled()) {
				logger.debug("Posición fuera de rango");
			}
			throw new IndexOutOfBoundsException();
		} else if (image == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("No se pudo leer la imagen de entrada");
			}
			return null;
		}
		
		// Se lee la cabecera, que tiene un tamaño fijo
		ByteArrayInputStream bais = null;
		try {
			boolean founded = false;
			int i = 0; // Puntero de lectura
			
			// Tamaño total = stampLen + FIXED_HEADER_LENGTH
			int cabeceraLength = CabeceraLSB.SELLO.length + CabeceraLSB.ESPACIO_RESERVADO;
			
			byte[] res = null;
			byte[] stamp = new byte[CabeceraLSB.SELLO.length];
			
			// Se comprueba con varias configuraciones
			for(int j = 1; j < config.getMaxBitsPorCanal(); ++j) {
				// Se reinician los elementos de control
				rand = new Random(StegoUtils.hashPassLong((password!=null)?new String(password):null));
				matrizMaestra = new boolean[imgWidth][imgHeight][3][config.getMaxBitsPorCanal()];
				for(int k = 0; k < imgWidth; k++) {
					for(int h = 0; h < imgHeight; h++) {
						for(int l = 0; l < config.getMaxBitsPorCanal(); l++) {
							matrizMaestra[k][h][0][l] = false;
							matrizMaestra[k][h][1][l] = false;
							matrizMaestra[k][h][2][l] = false;
						}
					}
				}
				i = 0;
				// Se establece el canal/es utilizado/s
				channelBitsUsed = j;
				// Se busca la marca
				res = new byte[cabeceraLength];
				for (; i < cabeceraLength ; i++) {
					res[i] = (byte)getPixelByte(b[off + i]);
				}
				bais = new ByteArrayInputStream(res);

				// Se comprueba que exista la marca en la cabecera
				bais.read(stamp, 0, CabeceraLSB.SELLO.length);
				if(!(new String(stamp)).equals(new String(CabeceraLSB.SELLO))) {
					// Se comprueba la posibilidad de que la marca haya sido ofuscada
					if (password != null && password.length > 0) {
						String msg = Utils.undoObfuscate(stamp, StegoUtils.hashPassLong(new String(password)));
						if (new String(msg).equals(new String(CabeceraLSB.SELLO))) {
							founded = true;
							break;
						}
					}
				} else {
					founded = true;
					break;
				}
			}	
				
			if (!founded) {
        		throw new StegoException("No se encuentra la cabecera");
        	}
            
            // Se extrae el resto de datos de la cabecera
            byte[] headerBytes = new byte[CabeceraLSB.ESPACIO_RESERVADO];
            bais.read(headerBytes, 0, CabeceraLSB.ESPACIO_RESERVADO);
            int dataLength = (StegoUtils.byteToInt(headerBytes[0]) + (StegoUtils.byteToInt(headerBytes[1]) << 8)
                    + (StegoUtils.byteToInt(headerBytes[2]) << 16) + (StegoUtils.byteToInt(headerBytes[3]) << 32));
            int fileNameLen = headerBytes[5];
            config.setComprimir(headerBytes[6] == 1);
            config.setEncriptar(headerBytes[7] == 1);
            
            // Se obtiene el nombre del fichero embebido
            res = new byte[fileNameLen];
            cabeceraLength = fileNameLen + cabeceraLength;
    		for (int j = 0; i < cabeceraLength; i++) {
    			res[j] = (byte)getPixelByte(b[off + i]);
    			j++;
    		}
    		
    		if (password != null && password.length > 0) {
    			if (logger.isDebugEnabled()) {
					logger.debug("Desencriptando " + stamp.length + " bytes");
				}
				try {
					res = Utils.undoObfuscate(res, StegoUtils.hashPassLong(new String(password))).getBytes();
				} catch(Exception e) {
					logger.error(e);
				}
    		}
            header.setFileName(res);
            
            // Se lee el resto
            if (dataLength == 0 || dataLength > b.length) {
    			if (logger.isDebugEnabled()) {
    				logger.debug("Longitud de entrada nula o fuera de rango");
    			}
    			return null;
            }
            res = new byte[dataLength];
            dataLength = dataLength + cabeceraLength;
    		for (int j = 0; i < dataLength ; i++) {
    			res[j] = (byte)getPixelByte(b[off + i]);
    			j++;
    		}
			
    		return res;
		} catch (Exception e) {
			logger.error(e);
			throw new IOException(e);
		} finally {
			try {
				bais.close();
			} catch (IOException e) {
				if (logger.isDebugEnabled()) {
					logger.debug(e);
				}
			}
		}
	}

	private int getPixelByte(int data) throws IOException {
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
	
	/* Bloque de escritura. */
	
	/**
	 * <p>Permite ocultar un array de bytes en los píxels de una imagen.</p>
	 * @param datos Datos a embeber dentro de la imagen
	 * @param pathDatos Ruta física de los datos a embeber
	 * @param img
	 * @param pathImg
	 * @return
	 * @throws StegoException
	 */
	public byte[] embeberDatos(byte[] datos, String nombreDatos, byte[] img, String pathImg, String password) throws StegoException {
		rand = new Random(StegoUtils.hashPassLong(password));
		try {
			this.image = StegoUtils.byteArrayToImage(img);
			
			imgWidth = image.getWidth();
			imgHeight = image.getHeight();
			
			if (logger.isDebugEnabled()) {
				this.imageDebug = StegoUtils.byteArrayToImage(img);
			}
		} catch(Exception e) {
			logger.error("No se pudo leer la imagen indicada", e);
			throw new StegoException(e);
		}

		if(this.image.getColorModel() instanceof IndexColorModel) {
            logger.error("No se pueden utilizar imagenes con colores indexados");
            throw new StegoException("No se pueden utilizar imagenes con colores indexados");
		}
		inicializar();
		
		try {
			if (nombreDatos != null) {
				write(crearCabecera(datos.length, nombreDatos, password!=null?password.getBytes():null));
			} else {
				int noOfPixels = imgWidth * imgHeight;
				int dataLength = datos.length;
				while((double)(noOfPixels * 3 * channelBitsUsed) / 8D < (double)(dataLength)) {
					if(++channelBitsUsed > config.getMaxBitsPorCanal())
						throw new StegoException("Datos demasiado grandes para embeber");
				}
			}
			write(datos);
			

			
			String formatoDestino = pathImg.substring(pathImg.lastIndexOf('.') + 1);
			return StegoUtils.imageToByteArray(image, formatoDestino);
		} catch(StegoException soEx) {
		    throw soEx;
		} catch(Exception e) {
			logger.error("No se pudo embeber los datos en la imagen indicada", e);
			throw new StegoException(e);
		}
	}
	
	private byte[] crearCabecera(int dataLength, String fileName, byte[] pass) throws StegoException {
		int noOfPixels = imgWidth * imgHeight;
		int headerSize = 0;
		try {
			header = new CabeceraLSB(dataLength, channelBitsUsed, fileName, config);
			for (headerSize = header.getLongitudCabecera(); (double)(noOfPixels * 3 * channelBitsUsed) / 8D < (double)(headerSize + dataLength);)
				if(++channelBitsUsed > config.getMaxBitsPorCanal())
					throw new StegoException("Datos demasiado grandes para embeber");

			header.setBitsUtilizados(channelBitsUsed);
			
			// Se recupera la cabecera
			return header.getDatosCabecera(pass);
		} catch (StegoException soEx) {
		    throw soEx;
		} catch(Exception ex) {
			throw new StegoException(ex);
		}
	}
	
	private void inicializar() throws StegoException {
		matrizMaestra = new boolean[imgWidth][imgHeight][3][config.getMaxBitsPorCanal()];
		for(int i = 0; i < imgWidth; i++) {
			for(int j = 0; j < imgHeight; j++) {
				for(int k = 0; k < channelBitsUsed; k++) {
					matrizMaestra[i][j][0][k] = false;
					matrizMaestra[i][j][1][k] = false;
					matrizMaestra[i][j][2][k] = false;
				}
			}
		}
		if (logger.isDebugEnabled()) {
			matrizDebug = new int[imgWidth][imgHeight];
			for(int i = 0; i < imgWidth; i++) {
				for(int j = 0; j < imgHeight; j++) {
					matrizDebug[i][j] = 0;
				}
			}
		}
	}
	
	private void write(byte b[]) throws IOException {
		write(b, 0, b.length);
	}

	private void write(byte b[], int off, int len) throws IOException {
		if (b == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("Byte de entrada nulo");
			}
			throw new NullPointerException();
		} else if ((off < 0) || (off > b.length) || (len < 0) ||
				((off + len) > b.length) || ((off + len) < 0)) {
			if (logger.isDebugEnabled()) {
				logger.debug("Posición fuera de rango");
			}
			throw new IndexOutOfBoundsException();
		} else if (len == 0) {
			if (logger.isDebugEnabled()) {
				logger.debug("Longitud de entrada nula");
			}
			return;
		} else if (image == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("No se pudo leer la imagen de entrada");
			}
			return;
		}
		
		for (int i = 0 ; i < len ; i++) {
			write(b[off + i]);
		}
	}

	private void write(int data) throws IOException {
		boolean bitValue = false;
		int x = 0;
		int y = 0;
		int channel = 0;
		int bit = 0;
		for(int i = 0; i < 8; i++) {
			bitValue = (data >> 7 - i & 1) == 1;
			do {
				x = rand.nextInt(imgWidth);
				y = rand.nextInt(imgHeight);
				channel = rand.nextInt(3);
				bit = rand.nextInt(channelBitsUsed);
			} while(matrizMaestra[x][y][channel][bit]);
			matrizMaestra[x][y][channel][bit] = true;
			setPixelBit(x, y, channel, bit, bitValue);
		}
	}
	
	private void setPixelBit(int x, int y, int channel, int bit, boolean bitValue) {
        int pixel = 0;
        int newPixel = 0;
        pixel = image.getRGB(x, y);
        if(bitValue) {
            newPixel = pixel | (1 << (bit + channel * 8));
        } else {
        	int newColor = -2;
            for(int i = 0; i < bit + channel * 8; i++)
                newColor = (newColor << 1) | 1;

            newPixel = pixel & newColor;
        }

        image.setRGB(x, y, newPixel);
        if (logger.isDebugEnabled()) {
            if (imageDebug != null) {
            	if (imageDebug.getRGB(x, y) != newPixel) {
            		matrizDebug[x][y] = newPixel;
            	} else if (matrizDebug[x][y] != 0) {
            		matrizDebug[x][y] = 0;
            	}
            }
        }
    }
}
