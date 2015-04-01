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

import java.awt.Graphics;
import java.awt.GraphicsConfiguration;
import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.awt.HeadlessException;
import java.awt.Image;
import java.awt.Toolkit;
import java.awt.Transparency;
import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.MemoryImageSource;
import java.awt.image.PixelGrabber;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import sun.awt.image.ImageFormatException;

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.Utils;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.utils.Base64Coder;

/**
 * <p>Esta clase provee de métodos de uso común para el manejo de imágenes esteganografiadas según
 *  el estándar RandomLSB permitiendo realizar tareas de backup en firmas XAdES</p>
 */
public class StegoUtils {
	
	private static Log logger = LogFactory.getLog(StegoUtils.class);
	
	private static final String RESTAURATION_NODE_NAME = "RestaurationData";
	private static final String REST_DIGEST_NODE_NAME = "RestDigestData";
	
	/**
	 * <p>Convierte una java.awt.image.BufferedImage en un array de bytes en formato JPG ó PNG.</p>
	 * @param image Imagen en memoria a convertir.
	 * @param formato Formato del fichero destino, o <code>null</code>.
	 * <p>jp2 para jpeg 2000</p>
	 * <p>png por defecto</p>
	 * @return Array de bytes correspondientes a la imagen indicada.
	 * @throws Exception
	 */
	public static byte[] imageToByteArray(BufferedImage image, String formato)
			throws Exception {
		if (logger.isDebugEnabled()) {
			logger.debug("Convirtiendo imagen");
			logger.debug("Formato: " + formato);
		}
		ByteArrayOutputStream barrOS = new ByteArrayOutputStream();
		if(formato != null) {
			String imageType = formato.toLowerCase();
			if(imageType.equals("jp2"))
				imageType = "jpeg 2000";
			ImageIO.write(image, imageType, barrOS);
		} else {
			ImageIO.write(image, "png", barrOS);
		}
		//TODO:Incluir más formatos
		barrOS.close();
		return barrOS.toByteArray();
	}
	
	/**
	 * <p>Convierte un array de bytes en una java.awt.image.BufferedImage a través de javax.imageio.ImageIO.</p>
	 * @param imageData Array de bytes en memoria a convertir.
	 * @param imageFileName Nombre del fichero destino, o <code>null</code>.
	 * @return Imagen en memoria.
	 * @throws Exception
     */
	public static BufferedImage byteArrayToImage(byte[] imageData) throws Exception {
		BufferedImage image = null;
		if(imageData == null) {
			return null;
		}
		image = ImageIO.read(new ByteArrayInputStream(imageData));
		if(image == null) {
			throw new Exception("La imagen no se puede leer");
		}
		return image;
	}
	
    /**
     * Byte 2 Int 
     * @param b Byte a convertir
     * @return Int 
     */
    public static int byteToInt(int b) {
        int i = b;
        if(i < 0)
            i = i + 256;
        return i;
    }

	/**
	 * <p>Añade los datos de recuperación en la firma XML indicada.</p>
	 * @param data Datos sobre los que se obtiene la información a añadir.
	 * @param xml Fichero XML que contiene la firma de la imagen.
	 * @throws Exception
	 */
	public static void appendRestaurationDataToXML(char[] data, File xml) throws Exception {
		FileInputStream fis = null;
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Escribiendo datos en el fichero XML: " + xml.getAbsolutePath());
				logger.debug("Longitud de datos: " + ((data!=null)?data.length:"Datos nulos"));
			}
			fis = new FileInputStream(xml);
			Document doc = getDocument(fis);

			if (logger.isDebugEnabled()) {
				logger.debug("Calculando posición");
			}
			Element restaurationDataElement = doc.createElement(RESTAURATION_NODE_NAME);
			String text = null;
			if (data == null) {
				text = "000000";
			} else {
				text = String.valueOf(data.length);
				while (text.length() < 6) {
					text = "0" + text;
				}
			}
			restaurationDataElement.appendChild(doc.createTextNode(text));
			NodeList prevData = doc.getDocumentElement().getElementsByTagName(RESTAURATION_NODE_NAME);
			if (prevData != null && prevData.getLength() > 0) {
				doc.getDocumentElement().removeChild(prevData.item(0));
			}
			doc.getDocumentElement().appendChild(restaurationDataElement);

			if (logger.isDebugEnabled()) {
				logger.debug("Calculando digest");
			}
			Element restDigestDataElement = doc.createElement(REST_DIGEST_NODE_NAME);
			if (data == null) {
				text = "00000000000000000000000000000000000000000000";
			} else {
				byte[] buffer = new byte[data.length];
				for(int i = 0; i < data.length; i++) {
					buffer[i] = (byte) data[i];
				}
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(buffer);
				byte[] a = md.digest();
				char[] r = Base64Coder.encode(a);
				text = new String(r);
			}

			restDigestDataElement.appendChild(doc.createTextNode(text));
			prevData = doc.getDocumentElement().getElementsByTagName(REST_DIGEST_NODE_NAME);
			if (prevData != null && prevData.getLength() > 0) {
				doc.getDocumentElement().removeChild(prevData.item(0));
			}
			doc.getDocumentElement().appendChild(restDigestDataElement);
			
			if (logger.isDebugEnabled()) {
				logger.debug("Escribiendo el resultado");
			}
	        FileOutputStream f = new FileOutputStream(xml);
			
			Writer out = new OutputStreamWriter(f, "UTF-8");
       		
       		Transformer xformer = TransformerFactory.newInstance().newTransformer();           
       		Properties props = new Properties();
       		props.setProperty(OutputKeys.METHOD, "XML");
       		props.setProperty(OutputKeys.ENCODING, "UTF-8");
       		props.setProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
       		xformer.setOutputProperties(props);
       		
       		StringWriter salida = new StringWriter();
       		xformer.transform(new DOMSource(doc), new StreamResult(salida));
           	out.write(salida.toString());
           	out.flush();
       		out.close();
		} finally {
			if (fis != null) { 
				try {fis.close();} catch (IOException e) {}
			}
		}
	}
	
	/**
	 * <p>Añade los datos de recuperación en la imagen indicada.</p>
	 * @param data Datos a insertar
	 * @param image Imagen a utilizar como recipiente
	 * @throws Exception
	 */
	public static void appendRestaurationDataToImage(char[] data, File image) throws Exception {
		FileWriter fw = null;
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Añadiendo datos en la imagen: " + image.getAbsolutePath());
				logger.debug("Datos: " + data.length);
			}
			fw = new FileWriter(image, true);
			fw.append(new String(data));
			fw.flush();
		} finally {
			if (fw != null) { 
				try {fw.close();} catch (IOException e) {}
			}
		}
	}
	
	/**
	 * <p>Elimina los datos de recuperación de la imagen firmada para recuperar el original.</p>
	 * @param image Imagen firmada
	 * @param pos Posición de lectura donde se encuentran los datos de recuperación.
	 * @throws Exception
	 */
	public static void deleteRestaurationDataInImage(File image, int pos) throws Exception {
		FileInputStream fis = null;
		ByteArrayOutputStream baosLeido = null;
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Borrando datos de la imagen: " + image.getAbsolutePath());
				logger.debug("Posición: " + pos);
			}
			fis = new FileInputStream(image);
			int imgLenght = fis.available();
			baosLeido = new ByteArrayOutputStream();
			int bytesRead = 0;
			byte[] buffer = new byte[1024];
			while((bytesRead = fis.read(buffer, 0, 1024)) >= 0) {
				baosLeido.write(buffer, 0, bytesRead);
			}
			fis.close();
			if (logger.isDebugEnabled()) {
				logger.debug("Escribiendo imagen");
			}
			FileOutputStream fileOutput = new FileOutputStream(image);
			BufferedOutputStream bufferedOutput = new BufferedOutputStream(fileOutput);
			bufferedOutput.write(baosLeido.toByteArray(), 0, (imgLenght - pos));
			bufferedOutput.close();
		} finally {
			if (fis != null) { 
				try {fis.close();} catch (IOException e) {}
			}
			if (baosLeido != null) { 
				try {baosLeido.close();} catch (IOException e) {}
			}
		}
	}
	
	/**
	 * <p>Lee los datos de recuperación que se encuentran adjuntos en la imagen firmada.</p>
	 * @param img Imagen firmada
	 * @param pos Posición de lectura donde se encuentran los datos de recuperación.
	 * @return Array de bytes con los datos de recuperación o <code>null</code> en caso de error.
	 * @throws Exception
	 */
	public static byte[] readRestaurationDataFromImage(File img, int pos, byte[] digest) throws Exception {
		ByteArrayOutputStream baosLeido = null;
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Extrayendo datos de la imagen: " + img.getAbsolutePath());
				logger.debug("Posición: " + pos);
			}
			baosLeido = new ByteArrayOutputStream();

			if (pos > 0) {
				if (logger.isDebugEnabled()) {
					logger.debug("Leyendo imagen");
				}
				FileInputStream fisImg = new FileInputStream(img);
				int imgLenght = fisImg.available();
				int bytesRead = 0;
				byte[] buffer = new byte[1024];
				while((bytesRead = fisImg.read(buffer, 0, 1024)) >= 0) {
					baosLeido.write(buffer, 0, bytesRead);
				}

				int from = imgLenght - pos;

				byte[] data = Arrays.copyOfRange(baosLeido.toByteArray(), from, imgLenght);
				if (logger.isDebugEnabled()) {
					logger.debug("Datos extraídos. Comprobando la integridad...");
				}
				if (digest != null) {
					MessageDigest md = MessageDigest.getInstance("SHA-256");
					md.update(data);
					byte[] a = md.digest();

					if (Arrays.equals(digest, a)) {
						if (logger.isDebugEnabled()) {
							logger.debug("Dátos validos");
						}
						return data;
					}
					logger.debug("Los datos no superaron la validación de Digest");
					return null;
				}
				logger.error("Digest indicado nulo");
				return null;
			} else {
				logger.error("Posición indicada nula");
				return null;
			}
		} finally {
			if (baosLeido != null) { 
				try {baosLeido.close();} catch (IOException e) {}
			}
		}
	}
	
	/**
	 * <p>Devuelve el nombre y el tamaño original y el valor de Digest de la imagen firmada por el XML indicado como parámetro.</p>
	 * @param xml XML que contiene la firma de la imagen.
	 * @return En la primera posición se devuelve el tamaño original (-1 si hubo error) seguido del nombre (<code>null</code> si hubo error)
	 * y finalmente los byte[] del Digest (<code>null</code> si hubo error)
	 * @throws Exception
	 */
	public static ArrayList<Object> getRestaurationDataFromXML(File xml) throws Exception {
		ArrayList<Object> res = new ArrayList<Object>(3);
		FileInputStream fis = null;
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Extrayendo datos del XML: " + xml.getAbsolutePath());
			}
			fis = new FileInputStream(xml);
			Document doc = getDocument(fis);
			
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo posición de los datos");
			}
			NodeList prevData = doc.getElementsByTagName(RESTAURATION_NODE_NAME);
			if (prevData != null && prevData.getLength() > 0) {			
				res.add(Integer.parseInt(prevData.item(0).getTextContent()));
			} else {
				res.add(-1);
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo nombre del fichero");
			}
			ArrayList<Element> nodosReference = getChildElementByTagName(doc.getDocumentElement(), "Reference");
			if (nodosReference != null && nodosReference.size() > 0) {
				String name = null;
				for (int i = 0; i < nodosReference.size(); ++i) {
					NamedNodeMap att = nodosReference.get(i).getAttributes();
					for (int j = 0; j < att.getLength(); ++j) {
						Node at = att.item(j);
						String attVal = at.getTextContent();
						if (attVal != null && attVal.startsWith("." + File.separator)) {
							name = attVal;
							break;
						}
					}
				}
				res.add(name);
			} else {
				res.add(null);
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo valor de Digest");
			}
			ArrayList<Element> nodosDigest = getChildElementByTagName(doc.getDocumentElement(), REST_DIGEST_NODE_NAME);
			if (nodosDigest != null && nodosDigest.size() == 1) {
				String b64Val = nodosDigest.get(0).getTextContent();
				byte[] digest = Base64Coder.decode(b64Val);
				res.add(digest);
			} else {
				res.add(null);
			}
		} finally {
			if (fis != null) { 
				try {fis.close();} catch (IOException e) {}
			}
		}
		
		return res;
	}

	/**
	 * <p>Comprime los datos indicados en formato GZIP.</p>
	 * @param msg Datos a comprimir
	 * @return Datos comprimidos
	 * @throws Exception
	 */
	public static byte[] zipData(byte[] msg) throws Exception {
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Comprimiendo datos en ZIP: " + msg.length);
			}
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			GZIPOutputStream zos;
			zos = new GZIPOutputStream(bos);
			zos.write(msg);
			zos.finish();
			zos.close();
			bos.close();

			byte[] data = bos.toByteArray();
			if (logger.isDebugEnabled()) {
				logger.debug("Datos comprimidos: " + data.length);
			}
			return data;
		} catch(IOException ioEx) {
			logger.error("Error al inflar los datos");
			if (logger.isDebugEnabled()) {
				logger.debug(ioEx);
			}
			throw ioEx;
		}
	}
	
	/**
	 * <p>Descomprime los datos indicados en formato GZIP.</p>
	 * @param msg Datos a inflar
	 * @return Datos inflados
	 * @throws Exception
	 */
	public static byte[] unzipData(byte[] msg) throws Exception {
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Descomprimiendo datos en ZIP: " + msg.length);
			}
			ByteArrayInputStream bis = new ByteArrayInputStream(msg);
			GZIPInputStream zis = new GZIPInputStream(bis);
			msg = es.mityc.javasign.utils.Utils.getStreamBytes(zis);
			zis.close();
			bis.close();
			if (logger.isDebugEnabled()) {
				logger.debug("Datos inflados: " + msg.length);
			}
			return msg;
		} catch(IOException ioEx) {
			logger.error("Error al inflar los datos");
			if (logger.isDebugEnabled()) {
				logger.debug(ioEx);
			}
			throw ioEx;
		}
	}
	
	public static byte[] hashPass(String pass) {
		logger.debug("Se emplea el valor SHA256 como contraseña.");
		if(pass == null || pass.trim().equals("")) {
			logger.error("Contraseña nula o vacía. Se utiliza por defecto");
			return "3141592654Pi".getBytes();
		}
		es.mityc.javasign.utils.Utils.addBCProvider();
		try {
			MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA256,
					ConstantsAPI.PROVIDER_BC_NAME);
			return hash.digest(pass.getBytes());
		} catch (Exception e) {
			logger.error("Error al calcular el Digest de la contraseña", e);
			return "3141592654Pi".getBytes();
		}
	}
	
	public static long hashPassLong(String pass) {
		byte[] byteHash = hashPass(pass);
		// Se convierte a formato hexadecimal para emplear su valor numérico
		byte[] hex = new byte[2 * byteHash.length];
		int index = 0;
		int byteVal;

		byte[] HEX_CHAR_TABLE = {
				(byte) '0', (byte) '1', (byte) '2', (byte) '3',
				(byte) '4', (byte) '5', (byte) '6', (byte) '7',
				(byte) '8', (byte) '9', (byte) 'a', (byte) 'b',
				(byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'
		};

		for(int i = 0; i < byteHash.length; i++) {
			byteVal = byteHash[i] & 0xFF;
			hex[index++] = HEX_CHAR_TABLE[byteVal >>> 4];
			hex[index++] = HEX_CHAR_TABLE[byteVal & 0xF];
		}
		String hexString = new String(hex);

		// El casteo a Long utiliza solo 16 bytes. Se trunca el resultado.
		hexString = hexString.substring(0, 15);
		return Long.parseLong(hexString, 16);
	}
	
	private static Document getDocument(FileInputStream fis) throws Exception {
		ByteArrayOutputStream baosLeido = null;
		try {
			baosLeido = new ByteArrayOutputStream();
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true) ;
			DocumentBuilder db = null;
			db = dbf.newDocumentBuilder();

			int bytesRead = 0;
			byte[] data = new byte[1024];
			while((bytesRead = fis.read(data, 0, 1024)) >= 0) {
				baosLeido.write(data, 0, bytesRead);
			}

			InputSource isour = new InputSource(new ByteArrayInputStream(baosLeido.toByteArray()));
			return db.parse(isour);
		} finally {
			if (baosLeido != null) { 
				try {baosLeido.close();} catch (IOException e) {}
			}
		}
	}
	
	private static ArrayList<Element> getChildElementByTagName(Element padre, String name) {
		ArrayList<Element> resultado = new ArrayList<Element>();
    	NodeList nodesHijos = padre.getChildNodes();
    	
		for (int i = 0; i < nodesHijos.getLength(); i++) {
			Node nodo = nodesHijos.item(i);
			
			// Busca el siguiente elemento
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				continue;
			
			// comprueba si es un nodo de los buscados
			if (name.equals(nodo.getLocalName()))
				resultado.add((Element)nodo);
			
			if (nodo.hasChildNodes()) {
				resultado.addAll(getChildElementByTagName((Element)nodo, name));
			}
		}
		return resultado;
	}
	
	/**
	 * <p>Recalcula la imagen indicada para sobreescribirla en un formato compatible.</p>
	 * <p>Los formatos compatibles vienen determinados por la clase <code>javax.imageio.ImageIO</code></p>
	 * @param imagen Imagen a reconvertir.
	 * @param destino Destino de la imagen recalculada.
	 * @throws Exception
	 */
	public static File prepareImage(File imagen, File destino) throws Exception {
		int BUF_SIZE = 512;
		byte[] res = null;
		BufferedOutputStream fos = null;
		
		InputStream is = null;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int bytesRead = 0;
		byte[] data = new byte[BUF_SIZE];
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Leyendo imagen.");
			}
			is = new FileInputStream(imagen);
			while((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
				bos.write(data, 0, bytesRead);
			}
			bos.flush();
			bos.close();
			is.close();
			
			if (logger.isDebugEnabled()) {
				logger.debug("Realizando la conversión");
			}
			
			BufferedImage image = null;
			if (imagen.getName().endsWith("bmp")) {
				image = StegoUtils.convertBitmap(imagen);
				// Se cambia la extensión a PNG
				destino = new File(destino.getAbsolutePath() + ".png");
				if (destino.exists()) {
					destino = new File(destino.getAbsolutePath() + new Random().nextInt(100) + ".png");
				}
			} else if (imagen.getName().endsWith("jpg")) {
				image = StegoUtils.byteArrayToImage(bos.toByteArray());
				// Se cambia la extensión a PNG
				destino = new File(destino.getAbsolutePath() + ".png");
				if (destino.exists()) {
					destino = new File(destino.getAbsolutePath() + new Random().nextInt(100) + ".png");
				}
			} else {
				image = StegoUtils.byteArrayToImage(bos.toByteArray());
			}
			
			if (image == null) {
				throw new ImageFormatException("Imagen no compatible");
			}
			
			if (image.getType() != BufferedImage.TYPE_INT_RGB) {
				int width = image.getWidth();
				int height = image.getHeight();
				BufferedImage imageConv = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
				for(int x = 0; x < width; x++) {
					for(int y = 0; y < height; y++) {
						imageConv.setRGB(x, y, image.getRGB(x, y));
					}
				}

				String formatoDestino = destino.getAbsolutePath();
				formatoDestino = formatoDestino.substring(formatoDestino.lastIndexOf('.') + 1);
				res = StegoUtils.imageToByteArray(imageConv, formatoDestino);
			} else {
				String formatoDestino = destino.getAbsolutePath();
				formatoDestino = formatoDestino.substring(formatoDestino.lastIndexOf('.') + 1);
				res = StegoUtils.imageToByteArray(image, formatoDestino);
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Escribiendo el resultado");
			}
			
			fos = new BufferedOutputStream(new FileOutputStream(destino));
			fos.write(res);
			
			return destino;
		} catch (Exception e) {
			logger.error(e);
			throw e;
		} finally {
			if (fos != null) {
				try {
					fos.flush();
					fos.close();
				} catch (Throwable e) {
					if (logger.isDebugEnabled()) {
						logger.debug(e);
					}
				}
			}
		}
	}
	
	/**
	 * <p>Convierte un mapa de bits a un formato compatible.</p>
	 * @param imagen Mapa de bits a convertir
	 * @return Imagen cargada en memoria.
	 */
	public static BufferedImage convertBitmap(File imagen) {
		if (logger.isDebugEnabled()) {
			logger.debug("Convirtiendo el mapa de bits: " + imagen.getAbsolutePath());
		}
		Image image = null;
		FileInputStream fs = null;
		try {
			fs = new FileInputStream(imagen);

			int bflen = 14; // 14 byte BITMAPFILEHEADER
			byte bf[] = new byte[bflen];
			fs.read(bf,0,bflen);

			int bilen=40; // 40-byte BITMAPINFOHEADER
			byte bi[] = new byte[bilen];
			fs.read(bi,0,bilen);

			// Interperet data.
			// int nsize = (((int)bf[5]&0xff) << 24)
			//      | (((int)bf[4]&0xff) << 16)
			//      | (((int)bf[3]&0xff) << 8)
			//      | (int)bf[2]&0xff;
			if (logger.isDebugEnabled()) {
				logger.debug("Tipo de mapa de bits: " + (char)bf[0]+(char)bf[1]);
			}

			int nbisize = (((int)bi[3]&0xff) << 24)
					| (((int)bi[2]&0xff) << 16)
					| (((int)bi[1]&0xff) << 8)
					| (int)bi[0]&0xff;
			if (logger.isDebugEnabled()) {
				logger.debug("Tamaño de la cabecera: " + nbisize);
			}

			int nwidth = (((int)bi[7]&0xff) << 24)
					| (((int)bi[6]&0xff) << 16)
					| (((int)bi[5]&0xff) << 8)
					| (int)bi[4]&0xff;

			int nheight = (((int)bi[11]&0xff) << 24)
					| (((int)bi[10]&0xff) << 16)
					| (((int)bi[9]&0xff) << 8)
					| (int)bi[8]&0xff;
			if (logger.isDebugEnabled()) {
				logger.debug("Tamaño de la imagen: " + nwidth + ", " + nheight);
			}

			// int nplanes = (((int)bi[13]&0xff) << 8) | (int)bi[12]&0xff;
			int nbitcount = (((int)bi[15]&0xff) << 8) | (int)bi[14]&0xff;

			// Look for non-zero values to indicate compression
			int ncompression = (((int)bi[19]) << 24)
					| (((int)bi[18]) << 16)
					| (((int)bi[17]) << 8)
					| (int)bi[16];
			if (logger.isDebugEnabled()) {
				logger.debug("Compresión de imagen: " + ncompression);
			}

			int nsizeimage = (((int)bi[23]&0xff) << 24)
					| (((int)bi[22]&0xff) << 16)
					| (((int)bi[21]&0xff) << 8)
					| (int)bi[20]&0xff;

			// int nxpm = (((int)bi[27]&0xff) << 24)
			//      | (((int)bi[26]&0xff) << 16)
			//      | (((int)bi[25]&0xff) << 8)
			//      | (int)bi[24]&0xff;
			//
			// int nypm = (((int)bi[31]&0xff)<<24)
			//      | (((int)bi[30]&0xff)<<16)
			//      | (((int)bi[29]&0xff)<<8)
			//      | (int)bi[28]&0xff;
			// // Y-Pixels per meter is nypm

			int nclrused = (((int)bi[35]&0xff) << 24)
					| (((int)bi[34]&0xff) << 16)
					| (((int)bi[33]&0xff) << 8)
					| (int)bi[32]&0xff;
			if (logger.isDebugEnabled()) {
				logger.debug("Colores: " + nclrused);
			}

			// int nclrimp = (((int)bi[39]&0xff)<<24)
			//      | (((int)bi[38]&0xff)<<16)
			//      | (((int)bi[37]&0xff)<<8)
			//      | (int)bi[36]&0xff;
			// Colors important are nclrimp

			if (nbitcount == 24) {
				// No Palatte data for 24-bit format but scan lines are
				// padded out to even 4-byte boundaries.
				int npad = (nsizeimage / nheight) - nwidth * 3;
				// added for Bug correction
				if(npad == 4) {
					npad = 0;
				}
				int ndata[] = new int [nheight * nwidth];
				byte brgb[] = new byte [( nwidth + npad) * 3 * nheight];

				fs.read (brgb, 0, (nwidth + npad) * 3 * nheight);
				int nindex = 0;
				for (int j = 0; j < nheight; j++) {
					for (int i = 0; i < nwidth; i++) {
						ndata [nwidth * (nheight - j - 1) + i] =
								(255&0xff) << 24
								| (((int)brgb[nindex+2]&0xff) << 16)
								| (((int)brgb[nindex+1]&0xff) << 8)
								| (int)brgb[nindex]&0xff;
						nindex += 3;
					}
					nindex += npad;
				}

				image = Toolkit.getDefaultToolkit().createImage( new MemoryImageSource (nwidth, nheight,ndata, 0, nwidth));
			} else if (nbitcount == 8) {
				// Have to determine the number of colors, the clrsused
				// parameter is dominant if it is greater than zero. If
				// zero, calculate colors based on bitsperpixel.
				int nNumColors = 0;
				if (nclrused > 0) {
					nNumColors = nclrused;
				} else {
					nNumColors = (1&0xff)<<nbitcount;
				}
				if (logger.isDebugEnabled()) {
					logger.debug("Colores: " + nNumColors);
				}

				// Some bitmaps do not have the sizeimage field calculated
				// Ferret out these cases and fix 'em.
				if (nsizeimage == 0) {
					nsizeimage = ((((nwidth*nbitcount)+31) & ~31 ) >> 3);
					nsizeimage *= nheight;
				}

				// Read the palatte colors.
				int npalette[] = new int [nNumColors];
				byte bpalette[] = new byte [nNumColors*4];
				fs.read (bpalette, 0, nNumColors*4);
				int nindex8 = 0;
				for (int n = 0; n < nNumColors; n++) {
					npalette[n] = (255&0xff) << 24
							| (((int)bpalette[nindex8+2]&0xff) << 16)
							| (((int)bpalette[nindex8+1]&0xff) << 8)
							| (int)bpalette[nindex8]&0xff;
					nindex8 += 4;
				}
				// Read the image data (actually indices into the palette)
				// Scan lines are still padded out to even 4-byte
				// boundaries.
				int npad8 = (nsizeimage / nheight) - nwidth;

				int ndata8[] = new int [nwidth*nheight];
				byte bdata[] = new byte [(nwidth+npad8)*nheight];
				fs.read (bdata, 0, (nwidth+npad8)*nheight);
				nindex8 = 0;
				for (int j8 = 0; j8 < nheight; j8++) {
					for (int i8 = 0; i8 < nwidth; i8++) {
						ndata8 [nwidth*(nheight-j8-1)+i8] =
								npalette [((int)bdata[nindex8]&0xff)];
						nindex8++;
					}
					nindex8 += npad8;
				}

				image = Toolkit.getDefaultToolkit().createImage( new MemoryImageSource (nwidth, nheight,ndata8, 0, nwidth));
			
			} else if (nbitcount == 1) {
				int npad1 = (nsizeimage / nheight) - nwidth/8;
				byte bdata[] = new byte [(nwidth+npad1) * nheight];
				fs.read (bdata, 0, 8);
				fs.read (bdata, 0, (nwidth+npad1)*nheight);
				int ndata1[] = new int [nwidth*nheight];
				int nindex1 = 0;

				for (int j1 = 0; j1 < nheight ; j1++) {
					int iindex;
					iindex = nindex1;
					for (int i1 = 0; i1 <= nwidth/8 ; i1++) {
						int ib1 = 0;
						if (i1*8 < nwidth) {
							for (int b1 = 128 ; b1 > 0 ; b1 = b1 / 2) {
								ndata1 [nwidth*(nheight-j1-1)+i1*8+ib1] =
										((b1 & bdata[iindex]) > 0) ? 255 + (255+255*256) * 256 : 0;
								ib1++;
								if (i1*8+ib1 >= nwidth) {
									b1 = 0;
								}
							}
						}
						iindex++;
					}
					nindex1 += (nsizeimage / nheight);
				}

				image = Toolkit.getDefaultToolkit().createImage(
							new MemoryImageSource(nwidth, nheight,ndata1, 0, nwidth));
			} else {
				logger.error("Formato incompatible. No pertenece a un formato válido de 24, 8 o 1 bit.");
				image = null;
			}
			
			BufferedImage img = toBufferedImage(image);

			return img;
		} catch (Exception e) {
			logger.error("No se pudo convertir la imagen", e);
		} finally {
			try {
				fs.close();
			} catch (Exception e) {
				logger.debug(e);
			}
		}
		
		return null;
	}
	
	private static BufferedImage toBufferedImage(Image image) {
	    if (image instanceof BufferedImage) {
	        return (BufferedImage)image;
	    }

	    // This code ensures that all the pixels in the image are loaded
	    image = new ImageIcon(image).getImage();

	    // Determine if the image has transparent pixels; for this method's
	    // implementation, see Determining If an Image Has Transparent Pixels
	    boolean hasAlpha = hasAlpha(image);

	    // Create a buffered image with a format that's compatible with the screen
	    BufferedImage bimage = null;
	    GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
	    try {
	        // Determine the type of transparency of the new buffered image
	        int transparency = Transparency.OPAQUE;
	        if (hasAlpha) {
	            transparency = Transparency.BITMASK;
	        }

	        // Create the buffered image
	        GraphicsDevice gs = ge.getDefaultScreenDevice();
	        GraphicsConfiguration gc = gs.getDefaultConfiguration();
	        bimage = gc.createCompatibleImage(image.getWidth(null), image.getHeight(null), transparency);
	    } catch (HeadlessException e) {
	    	logger.error("No se pudo recuperar los datos de cabacera de la imagen", e);
	    }

	    if (bimage == null) {
	        // Create a buffered image using the default color model
	        int type = BufferedImage.TYPE_INT_RGB;
	        if (hasAlpha) {
	            type = BufferedImage.TYPE_INT_ARGB;
	        }
	        bimage = new BufferedImage(image.getWidth(null), image.getHeight(null), type);
	    }

	    // Copy image to buffered image
	    Graphics g = bimage.getGraphics();

	    // Paint the image onto the buffered image
	    g.drawImage(image, 0, 0, null);
	    g.dispose();

	    return bimage;
	}
	
	// This method returns true if the specified image has transparent pixels
	private static boolean hasAlpha(Image image) {
	    // If buffered image, the color model is readily available
	    if (image instanceof BufferedImage) {
	        BufferedImage bimage = (BufferedImage)image;
	        return bimage.getColorModel().hasAlpha();
	    }

	    // Use a pixel grabber to retrieve the image's color model;
	    // grabbing a single pixel is usually sufficient
	     PixelGrabber pg = new PixelGrabber(image, 0, 0, 1, 1, false);
	    try {
	        pg.grabPixels();
	    } catch (InterruptedException e) {
	    	logger.error("No se pudo leer los pixels de la imagen", e);
	    	return false;
	    }

	    // Get the image's color model
	    ColorModel cm = pg.getColorModel();
	    return cm.hasAlpha();
	}
}
