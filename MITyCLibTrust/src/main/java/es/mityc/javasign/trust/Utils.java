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
package es.mityc.javasign.trust;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Properties;

import es.mityc.crypto.symetric.TripleDESManager;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Proporciona métodos comunes para la entrada y salida de datos de forma segura.</p>
 * <p>Incluye un método para calcular la huella MD5 de un certificado.</p>
 * 
 */
public class Utils {
	
	private static II18nManager i18n = I18nFactory.getI18nManager(ConstantsTrust.LIB_NAME);
	
	private static byte[] pass = new byte[] { 100, 87, 39, 78, 66, 55, 100, 75, 77, 114,
		 97, 85, 35, 119, 53, 64, 109, 98, 88, 37,
		 123, 44, 83, 88, 51, 103, 95, 94, 70, 40,
		 48, 104, 82, 66, 60, 70, 74, 118, 36, 55,
		 105, 98, 37, 73, 71, 34, 80, 75, 67, 63, 
		 87, 114, 39 };

	public static void setPass(byte[] password) {
		pass = password;
	}
	
	/**
	 * <p>Permite calcular el valor de Digest MD5 del certificado indicado.<p>
	 * @param cert Certificado a leer
	 * @return Valor MD5 del certificado.
	 * @throws Exception en caso de que no sea posible calcular su Digest
	 */
	public static String getMD5(X509Certificate cert) throws Exception {
		// Se calcula el valor de Digest del certificado
		MessageDigest certDigest = MessageDigest.getInstance("MD5");
		byte[] digestByte = certDigest.digest(cert.getEncoded());
		StringBuffer sb = new StringBuffer("");
		for (int i = 0; i < digestByte.length; i++) {
			sb.append(Integer.toString((digestByte[i] & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}
	
	/**
	 * <p>Encripta un fichero.</p>
	 * @param filePath Ruta absoluta al fichero destino
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al proteger la contraseña
	 */
	public static void protectConf(Properties conf, String path) throws SecurityException {
		if (pass == null || "".equals(new String(pass).trim()) || conf == null) {
			throw new SecurityException(i18n.getLocalMessage(ConstantsTrust.I18N_TRUST_UTILS_1));	
		}

		// Se instancia el encriptador
		TripleDESManager p = new TripleDESManager();

		// Se parsea la configuración
		String confText = conf.toString();
		confText = confText.substring(1, confText.lastIndexOf('}')).replace(',', '\n').replace('\\', '/');
		byte[] plainProps = confText.getBytes();

		// Se hace efectiva la encriptación
		char[] bufferChar = p.protectTripleDES(plainProps, new String(pass));
		String protectedConf = new String(bufferChar);

		try {
			File protectedFile = new File(path);
			Writer w = new FileWriter(protectedFile);
			w.write(protectedConf);
			w.close();
		} catch (IOException e) {
			throw new SecurityException(i18n.getLocalMessage(ConstantsTrust.I18N_TRUST_UTILS_2), e);
		}
	}
	
	/**
	 * <p>Desencripta un fichero convirtiéndolo en texto plano.</p>
	 * @param filePath Ruta absoluta al fichero
	 * @return Información en claro
	 */
	public static byte[] recoverConf(String filePath) throws SecurityException {
		if (pass == null || "".equals(new String(pass).trim()) || !new File(filePath).exists()) {
			throw new SecurityException(i18n.getLocalMessage(ConstantsTrust.I18N_TRUST_UTILS_1));	
		}
		InputStream bis = null;
		try {

			// Se recuperan los datos de la ruta indicada
			File file = new File(filePath);
			bis = new BufferedInputStream(new FileInputStream(file));
			byte[] buffer = null;
			int length = 0;
			int numBytes = 0;

			// Se comprueba el tamaño del fichero
			long len = file.length();
			if( len > Integer.MAX_VALUE ) {
				throw new SecurityException("Fichero de configuración demasiado largo: " + len);
			}

			// Se realiza la lectura
			buffer = new byte[(int)file.length()];
			if (buffer.length < 4096) {
				bis.read(buffer, length, (int)file.length());
			} else {
				int longitud = bis.read( buffer, length, 4096 );
				while((numBytes = longitud) >= 0 ){
					length += numBytes;
					longitud = bis.read( buffer, length, 4096 );
				}
			}
			
			if( len < 4 ) {
				return buffer;
			}
			
			// Se instancia el encriptador
			TripleDESManager p = new TripleDESManager();

			// Se recupera el texto en claro
			return p.recoverTripleDES(new String(buffer).toCharArray(), new String(pass));
		} catch(IOException ex) {
			throw new SecurityException(ex);
        } finally {
            try {
               if (bis != null){	
            	   bis.close();
               }
            } catch( Exception e) {}
        }
	}
}
