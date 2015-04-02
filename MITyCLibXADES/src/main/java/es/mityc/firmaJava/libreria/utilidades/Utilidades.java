/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES".
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
package es.mityc.firmaJava.libreria.utilidades;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.HexEncoder;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Diversas funciones de utilidades para el desarrollo
 * 
 */
public class Utilidades { // implements ConstantesXADES
	
	static Log logger = LogFactory.getLog(Utilidades.class);

	private static final String  STR_ABRIENDO_CONEXION = "Abriendo conexion con ";
	private static final String  STR_TRES_PUNTOS = "...";

	/**
	 * Este método mira si un string no es nulo, blancos o vacío
	 * @param valor
	 * @return true si tiene valor o false si es nulo, blancos o vacío
	 */
	public static boolean tieneValor(String valor) {
		if (valor != null && !valor.trim().equals(ConstantesXADES.CADENA_VACIA)){
			return true;
		}
		return false;
	}

	/**
	 * Este método mira si un string es nulo, blancos o vacío
	 * @param valor
	 * @return true si es nulo, blancos o vacío y false en caso contrario
	 */
	public static boolean isEmpty (String valor) {
		return (valor == null || valor.trim().equals(ConstantesXADES.CADENA_VACIA));
	}

	/**
	 * Este metodo recupera via URLConnection el fichero ubicado en la
	 * URL pasada como parametro. Devuelve un objeto tipo FileInputStream
	 * @return
	 */
	public static InputStream getInputStreamFromURL(String _url)
	throws Exception
	{
		URL url  = new URL(_url);
		logger.debug( STR_ABRIENDO_CONEXION + _url + STR_TRES_PUNTOS); 
		url.openConnection();
		// Copia el recurso al fichero local, usa un fichero remoto
		// si no esta especificado el nombre del fichero local
		InputStream is = url.openStream();

		System.out.flush();

		return is;
	}

	/**
	 * Método que almacena en el destino el contenido del fichero origen tras pasarlo a Base64
	 * @param sourceFile fichero origen
	 * @param wtargetFile writer destino
	 * @throws IOException
	 */
	public static void writeInputStream (File sourceFile, Writer wtargetFile) throws IOException {
		byte[] buffer = new byte[510];
		int numBytes=0;
		BufferedInputStream bSourceFile = null;
		BufferedWriter targetFile = (BufferedWriter) wtargetFile;
		try {
			bSourceFile = new BufferedInputStream(new FileInputStream(sourceFile));
			String aux = ConstantesXADES.CADENA_VACIA;
			do {
				numBytes = bSourceFile.read(buffer);
				if(numBytes == -1) break;
				aux = new String(Base64Coder.encode(buffer, numBytes));
				targetFile.write(aux);
			} while (numBytes >= 0);
		} 
		finally  {
			if (null != bSourceFile)
				bSourceFile.close();
		}

	}

	/**
	 * Método que almacena en el writer destino y en otro fichero el contenido del fichero origen tras pasarlo a Base64
	 * @param sourceFile fichero origen
	 * @param attachedFile fichero en el que copiar los datos pasadoa a base64
	 * @param wtargetFile writer al que se añadirán los datos en base64
	 * @throws IOException
	 */
	public static void writeInputStream (File sourceFile, File attachedFile, Writer wtargetFile) throws IOException {
		byte[] buffer = new byte[510];
		int numBytes=0;

		BufferedInputStream bSourceFile = null;
		BufferedWriter targetFile = (BufferedWriter) wtargetFile;

		BufferedWriter ficheroAdjuntoDatos = new BufferedWriter(new FileWriter(attachedFile));
		attachedFile.deleteOnExit();


		try {
			bSourceFile = new BufferedInputStream(new FileInputStream(sourceFile));
			String aux = ConstantesXADES.CADENA_VACIA;
			do {
				numBytes = bSourceFile.read(buffer);
				if(numBytes == -1) break;
				aux = new String(Base64Coder.encode(buffer, numBytes));
				targetFile.write(aux);
				ficheroAdjuntoDatos.write(aux);
				targetFile.flush();
				ficheroAdjuntoDatos.flush();

			} while (numBytes >= 0);

		} 
		finally  {
			if (null != ficheroAdjuntoDatos)
				ficheroAdjuntoDatos.close();

			if (null != bSourceFile)
				bSourceFile.close();
		}

	}
	
	/**
	 * Codifica un array de bytes a Hexadecimal
	 * @param byte[] Datos a codificar
	 * @return String Datos codificados en hexadecimal
	 */
	public static String binary2String(byte[] data) {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			HexEncoder enc = new HexEncoder();
			enc.encode(data, 0, data.length, baos);
			return baos.toString();
		} catch (IOException ex) {
		}
		return null;
	}
	
	/**
	 * Compara dos arrays de bytes para ver si tienen el mismo contenido.
	 * 
	 * @param data1 
	 * @param data2
	 * @return <code>true</code> si tienen el mismo contenido, <code>false</code> en cualquier otro caso
	 */
	public static boolean isEqual(byte[] data1, byte[] data2) {
		if ((data1 == null) && (data2 == null))
			return true;
		if ((data1 == null) || (data2 == null))
			return false;
		if (data1.length != data2.length)
			return false;
		for (int i = 0; i < data1.length; i++) {
			if (data1[i] != data2[i])
				return false;
		}
		return true;
	}
	
	private static int[] XML_ENTITIES = { 34, 38, 39, 60, 62 }; 
	
	/**
	 * <p>Escapa las entidades básicas de xml.</p>
	 * <p>Basada en la clase StringEscapeUtils de commons-lang pero sin cambiar los caracteres unicode.</p>
	 * @param str cadena a escapar
	 * @return
	 */
	public static String escapeXML(String str) {
		StringWriter stringWriter = new StringWriter((int)((double)str.length() + (double)str.length() * 0.10000000000000001D));
        int len = str.length();
        for(int i = 0; i < len; i++)
        {
            char c = str.charAt(i);
            if ((XML_ENTITIES[0] == c) || (XML_ENTITIES[1] == c) || (XML_ENTITIES[2] == c) || (XML_ENTITIES[3] == c) || (XML_ENTITIES[4] == c)) {
            	stringWriter.write("&#");
            	stringWriter.write(Integer.toString(c, 10));
            	stringWriter.write(59);
            } else {
            	stringWriter.write(c);
            }
        }
        return stringWriter.toString();
	}
}
