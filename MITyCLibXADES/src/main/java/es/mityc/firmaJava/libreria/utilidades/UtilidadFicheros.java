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
/**
 * 
 */
package es.mityc.firmaJava.libreria.utilidades;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;

import org.w3c.dom.Document;

/**
 * Clase de utilidad para el trabajo con ficheros
 *
 */
public class UtilidadFicheros {
	
	public static byte[] readFile(File file) {
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			int length = (int)file.length();
			ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
			byte[] buffer = new byte[4096];
			int i = 0;
			while (i < length) {
				int j = fis.read(buffer);
				baos.write(buffer, 0, j);
				i += j;
			}
			return baos.toByteArray();
		} catch (FileNotFoundException ex) {
		} catch (IOException ex) {
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException ex) {
				}
			}
		}
		return null;
	}
	
    /**
     * <p>Devuelve la ruta a un fichero relativa a la base indicada.</p> 
     * @param baseUri Base sobre la que se relativiza la ruta
     * @param file Fichero del que se calcula la ruta
     * @return ruta relativizada
     */
	public static String relativizeRute(String baseUri, File file) {
		String strFile = null;
    	try {
			URI relative = new URI(URIEncoder.encode(baseUri, "UTF-8"));
			URI uri = file.toURI();
			strFile = URIEncoder.relativize(relative.toString(), uri.toString());
		} catch (UnsupportedEncodingException e) {
				strFile = file.toURI().toString();
		} catch (URISyntaxException e) {
				strFile = file.toURI().toString();
		}
		
    	return strFile;
    }

	/**
	 * Escribe un Document en un outputstream
	 * @param doc Documento xml a escribir
	 * @param out OutputStream en el que escribir el xml
	 */
	public static void writeXML(Document doc, OutputStream out) {
		OutputStreamWriter osw = new OutputStreamWriter(out);
		
		com.sun.org.apache.xerces.internal.dom.DOMOutputImpl domoutputimpl = new com.sun.org.apache.xerces.internal.dom.DOMOutputImpl();
		domoutputimpl.setEncoding(doc.getXmlEncoding());
		domoutputimpl.setCharacterStream(osw);
		
		org.w3c.dom.ls.LSSerializer serializer;
		org.w3c.dom.ls.DOMImplementationLS dils;
		dils = (org.w3c.dom.ls.DOMImplementationLS)doc.getImplementation();
		serializer = dils.createLSSerializer();
		serializer.getDomConfig().setParameter("namespaces", false);
		serializer.getDomConfig().getParameterNames();
		((org.w3c.dom.ls.LSSerializer) (serializer)).write(doc, domoutputimpl);

	}

}
