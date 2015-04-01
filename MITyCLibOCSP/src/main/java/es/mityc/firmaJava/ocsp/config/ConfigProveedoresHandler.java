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
package es.mityc.firmaJava.ocsp.config;

import java.net.URISyntaxException;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Clase encargada de leer el fichero de configuracion de los OCSP's. 
 * 
 */

public final class ConfigProveedoresHandler 
	extends DefaultHandler implements ConstantesProveedores {

    static Log logger = LogFactory.getLog(ConfigProveedoresHandler.class);
	private boolean leyendoProveedor = false;
    private String valorTmp = EMPTY_STRING;

	private Vector<ProveedorInfo> proveedores = new Vector<ProveedorInfo>();
	private String version = EMPTY_STRING;
	private String fecha = EMPTY_STRING;
	
	public void error(SAXParseException ex)
	      throws SAXException {
			  throw ex;
	}     
	public void fatalError(SAXParseException ex)
	     throws SAXException {
		  throw ex;
	}		    
	public void warning(SAXParseException exception)
	      throws SAXException { 
		logger.warn(exception.getMessage());	  
	}
	
	public void startElement(
			final String namespace, 
			final String localname,  
		    final String type, 
		    final Attributes attributes) throws SAXException {
		
		
		if (localname.equals(NODO_PROVEEDOR)) { 
			leyendoProveedor = true;
			String v1 = EMPTY_STRING;
			String v2 = EMPTY_STRING;
			int at1 = attributes.getIndex(ATT_NOMBRE);
			int at2 = attributes.getIndex(ATT_DESCRIPCION);
			if (at1 >= 0) v1 = attributes.getValue(at1);
			if (at2 >= 0) v2 = attributes.getValue(at2);
			
			ProveedorInfo po = new ProveedorInfo();
			
			po.setNombre(v1);
			po.setDescripcion(v2);
			proveedores.add(po);
		} else 
			if (false == leyendoProveedor) return;
		
		if (localname.equals(NODO_CA)) { 
			String v1 = EMPTY_STRING;
			String v2 = EMPTY_STRING;
			int at1 = attributes.getIndex(ATT_NAMEHASH);
			int at2 = attributes.getIndex(ATT_PKHASH);
			if (at1 >= 0) v1 = attributes.getValue(at1);
			if (at2 >= 0) v2 = attributes.getValue(at2);
			
			((ProveedorInfo) proveedores.lastElement()).addCA 
				(
					v1, v2
				);
		}
		
		if (localname.equals(NODO_OCSP)) { 
			String v1 = EMPTY_STRING;
			String v2 = EMPTY_STRING;
			int at1 = attributes.getIndex(ATT_URI);
			int at2 = attributes.getIndex(ATT_DESCRIPCION);
			if (at1 >= 0) v1 = attributes.getValue(at1);
			if (at2 >= 0) v2 = attributes.getValue(at2);
			
			ServidorOcsp server = null;
			try {
				server = new ServidorOcsp(v1,v2);
				((ProveedorInfo) proveedores.lastElement()).addServidor(server);
			} catch (URISyntaxException e) {
				throw new SAXException (INVALID_URI + e.getMessage());
			}
		} 
	}

	public void characters(char[] ch, int start, int end) throws SAXException {
		valorTmp = new String (ch, start, end);
		valorTmp = valorTmp.trim();
	}
	public void endElement ( final String namespace, final String localname, final String type ) 
	{
		if (localname.equals(NODO_PROVEEDOR)) leyendoProveedor = false;
		if (localname.equals(NODO_VERSION)) {
			this.version = valorTmp;
		}
		if (localname.equals(NODO_FECHA)) {
			this.fecha = valorTmp;
		}
	}
	protected Vector<ProveedorInfo> getProveedores() {
		return proveedores;
	}
	protected String getFecha() {
		return fecha;
	}
	protected String getVersion() {
		return version;
	}

}
