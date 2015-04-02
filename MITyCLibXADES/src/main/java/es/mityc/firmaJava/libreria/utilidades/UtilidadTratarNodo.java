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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import adsi.org.apache.xml.security.c14n.CanonicalizationException;
import adsi.org.apache.xml.security.signature.XMLSignatureInput;
import adsi.org.apache.xml.security.transforms.TransformationException;
import adsi.org.apache.xml.security.transforms.Transforms;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.CanonicalizationEnum;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;

/**
 * Conjunto de utilidades para tratar todos xml.
 * 
 */

public class UtilidadTratarNodo {
	
	private static Log log = LogFactory.getLog(UtilidadTratarNodo.class);

	private final static String[] IDs = {ConstantesXADES.ID, ConstantesXADES.ID_MINUS, ConstantesXADES.ID_MAYUS}; 
	
	private static Random rnd = new Random(new Date().getTime());
	private final static int RND_MAX_SIZE = 1048576;
	
	/** Sentencia de selección de nodo por xpointer. */
	public static final String XPOINTER_ID  = "#xpointer(id('";
	/** Sentencia de selección del nodo raíz por xpointer. */
	public static final String XPOINTER_ROOT  = "#xpointer(/)";


	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del documento, y que se ajusten al namespace.
	 * 
	 * @param doc documento en el que se buscarán los hijos (en cualquier profundidad)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo raiz)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Document doc, String ns, String nombreHijos, CanonicalizationEnum canonicalization) throws FirmaXMLError{
		return obtenerByteNodo(doc.getDocumentElement(), ns, nombreHijos, canonicalization, 0);
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * Equivalente a la ejecución:
	 * <blockquote>
	 * obtenerByteNodo(Element padre, String ns, String nombreHijos, true)
	 * </blockquote>
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (en cualquier profundidad)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo padre)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, String ns, String nombreHijos, CanonicalizationEnum canonicalization, int tope) throws FirmaXMLError{
		return obtenerByteNodo(padre, ns, nombreHijos, true, canonicalization, tope);
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (en la profundidad indicada entre 1 y 5)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo padre)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @param requerido Si el valor es <code>true</code> y no se encuentra ningún hijo lanzará excepción
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, String ns, String nombreHijos, boolean requerido, CanonicalizationEnum canonicalization, int tope) throws FirmaXMLError{
		if ((canonicalization == null) || (canonicalization.equals((CanonicalizationEnum.UNKNOWN))))
			throw new FirmaXMLError("Canonicalization Method desconocido");
		
    	ArrayList<Element> nodesHijos = new ArrayList<Element> ();
    	
		if (ns == null)
			ns = padre.getNamespaceURI();
		
		if (tope <= 0) {
			NodeList nodosSinTope = padre.getElementsByTagNameNS(ns, nombreHijos);
			for (int i = 0; i < nodosSinTope.getLength(); ++i) {
				nodesHijos.add((Element)nodosSinTope.item(i));
			}
		} else
			nodesHijos = obtenerNodos(padre, tope, new NombreNodo(ns, nombreHijos));
		
    	log.debug(ConstantesXADES.MSG_NUMERO_FIRMAS_DOCUMENTO +  nodesHijos.size());
    	    	
    	if ((nodesHijos.size() == 0) && (requerido)) {
        	log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8) + ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_33) + ConstantesXADES.ESPACIO + nombreHijos);
        	throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8) + ConstantesXADES.ESPACIO +  I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_33) + ConstantesXADES.ESPACIO + nombreHijos);
        }  

    	if (nodesHijos.size() > 0) { 
        	Transforms  t = new Transforms(padre.getOwnerDocument());
        	
        	try {
    			t.addTransform(canonicalization.toString());
    		} catch (TransformationException e) {
    			log.error(e);
    			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
    		}
    		
			ByteArrayOutputStream bais = new ByteArrayOutputStream();
			
			for (int i = 0; i < nodesHijos.size(); i++) {
				XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodesHijos.get(i));
				try {
					XMLSignatureInput resultado = null;
					resultado = t.performTransforms(xmlSignatureInput);
					bais.write(resultado.getBytes());
				} catch (TransformationException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (CanonicalizationException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (IOException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				}
			}
			
			if (bais.size() > 0) 
				return bais.toByteArray();
	    }
		return null;
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo padre)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el array de bytes), <code>null</code> si no se quiere tope
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, String ns, String nombreHijos, Element tope) throws FirmaXMLError {
    	NodeList nodesHijos = null;
    	
		if (ns == null)
			ns = padre.getNamespaceURI();
		
		nodesHijos = padre.getChildNodes();
    	    	
    	if (nodesHijos.getLength() > 0) { 
        	Transforms  t = new Transforms(padre.getOwnerDocument());
        	
        	try {
    			t.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
    		} catch (TransformationException e) {
    			log.error(e);
    			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
    		}
    		
			ByteArrayOutputStream bais = new ByteArrayOutputStream();
			
			for (int i = 0; i < nodesHijos.getLength(); i++) {
				Node nodo = nodesHijos.item(i);
				
				// Busca el siguiente elemento
				if (nodo.getNodeType() != Node.ELEMENT_NODE)
					continue;
				
				// si es el elemento tope para de buscar
				if (tope != null) {
					if (tope.isEqualNode(nodo))
						break;
				}
				
				// comprueba si es un nodo de los buscados
				if (!nodo.getLocalName().equals(nombreHijos))
					continue;
				
				if (ns == null) {
					if (nodo.getNamespaceURI() != null)
						continue;
				} else if (!ns.equals(nodo.getNamespaceURI()))
					continue;
				
				XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodo);
				try {
					XMLSignatureInput resultado = null;
					resultado = t.performTransforms(xmlSignatureInput);
					bais.write(resultado.getBytes());
				} catch (TransformationException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (CanonicalizationException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (IOException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				}
			}
			
			if (bais.size() > 0) 
				return bais.toByteArray();
	    }
		return null;
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param nombreHijos listado de elementos que se buscarán (pareja de namespace y nombre del elemento)
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el array de bytes), <code>null</code> si no se quiere tope
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, ArrayList<NombreNodo> nombreHijos, Element tope) throws FirmaXMLError {
    	NodeList nodesHijos = null;
    	
		nodesHijos = padre.getChildNodes();
    	    	
    	if (nodesHijos.getLength() > 0) { 
        	Transforms  t = new Transforms(padre.getOwnerDocument());
        	
        	try {
    			t.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
    		} catch (TransformationException e) {
    			log.error(e);
    			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
    		}
    		
			ByteArrayOutputStream bais = new ByteArrayOutputStream();
			
			for (int i = 0; i < nodesHijos.getLength(); i++) {
				Node nodo = nodesHijos.item(i);
				
				// Busca el siguiente elemento
				if (nodo.getNodeType() != Node.ELEMENT_NODE)
					continue;
				
				// si es el elemento tope para de buscar
				if (tope != null) {
					if (tope.isEqualNode(nodo))
						break;
				}
				
				// comprueba si es un nodo de los buscados
				NombreNodo nombreNodo = new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName());
				if (nombreHijos.indexOf(nombreNodo) == -1)
					continue;
				
				XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodo);
				try {
					XMLSignatureInput resultado = null;
					resultado = t.performTransforms(xmlSignatureInput);
					bais.write(resultado.getBytes());
				} catch (TransformationException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (CanonicalizationException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (IOException ex) {
					log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
				}
			}
			
			if (bais.size() > 0) 
				return bais.toByteArray();
	    }
		return null;
	}

	/**
	 * Devuelve un listado con los elementos quen siendo hijos del nodo padre tienen el nombre indicado y están antes del elemento tope.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el listado), <code>null</code> si no se quiere tope
	 * @param nombreHijo Namespace y localname de los hijos que se buscarán
	 * @return listado con los elementos encontrados
	 */
	public static ArrayList<Element> obtenerNodos(Element padre, Element tope, NombreNodo nombreHijo) {
		if (padre == null) {
			return null;
		}
		ArrayList<Element> resultado = new ArrayList<Element>();
    	NodeList nodesHijos = padre.getChildNodes();
    	
		for (int i = 0; i < nodesHijos.getLength(); i++) {
			Node nodo = nodesHijos.item(i);
			
			// Busca el siguiente elemento
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				continue;
			
			// si es el elemento tope para de buscar
			if (tope != null) {
				if (tope.isEqualNode(nodo))
					break;
			}
			
			// comprueba si es un nodo de los buscados
			if (new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName()).equals(nombreHijo))
				resultado.add((Element)nodo);
		}
		return resultado;
	}
	
	/**
	 * Devuelve un listado con los elementos quen siendo hijos del nodo padre tienen el nombre indicado y están antes del elemento tope.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el listado), <code>null</code> si no se quiere tope
	 * @param nombreHijos listado de Namespace y localname de los hijos que se buscarán
	 * @return listado con los elementos encontrados
	 * @throws FirmaXMLError 
	 */
	public static ArrayList<Element> obtenerNodos(Element padre, Element tope, ArrayList<NombreNodo> nombreHijos) throws FirmaXMLError {
		ArrayList<Element> resultado = new ArrayList<Element>();
    	NodeList nodesHijos = padre.getChildNodes();
    	
		for (int i = 0; i < nodesHijos.getLength(); i++) {
			Node nodo = nodesHijos.item(i);
			
			// Busca el siguiente elemento
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				continue;
			
			// si es el elemento tope para de buscar
			if (tope != null) {
				if (tope.isEqualNode(nodo))
					break;
			}
			
			// comprueba si es un nodo de los buscados
			if (nombreHijos.indexOf(new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName())) != -1)
				resultado.add((Element)nodo);
		}
		return resultado;
	}
	
	/**
	 * Devuelve un array de bytes con el contenido de los elementos indicados (tras una canonalización estándar).
	 * 
	 * @param nodos listado de elementos
	 * @return array de bytes 
	 */
	public static byte[] obtenerByteNuevo(ArrayList<Element> nodos, CanonicalizationEnum canonicalization) throws FirmaXMLError {
		if ((nodos == null) || (nodos.size() == 0))
			return null;
		
		if ((canonicalization == null) || (canonicalization.equals(CanonicalizationEnum.UNKNOWN)))
			return null;
		
		ByteArrayOutputStream bais = new ByteArrayOutputStream();
		
		Iterator<Element> it = nodos.iterator();
		while (it.hasNext()) {
			Element nodo = it.next();
			try {
				bais.write(obtenerByte(nodo, canonicalization));
			} catch (IOException ex) {
				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
				throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
			}
		}
		
		if (bais.size() > 0) 
			return bais.toByteArray();
		return null;
	}
	
	/**
	 * Devuelve un array de bytes con el contenido del elemento indicado (tras una canonalización estándar).
	 * 
	 * @param nodos listado de elementos
	 * @return array de bytes 
	 */
	public static byte[] obtenerByte(Element nodo, CanonicalizationEnum canonicalization) throws FirmaXMLError {
		if (nodo == null)
			return null;

		if ((canonicalization == null) || (canonicalization.equals(CanonicalizationEnum.UNKNOWN)))
			return null;

		Transforms  t = new Transforms(nodo.getOwnerDocument());

		try {
			t.addTransform(canonicalization.toString());
		} catch (TransformationException e) {
			log.error(e);
			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
		}

		XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodo);
		try {
			XMLSignatureInput resultado = null;
			resultado = t.performTransforms(xmlSignatureInput);
			return resultado.getBytes();
		} catch (TransformationException ex) {
			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
		} catch (CanonicalizationException ex) {
			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
		} catch (IOException ex) {
			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
		}
	}
	
	/**
	 * Devuelve un array de bytes con el contenido de los elementos indicados (tras una canonalización estándar).
	 * 
	 * @param nodos listado de elementos
	 * @return array de bytes 
	 */
	public static byte[] obtenerByte(ArrayList<Element> nodos, CanonicalizationEnum canonicalization) throws FirmaXMLError {
		if ((nodos == null) || (nodos.size() == 0))
			return null;
		
		if ((canonicalization == null) || (canonicalization.equals(CanonicalizationEnum.UNKNOWN)))
			return null;
		
    	Transforms  t = new Transforms(nodos.get(0).getOwnerDocument());
    	
    	try {
			t.addTransform(canonicalization.toString());
		} catch (TransformationException e) {
			log.error(e);
			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
		}
		
		ByteArrayOutputStream bais = new ByteArrayOutputStream();
		
		Iterator<Element> it = nodos.iterator();
		while (it.hasNext()) {
			Element nodo = it.next();
			
			XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodo);
			try {
				XMLSignatureInput resultado = null;
				resultado = t.performTransforms(xmlSignatureInput);
				bais.write(resultado.getBytes());
			} catch (TransformationException ex) {
				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
				throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
			} catch (CanonicalizationException ex) {
				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
				throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
			} catch (IOException ex) {
				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
				throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8));
			}
		}
		
		if (bais.size() > 0) 
			return bais.toByteArray();
		return null;
	}
	
	/**
	 * Obtiene el nombre de un nodo eliminando el namespace si hace falta.
	 * @param node Nodo del que se quiere obtener el nombre
	 * @return Nombre del nodo eliminando el namespace si lo tiene
	 */
	public static String obtenerNombreNodo ( Node node ) {
		String nombreNodoConNS = node.getNodeName();
		int iPosNombreNodo = nombreNodoConNS.lastIndexOf(":")+1;
		String nombreNodo = nombreNodoConNS.substring(iPosNombreNodo);
		return nombreNodo;
	}
	
	
	/**
	 * Devuelve un listado con las ID de los elementos. Si no encuentra un atributo que sea ID, busca entre los atributos alguno que tenga
	 * la <i>forma</i> de ID.
	 * 
	 * @param elementos listado con los elementos de los cuales obtener las IDs
	 * @return
	 */
	public static ArrayList<String> obtenerIDs(ArrayList<Element> elementos) {
		if (elementos == null)
			return null;
		ArrayList<String> resultado = new ArrayList<String>();
		Iterator<Element> it = elementos.iterator();
		while (it.hasNext()) {
			Element elemento = it.next();
			boolean encontrado = false;
			NamedNodeMap map = elemento.getAttributes();
			for (int i = 0; i < map.getLength(); i++) {
				Attr attr = (Attr)map.item(i);
				if (attr.isId()) {
					resultado.add(attr.getValue());
					encontrado = true;
					break;
				}
			}
			if (!encontrado) {
				for (int i = 0; i < IDs.length; i++) {
					if (elemento.hasAttribute(IDs[i])) {
						resultado.add(elemento.getAttribute(IDs[i]));
						break;
					}
				}
			}
		}
		return resultado;
	}
	
	/**
	 * <p>Obtiene la ID del elemento indicado.</p>
	 * @param element elemento del que obtener la id
	 * @return id del elemento, <code>null</code> si no se encuentra el elemento
	 */
	public static String getId(Element element) {
		String id = element.getAttribute(ConstantesXADES.ID);
		if (id == null) {
			NamedNodeMap map = element.getAttributes();
			for (int i = 0; i < map.getLength(); i++) {
				Attr attr = (Attr) map.item(i);
				if (attr.isId()) {
					id = attr.getValue();
					break;
				}
			}		
		}
		return id;
	}
	
	/**
	 * Busca en una lista de nodos un elemento que tenga un atributo con nombre <b>Id</b> con el valor especificado
	 *  
	 * @param Valor del atributo id del elemento a buscar
	 * @return Elemento que contiene un atributo Id con ese id o <code>null</code> si no lo encuentra
	 */
	public static Element getElementById(NodeList list, String id) {
		Element resultado = null;
		if (list != null) {
			int length = list.getLength();
			for (int i = 0; i < length; i++) {
				Node node = list.item(i);
				// AppPerfect: Falso positivo
				if (node.getNodeType() == Node.ELEMENT_NODE) {
					Element el = (Element) node;
					if (id.equals(el.getAttribute(ConstantesXADES.ID))) {
						resultado = el;
						break;
					}
				}
			}
		}
		return resultado;
	}
	
	/**
	 * Explora el elemento y sus hijos para obtener un elemento que tenga la Id indicada
	 * 
	 * @param el Elemento desde el que buscar
	 * @param id Valor del atributo id del elemento a buscar
	 * @return Elemento que contiene un atributo Id con ese id o <code>null</code> si no lo encuentra
	 */
	private static Element exploreElementById(Element el, String id) {
		if (el != null) {
			for (int i = 0; i < IDs.length; i++) {
				if (id.equals(el.getAttribute(IDs[i]))) {
					return el; 
				}
			}
			// explora los hijos del nodo
			NodeList nodes = el.getChildNodes();
			for (int i = 0; i < nodes.getLength(); i++) {
				Node nodo = nodes.item(i);
				if (nodo.getNodeType() == Node.ELEMENT_NODE) {
					Element temp = exploreElementById((Element)nodo, id);
					if (temp != null)
						return temp;
				}
			}
		}
		return null;
	}
	
	/**
	 * Busca un nodo que tenga la Id indicada. Busca la id en cualquier atributo que tenga la forma Id, ID, ó id.
	 * 
	 * @param doc Documento en el que buscar
	 * @param id Valor del atributo id del elemento a buscar
	 * @return el elemento con la id indicada, <code>null</code> si no hay ningún elemento con esa id.
	 */
	public static Element getElementById(Document doc, String id) {
		if ((doc == null) || (id == null)) {
			return null;
		}
		// Si es id = "" lo toma como el nodo raíz
		if (id.length() == 0) {
			return doc.getDocumentElement();
		}
		id = (id != null) ? ((id.startsWith("#")) ? ((id.startsWith(XPOINTER_ID)) ?  id.substring(XPOINTER_ID.length(), id.length() - 2) : id.substring(1)) : id) : null;
		Element el = doc.getElementById(id);
		if (el == null) {
			el = exploreElementById(doc.getDocumentElement(), id);
		}
		return el;
	}

	/**
	 * Busca un nodo que tenga la Id indicada que sea hijo del nodo indicado. Busca la id en cualquier atributo que tenga la forma Id, ID, ó id.
	 * 
	 * @param padre Elemento a partir del cual buscar
	 * @param id Valor del atributo a buscar en cualquier atributo
	 * @return el elemento con la id indicada, <code>null</code> si no hay ningún elemento con esa id.
	 */
	public static Element getElementById(Element padre, String id) {
		Element el = getElementById(padre.getOwnerDocument(), id);
		// Comprueba que el nodo encontrado es hijo
		if (el != null) {
			Node temp = el;
			while ((temp != null) && (!temp.isSameNode(padre)))
				temp = temp.getParentNode();
			if (temp != null)
				return el;
		}
		return null;
	}
	
	/**
	 * <p>Comprueba si el nodo hijo indicado es hijo del nodo padre indicado.</p>
	 * @param child Elemento hijo
	 * @param parent Elemento que se comprueba si es el padre
	 * @return <code>true</code> si el hijo es hijo del padre 
	 */
	public static boolean isChildNode(Element child, Element parent) {
		Node temp = child;
		while ((temp != null) && (!temp.isSameNode(parent))) {
			temp = temp.getParentNode();
		}
		return (temp != null);
	}

	/**
	 * <p>Comprueba si el nodo hijo indicado no es hijo de un nodo padre que se ajuste al tipo de nodo indicado.</p>
	 * @param child Elemento hijo
	 * @param parent Tipo de elemento que se comprueba si es el padre
	 * @param top Tope de elemento padre del que no se pasará buscando padres
	 * @return <code>true</code> si el hijo es hijo del padre 
	 */
	public static boolean isChildNode(Element child, NombreNodo parent, Element top) {
		Node temp = child;
		while ((temp != null) && (!temp.isSameNode(top))) {
			if (parent.equals(temp)) {
				break;
			}
			temp = temp.getParentNode();
		}
		return parent.equals(temp);
	}

	/**
	 * Genera una nueva ID que no esté siendo usada en el documento
	 * 
	 * @param doc
	 * @param prefix
	 * @return
	 */
	public static String newID(Document doc, String prefix) {
		String newID = prefix + rnd.nextInt(RND_MAX_SIZE);
		while (getElementById(doc, newID) != null)
			newID = prefix + rnd.nextInt(RND_MAX_SIZE);
		return newID;
	}
	
	/**
	 * Método para obtener el primer nodo de tipo Element hijo del nodo dado. En la búsqueda se
	 * excluyen los nodos de texto "vacíos" (con caracteres de retorno de carro o espacios), los
	 * nodos Attribute y los nodos de comentario
	 * 
	 * @param Element .- Nodo padre en el que buscar el primer hijo de tipo Element
	 */
	public static Element getFirstElementChild(Node node, boolean strict) {
		Node nodeTemp = node.getFirstChild();
		
		while ((nodeTemp != null) && (nodeTemp.getNodeType() != Node.ELEMENT_NODE)) {
			if (strict) {
				if (nodeTemp.getNodeType() == Node.TEXT_NODE) {
					String text = nodeTemp.getNodeValue().trim();
					text = text.replaceAll("/n", ConstantesXADES.CADENA_VACIA);
					text = text.replaceAll("/r", ConstantesXADES.CADENA_VACIA);
					text = text.replaceAll(ConstantesXADES.ESPACIO, ConstantesXADES.CADENA_VACIA);		
					if (!text.equals(ConstantesXADES.CADENA_VACIA))
						return null;
				}
			}
			nodeTemp = nodeTemp.getNextSibling();
		}
		return (Element)nodeTemp;
	}
	
	/**
	 * Método para obtener el primer nodo de tipo Element vecino del nodo dado. En la búsqueda se
	 * excluyen nodos de texto "vacíos" (con caracteres de retorno de carro o espacios), los
	 * nodos Attribute y los nodos de comentario
	 * 
	 * @param Element .- Nodo en el que buscar su primer vecino de tipo Element
	 */
	public static Element getNextElementSibling(Node node, boolean strict) {
		Node nodeTemp = node.getNextSibling();
		
		while ((nodeTemp != null) && (nodeTemp.getNodeType() != Node.ELEMENT_NODE)) {
			if (strict) {
				if (nodeTemp.getNodeType() == Node.TEXT_NODE) {
					String text = nodeTemp.getNodeValue().trim();
					text = text.replaceAll("/n", ConstantesXADES.CADENA_VACIA);
					text = text.replaceAll("/r", ConstantesXADES.CADENA_VACIA);
					text = text.replaceAll(ConstantesXADES.ESPACIO, ConstantesXADES.CADENA_VACIA);		
					if (!text.equals(ConstantesXADES.CADENA_VACIA))
						return null;
				}
			}
			nodeTemp = nodeTemp.getNextSibling();
		}
		return (Element)nodeTemp;
	}
	
	/**
	 * Obtiene todos los hijos de tipo Element de un determinado nodo
	 * @param nodo
	 * @return
	 */
	public static ArrayList<Element> getElementChildNodes (Element nodo, boolean strict) {
		
		ArrayList<Element> retorno = new ArrayList<Element>();
		
		Element hijo = getFirstElementChild(nodo, strict);
		int tope = nodo.getChildNodes().getLength();
		
		for (int i = 0; i < tope; ++i) {
			if (hijo == null)
				break;
			retorno.add(hijo);
			hijo = getNextElementSibling(hijo, strict);
		}
		
		return retorno;
	}

	/**
	 * Devuelve un listado con los elementos quen siendo hijos del nodo padre tienen el nombre indicado y están dentro del
	 * límite establecido por tope.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos, nietos, bisnietos, etc... según el nivel de profundidad
	 * @param tope int Numero de niveles de profundidad para la búsqueda mínimo 1 y máximo 5.
	 * @param nombreHijos Namespace y localname de los hijos que se buscarán
	 * @return listado con los elementos encontrados
	 * @throws FirmaXMLError 
	 */
/*	public static ArrayList<Element> obtenerNodos(Element padre, int tope, NombreNodo nombreHijos) throws FirmaXMLError {
		// TODO: corregir
		ArrayList<Element> resultado = new ArrayList<Element>();
    	NodeList nodesHijos = padre.getChildNodes();
    	
    	if (tope < 1)
    		tope = 1;
    	
    	for (int i = 0; i < nodesHijos.getLength(); i++) {
    		Node nodo = nodesHijos.item(i);

    		// Busca el siguiente elemento (Se excluyen los demás tipos de nodo)
    		if (nodo.getNodeType() != Node.ELEMENT_NODE)
    			continue;
    		
    		// comprueba si es un nodo de los buscados
    		if (nombreHijos.equals(new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName())))
    			resultado.add((Element)nodo);
    		
    		if (tope > 1) { // Si se debe buscar en el segundo nivel
    			NodeList nodosHijos2 = nodo.getChildNodes();
    			for (int j = 0; j < nodosHijos2.getLength(); j++) {
    				Node nodo2 = nodosHijos2.item(j);

    				// Busca el siguiente elemento
    				if (nodo2.getNodeType() != Node.ELEMENT_NODE)
    					continue;

    				// comprueba si es un nodo de los buscados
    				if (nombreHijos.equals(new NombreNodo(nodo2.getNamespaceURI(), nodo2.getLocalName())))
    					resultado.add((Element)nodo2);
    				
    				if (tope > 2) { // Si se debe buscar en el tercer nivel
            			NodeList nodosHijos3 = nodo2.getChildNodes();
            			for (int k = 0; k < nodosHijos3.getLength(); k++) {
            				Node nodo3 = nodosHijos3.item(k);

            				// Busca el siguiente elemento
            				if (nodo3.getNodeType() != Node.ELEMENT_NODE)
            					continue;

            				// comprueba si es un nodo de los buscados
            				if (nombreHijos.equals(new NombreNodo(nodo3.getNamespaceURI(), nodo3.getLocalName())))
            					resultado.add((Element)nodo3);
            				
            				if (tope > 3) { // Si se debe buscar en el cuarto nivel
                    			NodeList nodosHijos4 = nodo3.getChildNodes();
                    			for (int l = 0; l < nodosHijos4.getLength(); l++) {
                    				Node nodo4 = nodosHijos4.item(l);

                    				// Busca el siguiente elemento
                    				if (nodo4.getNodeType() != Node.ELEMENT_NODE)
                    					continue;

                    				// comprueba si es un nodo de los buscados
                    				if (nombreHijos.equals(new NombreNodo(nodo4.getNamespaceURI(), nodo4.getLocalName())))
                    					resultado.add((Element)nodo4);
                    				
                    				if (tope > 4) { // Si se debe buscar en el quinto nivel
                            			NodeList nodosHijos5 = nodo4.getChildNodes();
                            			for (int m = 0; m < nodosHijos5.getLength(); m++) {
                            				Node nodo5 = nodosHijos5.item(m);

                            				// Busca el siguiente elemento
                            				if (nodo5.getNodeType() != Node.ELEMENT_NODE)
                            					continue;

                            				// comprueba si es un nodo de los buscados
                            				if (nombreHijos.equals(new NombreNodo(nodo5.getNamespaceURI(), nodo5.getLocalName())))
                            					resultado.add((Element)nodo5);
                            			}
                            		}
                    			}
                    		}
            			}
            		}
    			}
    		}
    	}
    	
		return resultado;
	}
*/
	   /**
     * Devuelve un listado con los elementos quen siendo hijos del nodo padre tienen el nombre indicado y están dentro del
     * límite establecido por tope.
     * 
     * @param padre nodo padre del que se buscarán los hijos, nietos, bisnietos, etc... según el nivel de profundidad
     * @param tope int Numero de niveles de profundidad para la búsqueda mínimo 1 y máximo 5.
     * @param nombreHijos Namespace y localname de los hijos que se buscarán
     * @return listado con los elementos encontrados
     * @throws FirmaXMLError 
     */
    public static ArrayList<Element> obtenerNodos(Element padre, int tope, NombreNodo nombreHijos) throws FirmaXMLError {
        // TODO: corregir
        ArrayList<Element> resultado = new ArrayList<Element>();
        NodeList nodesHijos = padre.getChildNodes();
        
        if (tope < 1)
            tope = 1;
        
        for (int i = 0; i < nodesHijos.getLength(); i++) {
            Node nodo = nodesHijos.item(i);

            // Busca el siguiente elemento (Se excluyen los demás tipos de nodo)
            if (nodo.getNodeType() != Node.ELEMENT_NODE)
                continue;
            
            // comprueba si es un nodo de los buscados
            if (nombreHijos.equals(new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName())))
                resultado.add((Element)nodo);
            
            if (tope > 1) { // Si se debe buscar en el segundo nivel
                ArrayList<Element> hijos = obtenerNodos((Element)nodo, tope-1, nombreHijos);
                if(hijos.size()>0) {
                    resultado.addAll(hijos);
                }
            }
/*                
                
                
                
                
                NodeList nodosHijos2 = nodo.getChildNodes();
                for (int j = 0; j < nodosHijos2.getLength(); j++) {
                    Node nodo2 = nodosHijos2.item(j);

                    // Busca el siguiente elemento
                    if (nodo2.getNodeType() != Node.ELEMENT_NODE)
                        continue;

                    // comprueba si es un nodo de los buscados
                    if (nombreHijos.equals(new NombreNodo(nodo2.getNamespaceURI(), nodo2.getLocalName())))
                        resultado.add((Element)nodo2);
                    
                    if (tope > 2) { // Si se debe buscar en el tercer nivel
                        NodeList nodosHijos3 = nodo2.getChildNodes();
                        for (int k = 0; k < nodosHijos3.getLength(); k++) {
                            Node nodo3 = nodosHijos3.item(k);

                            // Busca el siguiente elemento
                            if (nodo3.getNodeType() != Node.ELEMENT_NODE)
                                continue;

                            // comprueba si es un nodo de los buscados
                            if (nombreHijos.equals(new NombreNodo(nodo3.getNamespaceURI(), nodo3.getLocalName())))
                                resultado.add((Element)nodo3);
                            
                            if (tope > 3) { // Si se debe buscar en el cuarto nivel
                                NodeList nodosHijos4 = nodo3.getChildNodes();
                                for (int l = 0; l < nodosHijos4.getLength(); l++) {
                                    Node nodo4 = nodosHijos4.item(l);

                                    // Busca el siguiente elemento
                                    if (nodo4.getNodeType() != Node.ELEMENT_NODE)
                                        continue;

                                    // comprueba si es un nodo de los buscados
                                    if (nombreHijos.equals(new NombreNodo(nodo4.getNamespaceURI(), nodo4.getLocalName())))
                                        resultado.add((Element)nodo4);
                                    
                                    if (tope > 4) { // Si se debe buscar en el quinto nivel
                                        NodeList nodosHijos5 = nodo4.getChildNodes();
                                        for (int m = 0; m < nodosHijos5.getLength(); m++) {
                                            Node nodo5 = nodosHijos5.item(m);

                                            // Busca el siguiente elemento
                                            if (nodo5.getNodeType() != Node.ELEMENT_NODE)
                                                continue;

                                            // comprueba si es un nodo de los buscados
                                            if (nombreHijos.equals(new NombreNodo(nodo5.getNamespaceURI(), nodo5.getLocalName())))
                                                resultado.add((Element)nodo5);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }*/
        }
        
        return resultado;
    }

	/**
	 * Devuelve un listado con los elementos quen siendo hijos del nodo padre tienen el nombre indicado y están dentro del
	 * límite establecido por tope.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos, nietos, bisnietos, etc... según el nivel de profundidad
	 * @param tope int Numero de niveles de profundidad para la búsqueda mínimo 1 y máximo 5.
	 * @param nombreHijos localname de los hijos que se buscarán
	 * @return listado con los elementos encontrados
	 * @throws FirmaXMLError 
	 */
	public static ArrayList<Element> obtenerNodos(Element padre, int tope, String nombreHijos) throws FirmaXMLError {
		// TODO: corregir
		ArrayList<Element> resultado = new ArrayList<Element>();
    	NodeList nodesHijos = padre.getChildNodes();
    	
    	if (tope < 1)
    		tope = 1;
    	
    	for (int i = 0; i < nodesHijos.getLength(); i++) {
    		Node nodo = nodesHijos.item(i);

    		// Busca el siguiente elemento (Se excluyen los demás tipos de nodo)
    		if (nodo.getNodeType() != Node.ELEMENT_NODE)
    			continue;
    		
    		// comprueba si es un nodo de los buscados
    		if (nombreHijos.equals(nodo.getLocalName()))
    			resultado.add((Element)nodo);
    		
    		if (tope > 1) { // Si se debe buscar en el segundo nivel
    			NodeList nodosHijos2 = nodo.getChildNodes();
    			for (int j = 0; j < nodosHijos2.getLength(); j++) {
    				Node nodo2 = nodosHijos2.item(j);

    				// Busca el siguiente elemento
    				if (nodo2.getNodeType() != Node.ELEMENT_NODE)
    					continue;

    				// comprueba si es un nodo de los buscados
    				if (nombreHijos.equals(nodo2.getLocalName()))
    					resultado.add((Element)nodo2);
    				
    				if (tope > 2) { // Si se debe buscar en el tercer nivel
            			NodeList nodosHijos3 = nodo2.getChildNodes();
            			for (int k = 0; k < nodosHijos3.getLength(); k++) {
            				Node nodo3 = nodosHijos3.item(k);

            				// Busca el siguiente elemento
            				if (nodo3.getNodeType() != Node.ELEMENT_NODE)
            					continue;

            				// comprueba si es un nodo de los buscados
            				if (nombreHijos.equals(nodo3.getLocalName()))
            					resultado.add((Element)nodo3);
            				
            				if (tope > 3) { // Si se debe buscar en el cuarto nivel
                    			NodeList nodosHijos4 = nodo3.getChildNodes();
                    			for (int l = 0; l < nodosHijos4.getLength(); l++) {
                    				Node nodo4 = nodosHijos4.item(l);

                    				// Busca el siguiente elemento
                    				if (nodo4.getNodeType() != Node.ELEMENT_NODE)
                    					continue;

                    				// comprueba si es un nodo de los buscados
                    				if (nombreHijos.equals(nodo4.getLocalName()))
                    					resultado.add((Element)nodo4);
                    				
                    				if (tope > 4) { // Si se debe buscar en el quinto nivel
                            			NodeList nodosHijos5 = nodo4.getChildNodes();
                            			for (int m = 0; m < nodosHijos5.getLength(); m++) {
                            				Node nodo5 = nodosHijos5.item(m);

                            				// Busca el siguiente elemento
                            				if (nodo5.getNodeType() != Node.ELEMENT_NODE)
                            					continue;

                            				// comprueba si es un nodo de los buscados
                            				if (nombreHijos.equals(nodo5.getLocalName()))
                            					resultado.add((Element)nodo5);
                            			}
                            		}
                    			}
                    		}
            			}
            		}
    			}
    		}
    	}
    	
		return resultado;
	}

    /**
     * <p>
     * Escribe el documento a un flujo de salida. Este método es la exposición
     * pública de un método de la libreria XMLSec de Apache. Este método no
     * añade el preámbulo de XML
     * </p>
     * 
     * @param document
     *            El documento a salvar
     * @param outputStream
     *            El flujo de salida path del fichero donde se quiere escribir.
     */
    public static void saveDocumentToOutputStream(Document document, OutputStream outputStream) {
        //adsi.org.apache.xml.security.utils.XMLUtils.outputDOM(document, outputStream);
		UtilidadFicheros.writeXML(document, outputStream);
    }

    /**
     * <p>
     * Escribe el documento a un flujo de salida. Este método es la exposición
     * pública de un método de la libreria XMLSec de Apache.
     * </p>
     * 
     * @param document
     *            El documento a salvar
     * @param outputStream
     *            El flujo de salida path del fichero donde se quiere escribir.
     * @param addPreamble
     *            Si se desea añadir el preámbulo de XML.
     */
    public static void saveDocumentToOutputStream(Document document, OutputStream outputStream, boolean addPreamble) {
        //adsi.org.apache.xml.security.utils.XMLUtils.outputDOM(document, outputStream, addPreamble);
		UtilidadFicheros.writeXML(document, outputStream);
    }

    
}
