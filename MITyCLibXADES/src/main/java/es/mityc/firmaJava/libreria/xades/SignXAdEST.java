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
package es.mityc.firmaJava.libreria.xades;

import java.util.ArrayList;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import adsi.org.apache.xml.security.Init;
import adsi.org.apache.xml.security.transforms.Transforms;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.excepciones.AddXadesException;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.utilidades.I18n;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;

/**
 * <p>Clase para gestionar los selos de tiempo XAdES-T en la firma.</p>
 */
public class SignXAdEST {
	
	/**
	 * <p>Obtiene la información de una firma XAdES que debe ir en un sello para ser tipo T.</p>
	 * @param sign Firma en la que se quiere obtener el sello T
	 * @return array de bytes con la información que debe ser sellada
	 * @throws AddXadesException Lanzada si no se puede obtener la información
	 */
	public static byte[] getDataToStamp(Element sign)throws AddXadesException {
		Init.init();
		try {
			return UtilidadTratarNodo.obtenerByteNodo(sign, ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.SIGNATURE_VALUE, CanonicalizationEnum.C14N_OMIT_COMMENTS, 5);
		} catch (FirmaXMLError ex) {
			throw new AddXadesException("Error procesando información a sellar: " + ex.getMessage(), ex);
		}
	}
	
	/**
	 * <p>Incluye un sello de tiempo en una firma.</p>
	 * <p>Este método no tiene en cuenta la validez de la firma para incluir el sello, pero supone que existe al menos una XAdES-BES válida.</p>
	 * @param sign firma a la que añadir el sello de tiempo
	 * @param ts sello de tiempo que se quiere aplicar
	 * @throws AddXadesException Lanzada cuando hay un error a la hora de incluir el sello de tiempo 
	 */
	public static void addXAdEST(Element sign, byte[] ts) throws AddXadesException {
		Init.init();
		try {
	    	// Busca namespaces e IDs necesarias para insertar nodos
	        Document doc = sign.getOwnerDocument();
	    	Element qualifying = null;
	    	ArrayList<Element> qualifyings = UtilidadTratarNodo.obtenerNodos(sign, 2, new NombreNodo("*", ConstantesXADES.QUALIFYING_PROPERTIES));
	    	if ((qualifyings == null) || (qualifyings.size() != 1)) {
	    		throw new AddXadesException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_18));
	    	}
	    	qualifying = qualifyings.get(0);
	    	String xadesSchema = qualifying.getNamespaceURI();
	    	String xadesNS = qualifying.getPrefix();
	    	String xmldsigNS = sign.getPrefix();
	    	String firmaID = UtilidadTratarNodo.getId(sign);
	    	ArrayList<Element> signaturesValue = UtilidadTratarNodo.obtenerNodos(sign, 1, new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.SIGNATURE_VALUE));
	    	if ((signaturesValue == null) || (signaturesValue.size() != 1)) {
	    		throw new AddXadesException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_18));
	    	}
	    	String idSignatureValue = UtilidadTratarNodo.getId(signaturesValue.get(0));
	
	    	// Crea los elementos de propiedades no firmadas si no existen
	    	Element propiedadesElementosNoFirmados = null;
	    	ArrayList<Element> unsignedsProps = UtilidadTratarNodo.obtenerNodos(qualifying, 1, new NombreNodo(xadesSchema, ConstantesXADES.UNSIGNED_PROPERTIES));
	    	if ((unsignedsProps == null) || (unsignedsProps.size() == 0)) {
	    		propiedadesElementosNoFirmados = doc.createElementNS(xadesSchema, xadesNS + ConstantesXADES.DOS_PUNTOS + ConstantesXADES.UNSIGNED_PROPERTIES);
		    	Attr propiedadesNoFirmadasId = doc.createAttributeNS(null, ConstantesXADES.ID);
		    	propiedadesNoFirmadasId.setValue(UtilidadTratarNodo.newID(doc, 
		    			firmaID  + ConstantesXADES.GUION_UNSIGNED_PROPERTIES));
		    	NamedNodeMap atributosSinFirmarPropiedadesElemento =
		    		propiedadesElementosNoFirmados.getAttributes();
		    	atributosSinFirmarPropiedadesElemento.setNamedItem(propiedadesNoFirmadasId);
		    	qualifying.appendChild(propiedadesElementosNoFirmados);
	    	} else {
	    		propiedadesElementosNoFirmados = unsignedsProps.get(0);
	    	}
	    	
	    	Element propiedadesSinFirmarFirmaElementos = null;
	    	ArrayList<Element> unsignedsSigsProps = UtilidadTratarNodo.obtenerNodos(propiedadesElementosNoFirmados, 1, new NombreNodo(xadesSchema, ConstantesXADES.UNSIGNED_SIGNATURE_PROPERTIES));
	    	if ((unsignedsSigsProps == null) || (unsignedsSigsProps.size() == 0)) {
	    		propiedadesSinFirmarFirmaElementos = doc.createElementNS(xadesSchema, xadesNS + ConstantesXADES.DOS_PUNTOS + ConstantesXADES.UNSIGNED_SIGNATURE_PROPERTIES);
	    		propiedadesElementosNoFirmados.appendChild(propiedadesSinFirmarFirmaElementos);
	    	} else {
	    		propiedadesSinFirmarFirmaElementos = unsignedsSigsProps.get(0);
	    	}
	    	
	    	
	    	// Se crea el nodo de sello de tiempo
	    	Element tiempoSelloElementoFirma =
	    		doc.createElementNS(xadesSchema, xadesNS + ConstantesXADES.DOS_PUNTOS + ConstantesXADES.SIGNATURE_TIME_STAMP);
		
	    	// Se escribe una Id única
	    	Attr informacionElementoSigTimeStamp = doc.createAttributeNS(null, ConstantesXADES.ID);
	    	String idSelloTiempo = UtilidadTratarNodo.newID(doc, ConstantesXADES.SELLO_TIEMPO);
	    	informacionElementoSigTimeStamp.setValue(idSelloTiempo);
	    	tiempoSelloElementoFirma.getAttributes().setNamedItem(informacionElementoSigTimeStamp);
	
	    	// Se incluye un nodo que referencia a la Id de SignatureValue
	    	if (ConstantesXADES.SCHEMA_XADES_111.equals(xadesSchema) 
	    			|| ConstantesXADES.SCHEMA_XADES_122.equals(xadesSchema)) {
	    		
	    		String nombreNodoUri = null;
	    		String tipoUri = null;
	    		if (ConstantesXADES.SCHEMA_XADES_111.equals(xadesSchema)) {
	    			nombreNodoUri = ConstantesXADES.HASH_DATA_INFO;
	    			tipoUri = ConstantesXADES.URI_MINUS;
	    		} else {
	    			nombreNodoUri = ConstantesXADES.INCLUDE;
	    			tipoUri = ConstantesXADES.URI_MAYUS;
	    		}
	    		
	        	Element informacionElementoHashDatos = doc.createElementNS(xadesSchema, xadesNS + ConstantesXADES.DOS_PUNTOS + nombreNodoUri);
	    		
	    		Attr informacionElementoHashDatosUri = doc.createAttributeNS(null, tipoUri);
	    		informacionElementoHashDatosUri.setValue(ConstantesXADES.ALMOHADILLA + idSignatureValue);
	
	    		NamedNodeMap informacionAtributosElementoHashDatos = informacionElementoHashDatos.getAttributes();
	    		informacionAtributosElementoHashDatos.setNamedItem(informacionElementoHashDatosUri);
	
	    		tiempoSelloElementoFirma.appendChild(informacionElementoHashDatos) ;
	    	}
	    	
	    	// Se crea el nodo canonicalizationMethod en los esquemas 1.2.2 y 1.3.2
	    	if (!ConstantesXADES.SCHEMA_XADES_111.equals(xadesSchema)) {
	    		Element canonicalizationElemento = doc.createElementNS(ConstantesXADES.SCHEMA_DSIG, xmldsigNS + ConstantesXADES.DOS_PUNTOS + ConstantesXADES.CANONICALIZATION_METHOD);		
	    		Attr canonicalizationAttribute = doc.createAttributeNS(null, ConstantesXADES.ALGORITHM);
	    		canonicalizationAttribute.setValue(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
	    		canonicalizationElemento.getAttributes().setNamedItem(canonicalizationAttribute);
	
	    		tiempoSelloElementoFirma.appendChild(canonicalizationElemento);
	    	}
			
			// Se crea el nodo del sello de tiempo
			Element tiempoSelloEncapsulado =
	    		doc.createElementNS(xadesSchema, xadesNS + ConstantesXADES.DOS_PUNTOS + ConstantesXADES.ENCAPSULATED_TIME_STAMP);
	
	    	tiempoSelloEncapsulado.appendChild(
	    			doc.createTextNode(new String(Base64Coder.encode(ts))));
	    	Attr tiempoSelloEncapsuladoId = doc.createAttributeNS(null, ConstantesXADES.ID);
	    	String idEncapsulated = UtilidadTratarNodo.newID(doc, ConstantesXADES.SELLO_TIEMPO_TOKEN);
	    	tiempoSelloEncapsuladoId.setValue(idEncapsulated);
	    	tiempoSelloEncapsulado.getAttributes().setNamedItem(tiempoSelloEncapsuladoId);
	    	
	    	
	    	tiempoSelloElementoFirma.appendChild(tiempoSelloEncapsulado);
	
	    	propiedadesSinFirmarFirmaElementos.appendChild(tiempoSelloElementoFirma);
		} catch (FirmaXMLError ex) {
			throw new AddXadesException("Error incrustando sello de tiempo en firma XAdES: " + ex.getMessage(), ex);
		}
	}

}
