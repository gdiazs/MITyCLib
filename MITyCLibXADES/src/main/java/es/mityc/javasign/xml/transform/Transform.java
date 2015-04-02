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
package es.mityc.javasign.xml.transform;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * <p>Guarda información sobre una transformada que se va a aplicar a un objeto a firmar.</p>
 * 
 */
public class Transform {
	
	/** Algoritmo de la transformada. */
	private String algorithm;
	/** Generador de la información extra de la transformada. */
	private ITransformData data;
	
	/**
	 * <p>Construye una transformada general con el algoritmo indicado.</p>
	 * @param alg Algoritmo de la transformada
	 * @param extraData Generador de los nodos de información extra, <code>null</code> si no hay información extra para la transformada
	 */
	public Transform(String alg, ITransformData extraData) {
		this.algorithm = alg;
		this.data = extraData;
	}
	
	/**
	 * <p>Establece el generador de los nodos de información extra.</p>
	 * @param extraData
	 */
	protected void setTransformData(ITransformData extraData) {
		this.data = extraData;
	}
	
	/**
	 * <p>Devuelve el algoritmo de la transformada.</p>
	 * @return the algorithm
	 */
	public String getAlgorithm() {
		return algorithm;
	}
	
	/**
	 * <p>Devuelve el listado de nodos de información extra que necesita la transformada.</p>
	 * @param doc Documento en el que irá la transformada
	 * @return listado de nodos
	 */
	public NodeList getExtraData(Document doc) {
		NodeList nl = null; 
		if (data != null) {
			nl = data.getExtraData(doc);
		}
		return nl;
	}
	
}
