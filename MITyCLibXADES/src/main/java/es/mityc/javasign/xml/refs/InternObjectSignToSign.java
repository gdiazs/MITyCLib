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
package es.mityc.javasign.xml.refs;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import adsi.org.apache.xml.security.signature.ObjectContainer;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;

/**
 * Representa un objeto que se quiere añadir como un objeto (ds:object) de la firma.
 */
public class InternObjectSignToSign extends AbstractObjectToSign {

	private String encoding;
	private String mimeType;
    private Element data;
	/** Identidad del objeto interno a firmar. */
	private String id = null;
	
	public InternObjectSignToSign() {
	}
	
	public InternObjectSignToSign(String encoding, String mimeType) {
		this.encoding = encoding;
		this.mimeType = mimeType;
	}
	
	public void setData(Element data) {
		this.data = data;
	}
	
	public Element getData() {
		return data;
	}

	/**
	 * @return the encoding
	 */
	public String getEncoding() {
		return encoding;
	}

	/**
	 * @return the mimeType
	 */
	public String getMimeType() {
		return mimeType;
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getReferenceURI()
	 */
	@Override
	public String getReferenceURI() {
		return id;
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getObjects(org.w3c.dom.Document)
	 */
	@Override
	public List<ObjectContainer> getObjects(Document doc) {
		List<ObjectContainer> list = super.getObjects(doc);

		ObjectContainer container = new ObjectContainer(doc);
		// Es muy importante añadir el nodo antes de generar el nuevo Id para evitar colisiones (ids repetidos)
        container.appendChild(doc.adoptNode(getData().cloneNode(true)));

        id = UtilidadTratarNodo.newID(doc, "Object-ID-");
		container.setId(id);
		if (getEncoding() != null) {
			container.setEncoding(getEncoding());
		}
		if (getMimeType() != null) {
			container.setMimeType(getMimeType());
		}
		id = ConstantesXADES.ALMOHADILLA + id;

		list.add(container);
		return list;
	}

}
