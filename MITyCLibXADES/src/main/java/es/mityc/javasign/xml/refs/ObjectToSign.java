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

import java.net.URI;

import es.mityc.firmaJava.libreria.xades.elementos.xades.ObjectIdentifier;

/**
 * Contiene un objeto que se firmará e información de apoyo.
 */
public class ObjectToSign {
	
	private AbstractObjectToSign objectToSign;
	private String id;
	
	// Información adicional
	private String description = null;
	private ObjectIdentifier objectIdentifier = null;
	private ExtraObjectData extraData = null;
	
	/**
	 * Permite pasar un objeto a firmar, junto con la información sobre dicho objeto a firmar.
	 * 
	 * @param objectToSign .- Objeto a firmar
	 * @param desc .- Descripción del objeto a firmar
	 * @param id .- Objecto identificador del objeto descrito
	 * @param mimeType .- Tipo MIME del objeto descrito
	 * @param encoding .- Codificación en la firma del objeto descrito
	 */
	public ObjectToSign(AbstractObjectToSign objectToSign, String desc, ObjectIdentifier id,
			String mimeType, URI encoding) {
		this.objectToSign = objectToSign;
		this.description = desc;
		this.objectIdentifier = id;
		this.extraData = new ExtraObjectData(mimeType, encoding);
	}
	
	public void setObjectToSign(AbstractObjectToSign objectToSign) {
		this.objectToSign = objectToSign;
	}
	
	public AbstractObjectToSign getObjectToSign() {
		return this.objectToSign;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String descripcion) {
		this.description = descripcion;
	}

	public ObjectIdentifier getObjectIdentifier() {
		return objectIdentifier;
	}

	public void setObjectIdentifier(ObjectIdentifier identificador) {
		this.objectIdentifier = identificador;
	}

	public String getMimeType() {
		return extraData.getMimeType();
	}

	public URI getEncoding() {
		return extraData.getEncoding();
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}
	
}
