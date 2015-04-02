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
package es.mityc.javasign.xml.xades;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;

import adsi.org.apache.xml.security.c14n.CanonicalizationException;
import adsi.org.apache.xml.security.exceptions.XMLSecurityException;
import adsi.org.apache.xml.security.signature.Reference;
import adsi.org.apache.xml.security.signature.XMLSignatureException;
import adsi.org.apache.xml.security.signature.XMLSignatureInput;
import adsi.org.apache.xml.security.transforms.InvalidTransformException;
import adsi.org.apache.xml.security.transforms.TransformationException;
import adsi.org.apache.xml.security.transforms.Transforms;

/**
 * <p>Clase proxy para trabajar con un elemento Reference de XMLSec.</p>
 */
public class ReferenceProxy {
	
	/** Guarda la referencia a la instancia Reference. */
	private Reference reference;
	
	/**
	 * <p>Construye una instancia proxy a un Reference.</p>
	 * @param ref referencia
	 */
	public ReferenceProxy(Reference ref) {
		this.reference = ref;
	}
	
	/**
	 * <p>Devuelve la Id del nodo Reference.</p>
	 * @return id
	 */
	public String getID() {
		return reference.getId();
	}
	
	/**
	 * <p>Devuelve la URI señalada por la Reference.</p>
	 * @return URI
	 */
	public String getURI() {
		return reference.getURI();
	}
	
	/**
	 * <p>Devuelve un listado de las transformadas aplicadas al nodo.</p>
	 * @return
	 */
	public List<TransformProxy> getTransforms() {
		ArrayList<TransformProxy> proxys = new ArrayList<TransformProxy>();
		Transforms trans = null;
		try {
			trans = reference.getTransforms();
		} catch (XMLSignatureException ex) {
		} catch (InvalidTransformException ex) {
		} catch (TransformationException ex) {
		} catch (XMLSecurityException ex) {
		}
		if (trans != null) {
			for (int i = 0; i < trans.getLength(); i++) {
				try {
					proxys.add(new TransformProxy(trans.item(i)));
				} catch (TransformationException ex) {
				}
			}
		}
		return proxys;
	}
	
	/**
	 * <p>Devuelve la información en binario del contenido indicado en la referencia.</p>
	 * @return byte[] con los datos, <code>null</code> si se produce un error en el acceso
	 */
	public byte[] getBytes() {
		byte[] data = null;
		try {
			XMLSignatureInput si = reference.getContentsAfterTransformation();
			data = si.getBytes();
		} catch (XMLSignatureException ex) {
		} catch (CanonicalizationException ex) {
		} catch (IOException ex) {
		}
		return data;
	}
	
	/**
	 * <p>Escribe el contenido del nodo referenciado en un stream de salida.</p>
	 * @param os Stream de salida
	 */
	public void writeToStream(OutputStream os) throws IOException {
		try {
			XMLSignatureInput si = reference.getContentsAfterTransformation();
			si.updateOutputStream(os);
		} catch (XMLSignatureException ex) {
		} catch (CanonicalizationException ex) {
		}
	}
	
	/**
	 * <p>Devuelve el Element que representa al Reference.</p>
	 * @return Element
	 */
	public Element getElement() {
		return reference.getElement();
	}
	
}
