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

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.elementos.xades.ObjectIdentifier;
import es.mityc.javasign.ConstantsXAdES;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.xml.xades.ReferenceProxy;
import es.mityc.javasign.xml.xades.TransformProxy;

/**
 * Almacena datos extra incluidos en la firma sobre el formato de los nodos firmados
 *  
 */
public class DatosNodosFirmados {
	
	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(DatosNodosFirmados.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsXAdES.LIB_NAME);
	
	/** Sentencia de selección de nodo por xpointer. */
	private static final String XPOINTER_ID  = "#xpointer(id('";
	/** Sentencia de selección del nodo raíz por xpointer. */
	private static final String XPOINTER_ROOT  = "#xpointer(/)";
	
	private ObjectIdentifier oi;
	private String desc;
	private String mimeType;
	private URI encoding;
	/** Guarda la referencia a la instancia Reference. */
	private ReferenceProxy reference;

	
	public DatosNodosFirmados(){}
	
	public DatosNodosFirmados(ObjectIdentifier oi, 
			String desc, String mimeType, URI encoding) {
		this.oi = oi;
		this.desc = desc;
		this.mimeType = mimeType;
		this.encoding = encoding;		
	}
	
	public void setReference(ReferenceProxy ref) {
		this.reference = ref;
		// si la referencia señala a un nodo ds:object intenta obtener sus datos de mimetype y encoding
		if ((ref != null) && (!isExternalData())) {
			Element el = UtilidadTratarNodo.getElementById(ref.getElement().getOwnerDocument(), getId());
			NombreNodo nn = new NombreNodo(ConstantesXADES.XML_NS, ConstantesXADES.OBJECT);
			if (nn.equals(el)) {
				setMimeType(el.getAttribute(ConstantesXADES.XADES_TAG_MIME_TYPE));
				String data = el.getAttribute(ConstantesXADES.XADES_TAG_ENCODING);
				if (data != null) {
					try {
						// FIX: Cambia los espacios por %20 para evitar problemas con la clase URI
						data = data.replace(" ", "%20");
						setEncoding(new URI(data));
					} catch (URISyntaxException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_9, ex.getMessage()));
					}
				}
			}
		}
	}
	
	/**
	 * <p>Intenta recuperar el identificador de este elemento basándose en la ruta indicada en el reference.</p>
	 * @return id del nodo
	 */
	public String getId() {
		// TODO: Si la URI es xpointer u otro obtener correctamente la Id
		String uri = getURI();
		return (uri != null) ? ((uri.startsWith("#")) ? ((uri.startsWith(XPOINTER_ID)) ?  uri.substring(XPOINTER_ID.length(), uri.length() - 2) : uri.substring(1)) : uri) : null;
	}
	
	/**
	 * <p>Devuelve la Id del nodo Reference que apunta a este nodo firmado.</p>
	 * @return id del nodo reference
	 */
	public String getIdReference() {
		return (reference != null) ? reference.getID() : null;
	}
	
	/**
	 * <p>Devuelve el Element que representa al Reference.</p>
	 * @return Element
	 */
	public Element getElementReference() {
		return (reference != null) ? reference.getElement() : null;
	}

	public ObjectIdentifier getObjectIdentifier() {
		return oi;
	}
	public void setObjectIdentifier(ObjectIdentifier oi) {
		this.oi = oi;
	}
	public String getDescription() {
		return desc;
	}
	public void setDescription(String desc) {
		this.desc = desc;
	}
	public String getMimeType() {
		return mimeType;
	}
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}
	public URI getEncoding() {
		return encoding;
	}
	public void setEncoding(URI encoding) {
		this.encoding = encoding;
	}
	
	/**
	 * <p>Devuelve la URI señalada por la Reference.</p>
	 * @return URI
	 */
	public String getURI() {
		return (reference != null) ? ((XPOINTER_ROOT.equals(reference)) ? "" : reference.getURI()) : null;
	}
	
	/**
	 * <p>Devuelve un listado de las transformadas aplicadas al nodo.</p>
	 * @return
	 */
	public List<TransformProxy> getTransforms() {
		return (reference != null) ? reference.getTransforms() : new ArrayList<TransformProxy>();
	}
	
	/**
	 * <p>Indica si el nodo firmado puede ver modificado su contenido debido a las aplicaciones a las que está sometido.</p>
	 * <p>Las únicas transformadas que supone que no modifican al contenido original (de una manera significativa) son las de canonicalización
	 * y la enveloped.</p>
	 * @return <code>true</code> si existe alguna transformada que no sea enveloped o de canonicalización
	 */
	public boolean canBeModifiedByTransforms() {
		boolean modified = false;
		List<TransformProxy> trans = getTransforms();
		for (TransformProxy transform : trans) {
			String uri = transform.getURI();
			if ((!TransformProxy.isCanonicalization(transform)) && (!uri.equals(TransformProxy.TRANSFORM_ENVELOPED_SIGNATURE))) {
				modified = true;
				break;
			}
		}
		return modified;
	}
	
	/**
	 * <p>Devuelve los bytes del contenido firmado (si está disponible).</p> 
	 * @return contenido del nodo en bytes
	 */
	public byte[] getNodoFirmadoBytes() {
		return reference.getBytes();
	}
	
	/**
	 * <p>Escribe el contenido firmado en un stream de salida.</p>
	 * @param os stream de salida
	 * @throws IOException lanzada si ocurre algún error durante la escritura del contenido
	 */
	public void writeBytesToStream(OutputStream os) throws IOException {
		reference.writeToStream(os);
	}
	
	/**
	 * <p>Indica si el nodo firmado es un nodo de firma o un nodo <i>externo</i> a ésta.</p>
	 * <p>Uno nodo &lt;ds:object&gt; se considerará externo (a menos que contenga información XAdES).</p> 
	 * @return <code>true</code> si es un nodo con información de firma
	 */
	public boolean isSignInternal() {
		boolean res = false;
		if (!isExternalData()) {
			if (reference != null) {
				String id = getId();
				if (id != null) {
					Element el = UtilidadTratarNodo.getElementById(reference.getElement().getOwnerDocument(), id);
					if (el != null) {
						Element signature = (Element) reference.getElement().getParentNode().getParentNode();
						if (UtilidadTratarNodo.isChildNode(el, signature)) {
							// Es un nodo interno a la firma, comprueba si es un nodo ds:object dentro de la firma
							res = !UtilidadTratarNodo.isChildNode(el, new NombreNodo(ConstantesXADES.XML_NS, ConstantesXADES.OBJECT), signature);
						} else {
							res = false;
						}
					}
				}
			}
		}
		return res;
	}
	
	/**
	 * <p>Indica que la información firmada en el reference es información <i>detached</i> (no disponible dentro de la firma).</p>
	 * @return <code>true</code> si los datos son externos al xml que contiene la firma
	 */
	public boolean isExternalData() {
		boolean res = false;
		if (reference != null) {
			String uri = reference.getURI();
			if ((uri != null) && (!"".equals(uri)) && (!uri.startsWith("#"))) {
				res = true;
			}
		}
		return res;
	}

}
