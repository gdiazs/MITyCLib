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

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;

import adsi.org.apache.xml.security.signature.ObjectContainer;
import adsi.org.apache.xml.security.transforms.Transforms;

import es.mityc.javasign.xml.resolvers.MITyCResourceResolver;
import es.mityc.javasign.xml.transform.Transform;

/**
 * Interfaz para señalar las clases que representan objetos a ser firmados
 * 
 */
public abstract class AbstractObjectToSign {

	/** Transformadas. */
	private ArrayList<Transform> transforms = new ArrayList<Transform>();
	
	/**
	 * <p>Incluye la transformada indicada para que se aplique en el objeto a firmar.</p>
	 * 
	 * @param t transformada
	 */
	public void addTransform(Transform t) {
		// evita que se añada una transformada que ya está incluida que no aporte nada nuevo
		if (t != null) {
			boolean mustadd = true;
			String alg = t.getAlgorithm();
			if ((alg != null) &&
				(Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(alg))) {
				for (Transform trans : transforms) {
					if (alg.equals(trans.getAlgorithm())) {
						mustadd = false;
						break;
					}
				}
			}
			if (mustadd) {
				transforms.add(t);
			}
		}
	}
	
	/**
	 * <p>Devuelve el listado de transformadas que se quieren aplicar al objeto.</p>
	 * @return lista de transformadas
	 */
	@SuppressWarnings("unchecked")
	public List<Transform> getTransforms() {
		return (List<Transform>) transforms.clone();
	}
	
	/**
	 * <p>Devuelve una URI que sirve para indicar dónde se encuentra el objeto a ser firmado.</p>
	 * @return URI de referencia
	 */
	public abstract String getReferenceURI();
	
	/**
	 * <p>Devuelve el tipo de referencia que tendrá el objeto a firmar.</p>
	 * <p>Este método deberá ser sobreescrito por las clases hijas que quieran devolver un tipo específico.</p>
	 * @return devuelve <code>null</code>
	 */
	public String getType() {
		return null;
	}
	
	/**
	 * <p>Devuelve un conjunto de contenedores de objetos que se añadirán a la firma.</p>
	 * <p>Este método deberá ser sobreescrito por las clases hijas que quieran incluir nuevos objetos de firma.</p>
	 * @param doc Document en el que irán los objetos
	 * @return devuelve una lista vacía
	 */
	public List<ObjectContainer> getObjects(Document doc) {
		return new ArrayList<ObjectContainer>();
	}
	
	/**
	 * <p>Devuelve un Resolver extra para tratar este objeto a ser firmado.</p>
	 * <p>Este método deberá ser sobreescrito por las clases hijas que quieran incluir Resolver extra.</p>
	 * @return devuelve <code>null</code>
	 */
	public MITyCResourceResolver getResolver() {
		return null;
	}
	
}
