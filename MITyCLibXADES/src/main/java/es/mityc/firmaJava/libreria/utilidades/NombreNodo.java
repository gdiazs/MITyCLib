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

import org.w3c.dom.Element;


/**
 * <p>Clase para indicar nombres de elementos.</p>
 *
 */
public class NombreNodo {
	
	private static final String COMODIN = "*";
	
	private String namespace;
	private String localname;
	public NombreNodo(String namespace, String localname) {
		this.namespace = namespace;
		this.localname = localname;
	}
	@Override
	public boolean equals(Object obj) {
		if (obj != null) {
			if (obj instanceof NombreNodo) {
				NombreNodo nodo = (NombreNodo) obj;
				if (namespace == null) {
					if (nodo.namespace != null)
						return false;
				} else if ((!COMODIN.equals(namespace)) && (!namespace.equals(nodo.namespace))) {
					return false;
				}
				if (localname.equals(nodo.localname))
					return true;
			} else if (obj instanceof Element) {
				Element el = (Element) obj;
				if ((namespace == el.getNamespaceURI()) &&
					(localname == el.getLocalName())) {
					return true;
				}
			}
		}
		return false;
	}
	public String getNamespace() {
		return namespace;
	}
	public String getLocalname() {
		return localname;
	}
}
