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
/**
 * 
 */
package es.mityc.firmaJava.libreria.xades.elementos.xades;

import java.util.ArrayList;
import java.util.Iterator;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class CRLRefsType extends AbstractXADESElement {

	private ArrayList<CRLRef> crlRefs;

	/**
	 * @param schema
	 */
	public CRLRefsType(XAdESSchemas schema) {
		super(schema);
	}
	
	public CRLRefsType(XAdESSchemas schema, ArrayList<CRLRef> crlRefs) {
		super(schema);
		this.crlRefs = crlRefs;
	}
	
	public void addCRLRef(CRLRef crlRef) {
		if (crlRefs == null)
			crlRefs = new ArrayList<CRLRef>();
		crlRefs.add(crlRef);
	}

	/**
	 * @return the certificates
	 */
	public ArrayList<CRLRef> getCRLRefs() {
		return crlRefs;
	}

	/**
	 * @param certificates the certificates to set
	 */
	public void setCertificates(ArrayList<CRLRef> crlRefs) {
		this.crlRefs = crlRefs;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CRLRefsType) {
			CRLRefsType cvt = (CRLRefsType) obj;
			ArrayList<CRLRef> comp = cvt.crlRefs;
			if (((crlRefs == null) || (crlRefs.isEmpty())) &&
				((comp == null) || (comp.isEmpty())))
				return true;
			if (((crlRefs != null) && (comp != null)) && 
				 (crlRefs.size() == comp.size())) {
				Iterator<CRLRef> itThis = crlRefs.iterator();
				Iterator<CRLRef> itComp = comp.iterator();
				while (itThis.hasNext()) {
					if (!itThis.next().equals(itComp.next()))
						return false;
				}
				return true;
			}
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		NodeList nodos = element.getChildNodes();

		ArrayList<CRLRef> temp = new ArrayList<CRLRef>(nodos.getLength());
		for (int i = 0; i < nodos.getLength(); i++) {
			Node nodo = nodos.item(i);
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Hijo de CRLRefsType no es un elemento");
			
			CRLRef crlRef = new CRLRef(schema);
			crlRef.load((Element)nodo);
			temp.add(crlRef);
		}
		
		if (temp.size() == 0)
			throw new InvalidInfoNodeException("CRLRefsType debe tener al menos un hijo");
		
		crlRefs = temp;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((crlRefs == null) || (crlRefs.size() == 0))
			throw new InvalidInfoNodeException("CRLRefsType debe tener al menos un hijo");
		Iterator<CRLRef> it = crlRefs.iterator();
		while (it.hasNext()) {
			element.appendChild(it.next().createElement(element.getOwnerDocument(), namespaceXDsig, namespaceXAdES));
		}
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES, String namespaceXDsig) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES, namespaceXDsig);
	}

}
