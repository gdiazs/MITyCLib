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
public class SigPolicyQualifiersListType extends AbstractXADESElement {
	
	private ArrayList<SigPolicyQualifier> qualifiers;

	/**
	 * @param schema
	 */
	public SigPolicyQualifiersListType(XAdESSchemas schema) {
		super(schema);
	}

	public SigPolicyQualifiersListType(XAdESSchemas schema, ArrayList<SigPolicyQualifier> list) {
		super(schema);
		this.qualifiers = list;
	}
	
	

	public ArrayList<SigPolicyQualifier> getList() {
		return qualifiers;
	}

	public void setList(ArrayList<SigPolicyQualifier> list) {
		this.qualifiers = list;
	}
	
	public void addPolicyQualifier(SigPolicyQualifier qualifier) {
		if (qualifiers == null)
			qualifiers = new ArrayList<SigPolicyQualifier>();
		qualifiers.add(qualifier);
	}

	public void addPolicyQualifier(IPolicyQualifier policyQualifier) {
		if (qualifiers == null)
			qualifiers = new ArrayList<SigPolicyQualifier>();
		qualifiers.add(new SigPolicyQualifier(schema, policyQualifier));
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SigPolicyQualifiersListType) {
			SigPolicyQualifiersListType cvt = (SigPolicyQualifiersListType) obj;
			ArrayList<SigPolicyQualifier> comp = cvt.qualifiers;
			if (((qualifiers == null) || (qualifiers.isEmpty())) &&
				((comp == null) || (comp.isEmpty())))
				return true;
			if (((qualifiers != null) && (comp != null)) && 
				 (qualifiers.size() == comp.size())) {
				Iterator<SigPolicyQualifier> itThis = qualifiers.iterator();
				Iterator<SigPolicyQualifier> itComp = comp.iterator();
				while (itThis.hasNext()) {
					if (!itThis.next().equals(itComp.next()))
						return false;
				}
				return true;
			}
		}
		return false;
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((qualifiers != null) && (qualifiers.size() > 0)) {
			Iterator<SigPolicyQualifier> it = qualifiers.iterator();
			while (it.hasNext()) {
				element.appendChild(it.next().createElement(element.getOwnerDocument(), namespaceXAdES));
			}
		}
		else
			throw new InvalidInfoNodeException("Nodo SigPolicyQualifiersListType no tiene ningún hijo");
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}
	

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		NodeList nodos = element.getChildNodes();
		ArrayList<SigPolicyQualifier> temp = new ArrayList<SigPolicyQualifier>(nodos.getLength());
		for (int i = 0; i < nodos.getLength(); i++) {
			Node nodo = nodos.item(i);
			if (isDecorationNode(nodo))
				continue;
			
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Hijo de SigPolicyQualifiersListType no es un elemento");
			
			SigPolicyQualifier qualifier = new SigPolicyQualifier(schema);
			qualifier.load((Element)nodo);
			temp.add(qualifier);
		}
		if (temp.size() == 0)
			throw new InvalidInfoNodeException("SigPolicyQualifiersListType no tiene hijos");
		
		qualifiers = temp;
	}

}
