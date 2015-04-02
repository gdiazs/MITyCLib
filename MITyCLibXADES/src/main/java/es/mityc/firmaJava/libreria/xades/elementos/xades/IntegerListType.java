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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class IntegerListType extends AbstractXADESElement {
	
	private ArrayList<Int> ints;

	/**
	 * @param schema
	 */
	public IntegerListType(XAdESSchemas schema) {
		super(schema);
	}

	public IntegerListType(XAdESSchemas schema, ArrayList<Int> ints) {
		super(schema);
		this.ints = ints;
	}
	
	public IntegerListType(XAdESSchemas schema, int[] ints) {
		super(schema);
		if (ints != null) {
			this.ints = new ArrayList<Int>(ints.length);
			for (int i = 0 ; i < ints.length; i++) {
				this.ints.add(new Int(schema, new BigInteger(Integer.toString(ints[i]))));
			}
		}
	}
	

	public ArrayList<Int> getInts() {
		return ints;
	}

	public void setInts(ArrayList<Int> ints) {
		this.ints = ints;
	}
	
	public void addInt(BigInteger integer) {
		if (ints == null)
			ints = new ArrayList<Int>();
		ints.add(new Int(schema, integer));
	}

	public void addInt(Int integer) {
		if (ints == null)
			ints = new ArrayList<Int>();
		ints.add(integer);
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof IntegerListType) {
			IntegerListType cvt = (IntegerListType) obj;
			ArrayList<Int> comp = cvt.ints;
			if (((ints == null) || (ints.isEmpty())) &&
				((comp == null) || (comp.isEmpty())))
				return true;
			if (((ints != null) && (comp != null)) && 
				 (ints.size() == comp.size())) {
				Iterator<Int> itThis = ints.iterator();
				Iterator<Int> itComp = comp.iterator();
				while (itThis.hasNext()) {
					if (!itThis.next().equals(itComp.next()))
						return false;
				}
				return true;
			}
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		NodeList nodos = element.getChildNodes();
		ArrayList<Int> temp = new ArrayList<Int>(nodos.getLength());
		for (int i = 0; i < nodos.getLength(); i++) {
			Node nodo = nodos.item(i);
			if (isDecorationNode(nodo))
				continue;
			
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Hijo de CertificateValuesType no es un elemento");
			
			Int integer = new Int(schema);
			integer.load((Element)nodo);
			temp.add(integer);
		}
		ints = temp;
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (ints != null) {
			Iterator<Int> it = ints.iterator();
			while (it.hasNext()) {
				element.appendChild(it.next().createElement(element.getOwnerDocument(), namespaceXAdES));
			}
		}
	}

}
