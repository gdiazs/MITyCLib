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

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Iterator;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class CRLValuesType extends AbstractXADESElement {
	
	private ArrayList<EncapsulatedCRLValue> crls;

	/**
	 * @param schema
	 */
	public CRLValuesType(XAdESSchemas schema) {
		super(schema);
	}
	
	public CRLValuesType(XAdESSchemas schema, ArrayList<EncapsulatedCRLValue> crls) {
		super(schema);
		this.crls = crls;
	}
	
	public void addEncapsulatedCRLValue(EncapsulatedCRLValue crl) {
		if (crls == null)
			crls = new ArrayList<EncapsulatedCRLValue>();
		crls.add(crl);
	}

	/**
	 * @return the certificates
	 */
	public ArrayList<EncapsulatedCRLValue> getEncapsulatedCRLValues() {
		return crls;
	}

	/**
	 * @param certificates the certificates to set
	 */
	public void setEncapsulatedCRLValues(ArrayList<EncapsulatedCRLValue> crls) {
		this.crls = crls;
	}
	
	public void addCRL(X509CRL crl, String id) throws InvalidInfoNodeException {
		EncapsulatedCRLValue ecv = new EncapsulatedCRLValue(schema, id, crl);
		addEncapsulatedCRLValue(ecv);
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CertificateValuesType) {
			CRLValuesType cvt = (CRLValuesType) obj;
			ArrayList<EncapsulatedCRLValue> comp = cvt.crls;
			if (((crls == null) || (crls.isEmpty())) &&
				((comp == null) || (comp.isEmpty())))
				return true;
			if (((crls != null) && (comp != null)) && 
				 (crls.size() == comp.size())) {
				Iterator<EncapsulatedCRLValue> itThis = crls.iterator();
				Iterator<EncapsulatedCRLValue> itComp = comp.iterator();
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

		ArrayList<EncapsulatedCRLValue> temp = new ArrayList<EncapsulatedCRLValue>(nodos.getLength());
		for (int i = 0; i < nodos.getLength(); i++) {
			Node nodo = nodos.item(i);
			if (isDecorationNode(nodo))
				continue;
			
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Hijo de CRLValuesType no es un elemento");
			
			EncapsulatedCRLValue crl = new EncapsulatedCRLValue(schema);
			crl.load((Element)nodo);
			temp.add(crl);
		}
		
		if (temp.size() == 0)
			throw new InvalidInfoNodeException("CRLValuesType debe tener al menos un hijo");
		
		crls = temp;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((crls == null) || (crls.size() == 0))
			throw new InvalidInfoNodeException("CRLValuesType debe tener al menos un hijo");
		Iterator<EncapsulatedCRLValue> it = crls.iterator();
		while (it.hasNext()) {
			element.appendChild(it.next().createElement(element.getOwnerDocument(), namespaceXAdES));
		}
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.xades.AbstractXADESElement#addContent(org.w3c.dom.Element, java.lang.String)
	 */
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}

}
