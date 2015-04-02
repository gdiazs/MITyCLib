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

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 */
public class SignatureProductionPlaceType extends AbstractXADESElement {
	
	private City city;
	private CountryName country;
	private PostalCode postal;
	private StateOrProvince province;

	/**
	 * @param schema
	 */
	public SignatureProductionPlaceType(XAdESSchemas schema) {
		super(schema);
	}
	
	public SignatureProductionPlaceType(XAdESSchemas schema, String city, String state, String postalCode, String country) {
		super(schema);
		if (city != null)
			this.city = new City(schema, city);
		if (state != null)
			this.province = new StateOrProvince(schema, state);
		if (postalCode != null)
			this.postal = new PostalCode(schema, postalCode);
		if (country != null)
			this.country = new CountryName(schema, country);
	}
	
	public String getCity() {
		if (city != null)
			return city.getValue();
		return null;
	}

	public String getCountry() {
		if (country != null)
			return country.getValue();
		return null;
	}
	
	public String getPostalCode() {
		if (postal != null)
			return postal.getValue();
		return null;
	}
	
	public String getStateOrProvince() {
		if (province != null)
			return province.getValue();
		return null;
	}
	
	public void setCity(String city) {
		if (city != null)
			this.city = new City(schema, city);
		else
			this.city = null;
	}

	public void setCountry(String country) {
		if (country != null)
			this.country = new CountryName(schema, country);
		else
			this.country = null;
	}

	public void setPostalCode(String postalCode) {
		if (postalCode != null)
			this.postal = new PostalCode(schema, postalCode);
		else
			this.postal = null;
	}

	public void setStateOrProvince(String stateOrProvince) {
		if (stateOrProvince != null)
			this.province = new StateOrProvince(schema, stateOrProvince);
		else
			this.province = null;
	}
	
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}
	
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (city != null)
			element.appendChild(city.createElement(element.getOwnerDocument(), namespaceXAdES));
		if (province != null)
			element.appendChild(province.createElement(element.getOwnerDocument(), namespaceXAdES));
		if (postal != null)
			element.appendChild(postal.createElement(element.getOwnerDocument(), namespaceXAdES));
		if (country != null)
			element.appendChild(country.createElement(element.getOwnerDocument(), namespaceXAdES));
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SignatureProductionPlaceType) {
			SignatureProductionPlaceType sppt = (SignatureProductionPlaceType) obj;
			if (city == null) {
				if (sppt.city != null)
					return false;
			}
			else if (!city.equals(sppt.city))
				return false;
			if (country == null) {
				if (sppt.country != null)
					return false;
			}
			else if (!country.equals(sppt.country))
				return false;
			if (postal == null) {
				if (sppt.postal != null)
					return false;
			}
			else if (!postal.equals(sppt.postal))
				return false;
			if (province == null) {
				if (sppt.province != null)
					return false;
			}
			else if (!province.equals(sppt.province))
				return false;
			
			return true;
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		Node node = UtilidadTratarNodo.getFirstElementChild(element, true);
		// busca la ciudad
		if (node == null)
			return;
		else if (node.getNodeType() != Node.ELEMENT_NODE)
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de SignatureProductionPlaceType");
		Element child = (Element)node;
		City cityTemp = new City(schema);
		if (cityTemp.isThisNode(child)) {
			cityTemp.load(child);
			city = cityTemp;
			node = UtilidadTratarNodo.getNextElementSibling(node, true);
		} else
			city = null;
		
		// busca la provincia
		if (node == null)
			return;
		else if (node.getNodeType() != Node.ELEMENT_NODE)
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de SignatureProductionPlaceType");
		child = (Element)node;
		StateOrProvince stateTemp = new StateOrProvince(schema);
		if (stateTemp.isThisNode(child)) {
			stateTemp.load(child);
			province = stateTemp;
			node = UtilidadTratarNodo.getNextElementSibling(node, true);
		} else
			province = null;
		
		// busca el código postal
		if (node == null)
			return;
		else if (node.getNodeType() != Node.ELEMENT_NODE)
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de SignatureProductionPlaceType");
		child = (Element)node;
		PostalCode postalTemp = new PostalCode(schema);
		if (postalTemp.isThisNode(child)) {
			postalTemp.load(child);
			postal = postalTemp;
			node = UtilidadTratarNodo.getNextElementSibling(node, true);
		} else
			postal = null;

		// busca el nombre del pais
		if (node == null)
			return;
		else if (node.getNodeType() != Node.ELEMENT_NODE)
			throw new InvalidInfoNodeException("Se esperaba elemento como hijo de SignatureProductionPlaceType");
		child = (Element)node;
		CountryName countryTemp = new CountryName(schema);
		if (countryTemp.isThisNode(child)) {
			countryTemp.load(child);
			country = countryTemp;
			node = UtilidadTratarNodo.getNextElementSibling(node, true);
		} else
			country = null;

		if (node != null)
			throw new InvalidInfoNodeException("No se esperaba este elemento como hijo de SignatureProductionPlaceType");
	}

}
