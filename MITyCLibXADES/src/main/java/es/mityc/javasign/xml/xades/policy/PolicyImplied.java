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
package es.mityc.javasign.xml.xades.policy;

import org.w3c.dom.Element;

import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SignaturePolicyIdentifier;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;
import es.mityc.javasign.trust.TrustAbstract;

/**
 * Escribe la política implícita en el nodo de firma indicado, sustituyendo la política previa indicada (si la hay).
 * 
 */
public class PolicyImplied implements IFirmaPolicy, IValidacionPolicy {
	
	
	public PolicyImplied() {	}

	/**
	 * 
	 * @see es.mityc.javasign.xml.xades.policy.IFirmaPolicy#writePolicyNode(org.w3c.dom.Element, java.lang.String, java.lang.String, es.mityc.firmaJava.libreria.xades.XAdESSchemas)
	 */
	public void writePolicyNode(Element nodoFirma, String namespaceDS, String namespaceXAdES, XAdESSchemas schema) throws PolicyException {
		SignaturePolicyIdentifier spi = new SignaturePolicyIdentifier(schema, true);
		PoliciesTool.insertPolicyNode(nodoFirma, namespaceDS, namespaceXAdES, schema, spi);
	}

	public String getIdentidadPolicy() {
		return "IMPLIED";
	}

	public PolicyResult validaPolicy(Element nodoFirma, ResultadoValidacion resultadoValidacion) {
		PolicyResult policyResult = new PolicyResult();
		policyResult.setResult(PolicyResult.StatusValidation.valid);
		        
		return policyResult;
	}
	
	public void setTruster(TrustAbstract truster) {
	}
}
