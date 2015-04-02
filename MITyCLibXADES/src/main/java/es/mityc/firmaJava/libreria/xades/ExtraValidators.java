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

import java.util.List;

import es.mityc.javasign.certificate.ICertStatusRecoverer;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.xml.xades.policy.IValidacionPolicy;

/**
 * Esta clase contiene los validadores adicionales que se utilizarán al validar la firma XAdES.
 * 
 * <br/><br/>Estos validadores contemplan la validación de:
 * <ul>
 * 	<li>Validación de política de firma: comprueban que la firma se ajuste a las políticas indicadas.</li>
 * 	<li>Validación de certificado: si la firma es válida y no incluye información de estado de certificado, comprueba el estado del 
 * certificado con este validador.</li>
 * 	<li>Confianza: comprueban que los elementos de la firma sean de entidades de confianza (certificados de firma, 
 * respuestas de estados de certificados, sellos de tiempo, etc).</li>
 * </ul>
 */
public class ExtraValidators {
	
	private List<IValidacionPolicy> policies;
	private ICertStatusRecoverer certStatus;
	private TrustAbstract trusterOCSP;
	private TrustAbstract trusterCRL;
	private TrustAbstract trusterCerts;
	private TrustAbstract trusterTSA;
	
	
	/**
	 * @param policies Validadores de política
	 * @param certStatus Validadores de estado de certificado
	 * @param trusterCerts Validadores de confianza
	 */
	public ExtraValidators(List<IValidacionPolicy> policies, ICertStatusRecoverer certStatus, TrustAbstract trusterCerts) {
		super();
		this.policies = policies;
		this.certStatus = certStatus;
		this.trusterCerts = trusterCerts;
	}
	
	/**
	 * @return the policies
	 */
	public List<IValidacionPolicy> getPolicies() {
		return policies;
	}
	/**
	 * @param policies the policies to set
	 */
	public void setPolicies(List<IValidacionPolicy> policies) {
		this.policies = policies;
	}
	/**
	 * @return the certStatus
	 */
	public ICertStatusRecoverer getCertStatus() {
		return certStatus;
	}
	/**
	 * @param certStatus the certStatus to set
	 */
	public void setCertStatus(ICertStatusRecoverer certStatus) {
		this.certStatus = certStatus;
	}
	/**
	 * @return the trusterOCSP
	 */
	public TrustAbstract getTrusterOCSP() {
		return trusterOCSP;
	}
	/**
	 * @param trusterOCSP the trusterOCSP to set
	 */
	public void setTrusterOCSP(TrustAbstract trusterOCSP) {
		this.trusterOCSP = trusterOCSP;
	}
	/**
	 * @return the trusterCRL
	 */
	public TrustAbstract getTrusterCRL() {
		return trusterCRL;
	}
	/**
	 * @param trusterCRL the trusterCRL to set
	 */
	public void setTrusterCRL(TrustAbstract trusterCRL) {
		this.trusterCRL = trusterCRL;
	}
	/**
	 * @return the trusterCerts
	 */
	public TrustAbstract getTrusterCerts() {
		return trusterCerts;
	}
	/**
	 * @param trusterCerts the trusterCerts to set
	 */
	public void setTrusterCerts(TrustAbstract trusterCerts) {
		this.trusterCerts = trusterCerts;
	}
	/**
	 * @return the trusterTSA
	 */
	public TrustAbstract getTrusterTSA() {
		return trusterTSA;
	}
	/**
	 * @param trusterTSA the trusterTSA to set
	 */
	public void setTrusterTSA(TrustAbstract trusterTSA) {
		this.trusterTSA = trusterTSA;
	}

}
