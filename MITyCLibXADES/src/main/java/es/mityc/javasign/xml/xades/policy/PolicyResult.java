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

import java.net.URI;

/**
 * Estructura para la validación de políticas de firma
 *
 */

public class PolicyResult {
	
	public enum StatusValidation { unknown, valid, invalid };
	
	public class DownloadPolicy {
		public URI uri;
		public StatusValidation status;
		public DownloadPolicy(URI uri, StatusValidation status) {
			this.uri = uri;
			this.status = status;
		}
	}
	
	private StatusValidation result;		// Almacena el resultado de la validacion
	private String descriptionResult;		// Almacena una cadena descriptiva del resultado de la validación
	private String description;
	private URI policyID;
	private URI[] documentation;
	private DownloadPolicy[] downloable;
	private String[] notices;
	private IValidacionPolicy policyVal;	// Almacena el validador de la policy
	
	public PolicyResult(){
		result = StatusValidation.unknown;
	}
	
	public DownloadPolicy newDownloadPolicy(URI uri, StatusValidation status) {
		return new DownloadPolicy(uri, status);
	}
	
	public StatusValidation getResult() {
		return result;
	}

	public void setResult(StatusValidation result) {
		this.result = result;
	}

	public String getDescriptionResult() {
		return descriptionResult;
	}

	public void setDescriptionResult(String descriptionResult) {
		this.descriptionResult = descriptionResult;
	}

	public URI getPolicyID() {
		return policyID;
	}

	public void setPolicyID(URI policyID) {
		this.policyID = policyID;
	}

	public URI[] getDocumentation() {
		return documentation;
	}

	public void setDocumentation(URI[] documentation) {
		this.documentation = documentation;
	}

	public DownloadPolicy[] getDownloable() {
		return downloable;
	}

	public void setDownloable(DownloadPolicy[] downloable) {
		this.downloable = downloable;
	}

	public String[] getNotices() {
		return notices;
	}

	public void setNotices(String[] notices) {
		this.notices = notices;
	}

	/**
	 * Get clase validadora de la policy
	 * @return Instancia al validador de la policy
	 */
	public IValidacionPolicy getPolicyVal() {
		return policyVal;
	}

	/**
	 * Set clase validadora de la policy
	 * @param Instancia del validador de la policy
	 */
	public void setPolicyVal(IValidacionPolicy policyVal) {
		this.policyVal = policyVal;
	}
	
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if ((obj instanceof IValidacionPolicy) && (policyVal != null)) {
			IValidacionPolicy val = (IValidacionPolicy)obj;
			if (policyVal.getIdentidadPolicy().equals(val.getIdentidadPolicy()))
				return true;
			return false;
		}
		else
			return super.equals(obj);
	}
	
	public void copy(PolicyResult pr) {
		setResult(pr.getResult());
		setPolicyID(pr.getPolicyID());
		setDescriptionResult(pr.getDescriptionResult());
		setDocumentation(pr.getDocumentation());
		setDownloable(pr.getDownloable());
		setNotices(pr.getNotices());
	}
}
