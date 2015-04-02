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

import java.security.cert.CertPath;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import es.mityc.firmaJava.trust.ConfianzaEnum;
import es.mityc.javasign.xml.xades.policy.PolicyResult;

/**
 */

public class DatosFirma {
	
	private CertPath cadenaFirma = null;
	private ConfianzaEnum esCadenaConfianza = ConfianzaEnum.NO_REVISADO;
	private DatosTipoFirma tipoFirma = null; 
	private ArrayList<DatosSelloTiempo>  datosSelloTiempo = null;
	private ArrayList<DatosCRL> datosCRL = null; 
	private ArrayList<DatosOCSP> datosOCSP = null;
	private Date fechaFirma = null;
	private ArrayList<String> roles = null;
	private ArrayList<PolicyResult> politicas = null;
	private XAdESSchemas esquema = null;
	private String sigValueId = null;
	private ArrayList<String> contraFirma = null;
	private ArrayList<DatosNodosFirmados> datosNodos = null;
	
	public DatosFirma() {}
	
	/**
	 * Almacena informacion referente a una validación de Firma
	 * 
	 * @param cadenaFirma .- Cadena de certificados utilizados en la firma  
	 * @param esCadenaConfianza .- Booleano que indica si la cadena está consierada de confianza  
	 * @param tipoFirma .- Tipo de firma XAdES (BES, EPES, T...) con dos modificadores para EPES y A
	 * @param datosSelloTiempo .- Recoge la información de cada sello de tiempo de la firma  
	 * @param datosCRL .- Recoge la información de cada lista de revocación de la firma  
	 * @param datosOCSP .- Recoge información de cada respuesta OCSP de la firma  
	 * @param fechaFirma .- Fecha de firma recuperada del nodo SigningTime  
	 * @param roles .- roles definidos en la firma  
	 * @param politicas .- Recoge información de las firmas incluidas en la firma  
	 * @param esquema .- Esquema utilizado en la firma  
	 * @param sigValueId .- Identificador del nodo que contiene el valor de la firma
	 * @param contraFirma.- ArrayList de String que contiene los identificadores de los nodos firmados por ésta firma
	 * @parma datosFicheros .- ArrayList que contiene los datos asociados a los ficheros firmados
	 */
	public DatosFirma(CertPath cadenaFirma, 
			ConfianzaEnum esCAdenaConfianza,
			DatosTipoFirma tipoFirma,
			ArrayList<DatosSelloTiempo> datosSelloTiempo,
			ArrayList<DatosCRL> datosCRL,
			ArrayList<DatosOCSP> datosOCSP,
			Date fechaFirma,
			ArrayList<String> roles,
			ArrayList<PolicyResult> politicas,
			XAdESSchemas esquema,
			String sigValueId,
			ArrayList<String> contraFirma,
			ArrayList<DatosNodosFirmados> datosFicheros) {
		
		this.cadenaFirma = cadenaFirma;
		this.esCadenaConfianza = esCAdenaConfianza;
		this.datosSelloTiempo = datosSelloTiempo;
		this.datosCRL = datosCRL;
		this.datosOCSP = datosOCSP;
		this.fechaFirma = fechaFirma;
		this.roles = roles;
		this.politicas = politicas;
		this.esquema = esquema;
		this.sigValueId	= sigValueId; 
		this.contraFirma = contraFirma;
		this.datosNodos = datosFicheros;
	}	
	
	public CertPath getCadenaFirma() {
		return cadenaFirma;
	}
	public void setCadenaFirma(CertPath cadenaFirma) {
		this.cadenaFirma = cadenaFirma;
	}
	public ConfianzaEnum esCadenaConfianza() {
		return esCadenaConfianza;
	}
	public void setEsCadenaConfianza(ConfianzaEnum esCadenaConfianza) {
		this.esCadenaConfianza = esCadenaConfianza;
	}
	public ArrayList<DatosOCSP> getDatosOCSP() {
		if (datosOCSP != null)
			return datosOCSP;
		else
			return new ArrayList<DatosOCSP>();
	}
	public void setDatosOCSP(ArrayList<DatosOCSP> datosOCSP) {
		this.datosOCSP = datosOCSP;
	}
	public ArrayList<DatosCRL> getDatosCRL() {
		return datosCRL;
	}
	public void setDatosCRL(ArrayList<DatosCRL> datosCRL) {
		this.datosCRL = datosCRL;
	}
	public ArrayList<DatosSelloTiempo> getDatosSelloTiempo() {
		if (datosSelloTiempo != null)
			return datosSelloTiempo;
		else 
			return new ArrayList<DatosSelloTiempo>();
	}
	public void setDatosSelloTiempo(ArrayList<DatosSelloTiempo> datosSelloTiempo) {
		this.datosSelloTiempo = datosSelloTiempo;
	}
	public Date getFechaFirma() {
		return fechaFirma;
	}
	public void setFechaFirma(Date fechaFirma) {
		this.fechaFirma = fechaFirma;
	}
	public ArrayList<String> getRoles() {
		if (roles != null)
			return roles;
		else
			return new ArrayList<String>();
	}
	public void setRoles(ArrayList<String> roles) {
		this.roles = roles;
	}
	public ArrayList<PolicyResult> getPoliticas() {
		if (politicas != null)
			return politicas;
		else
			return new ArrayList<PolicyResult>();
	}
	public void setPoliticas(ArrayList<PolicyResult> politicas) {
		this.politicas = politicas;
	}
	public XAdESSchemas getEsquema() {
		return esquema;
	}
	public void setEsquema(XAdESSchemas esquema) {
		this.esquema = esquema;
	}
	public DatosTipoFirma getTipoFirma() {
		return tipoFirma;
	}
	public void setTipoFirma(DatosTipoFirma tipoFirma) {
		this.tipoFirma = tipoFirma;
	}
	
	/**
	 * Devuleve el identificador del nodo SignatureValue
	 * @return String
	 */
	public String getSigValueId() {
		return sigValueId;
	}

	/**
	 * Establece el identificador del nodo signatureValue
	 */
	public void setSigValueId(String sigValueId) {
		this.sigValueId = sigValueId;
	}

	/**
	 * Devuelve la estructura de firmas contrafirmadas por esta firma
	 */
	public ArrayList<String> getContraFirma() {
		return contraFirma;
	}

	/**
	 * Establece la estructura de firmas contrafirmadas por esta firma
	 */
	public void setContraFirma(ArrayList<String> contraFirma) {
		this.contraFirma = contraFirma;
	}

	/**
	 * @return ArrayList con los datos de los nodos firmados
	 */
	public List<DatosNodosFirmados> getDatosNodosFirmados() {
		return datosNodos;
	}
	
	/**
	 * <p>Devuelve un listado con los datos de los nodos firmados que no son intrínsecos de la firma.</p>
	 * @return ArrayList con los datos de los nodos
	 */
	public List<DatosNodosFirmados> getDatosNodosNoSignFirmados() {
		ArrayList<DatosNodosFirmados> res = new ArrayList<DatosNodosFirmados>();
		if (datosNodos != null) {
			for (DatosNodosFirmados dnf : datosNodos) {
				if (!dnf.isSignInternal()) {
					res.add(dnf);
				}
			}
		}
		return res;
	}

	/**
	 * @param datosFicheros.- ArrayList con los datos de los nodos firmados 
	 */
	public void setDatosNodosFirmados(ArrayList<DatosNodosFirmados> datosNodos) {
		this.datosNodos = datosNodos;
	}
	
	/**
	 * <p>Incluye datos sobre el nodo firmado indicado.</p>
	 * @param datosNodo Datos del nodo firmado
	 */
	public void addDatosNodoFirmado(DatosNodosFirmados datosNodo) {
		if (this.datosNodos == null) {
			this.datosNodos = new ArrayList<DatosNodosFirmados>();
		}
		datosNodos.add(datosNodo);
	}
	
	/**
	 * <p>Busca los datos que hay sobre el nodo firmado indicado.</p>
	 * @param id identidad del nodo Reference que apunta al nodo firmado
	 * @return Datos del nodo firmado
	 */
	public DatosNodosFirmados getDatosNodoFimadoByReferenceId(String id) {
		DatosNodosFirmados dnf = null;
		if ((datosNodos != null) && (id != null)) {
			for (DatosNodosFirmados datos : datosNodos) {
				if (id.equals(datos.getIdReference())) {
					dnf = datos;
					break;
				}
			}
		}
		return dnf;
	}

	/**
	 * <p>Busca los datos que hay sobre el nodo firmado indicado.</p>
	 * @param id identidad del nodo al que apunta el Reference
	 * @return Datos del nodo firmado
	 */
	public DatosNodosFirmados getDatosNodoFimadoById(String id) {
		DatosNodosFirmados dnf = null;
		if ((datosNodos != null) && (id != null)) {
			for (DatosNodosFirmados datos : datosNodos) {
				if (id.equals(datos.getId())) {
					dnf = datos;
					break;
				}
			}
		}
		return dnf;
	}
	
}
