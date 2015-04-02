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
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import es.mityc.firmaJava.trust.ConfianzaEnum;
import es.mityc.javasign.certificate.ICertStatus;


public class DatosSelloTiempo {
	
	private Date fecha = null;
	private X500Principal emisor = null;
	private CertPath cadena = null; 
	private String algoritmo = null;
	private Long precision = null;
	private TipoSellosTiempo tipoSello = null;
	private byte[] rawTimestamp = null;
	private ICertStatus.CERT_STATUS revockedStatus = ICertStatus.CERT_STATUS.unknown;
	private ConfianzaEnum esCertConfianza = ConfianzaEnum.NO_REVISADO;
	
	public DatosSelloTiempo() {}
	
	/**
	 * Almacena información referente al sello de tiempo de una firma
	 * 
	 * @param java.util.Date fecha  .- Fecha del sello de tiempo
	 * @param String emisor     	.- Emisor del sello de tiempo
	 * @param CertPath cadena       .- Cadena de certificados del emisor del sello de tiempo 
	 * @param String algoritmo  	.- Algoritmo de calculo del hash del sello
	 * @param Long precission       .- Precisión del sello de tiempo en milisegundos
	 * @param TipoSellosTiempo		.- Tipo de sello para la firma XAdES-X
	 * @param rawTimestamp          .- El timetamp en crudo  
	 * @param esCertConfianza       .- Indica si el certificado de la TSA es considerado de confianza
	 */
	public DatosSelloTiempo(Date fecha,
			X500Principal emisor,
			CertPath cadena,
			String algoritmo,
			Long precision,
			TipoSellosTiempo tipoSello,
			byte[] rawTimestamp,
			ConfianzaEnum esCertconfianza) {
		
		this.fecha = fecha;
		this.emisor = emisor;
		this.cadena = cadena;
		this.algoritmo = algoritmo;
		this.precision = precision;
		this.tipoSello = tipoSello;
		this.rawTimestamp = rawTimestamp;
		this.esCertConfianza = esCertconfianza;
	}
	
	public String getAlgoritmo() {
		return algoritmo;
	}
	public void setAlgoritmo(String algoritmo) {
		this.algoritmo = algoritmo;
	}
	public X500Principal getEmisor() {
		return emisor;
	}
	public void setEmisor(X500Principal emisor) {
		this.emisor = emisor;
	}
	public Date getFecha() {
		return fecha;
	}
	public void setFecha(Date fecha) {
		this.fecha = fecha;
	}
	public Long getPrecision() {
		return precision;
	}
	public void setPrecision(Long precision) {
		this.precision = precision;
	}
	public TipoSellosTiempo getTipoSello() {
		return tipoSello;
	}
	public void setTipoSello(TipoSellosTiempo tipoSello) {
		this.tipoSello = tipoSello;
	}
	public byte[] getRawTimestamp() {
        return rawTimestamp;
    }
	public void setRawTimestamp(byte[] rawTimestamp) {
        this.rawTimestamp = rawTimestamp;
    }
	public ConfianzaEnum esCertConfianza() {
		return esCertConfianza;
	}
	public void setEsCertConfianza(ConfianzaEnum esCertConfianza) {
		this.esCertConfianza = esCertConfianza;
	}
	public CertPath getCadena() {
		return cadena;
	}
	public void setCadena(CertPath cadena) {
		this.cadena = cadena;
	}
	public ICertStatus.CERT_STATUS getRevockedStatus() {
		return revockedStatus;
	}
	public void setRevockedStatus(ICertStatus.CERT_STATUS revockedStatus) {
		this.revockedStatus = revockedStatus;
	}
}
