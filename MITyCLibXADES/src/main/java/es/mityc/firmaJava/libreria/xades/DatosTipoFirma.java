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

import es.mityc.javasign.EnumFormatoFirma;


/**
 */
public class DatosTipoFirma {
	
	private EnumFormatoFirma tipoXAdES = null;
	private boolean esXAdES_EPES = false;
	private boolean esXAdES_A = false;
	
	public DatosTipoFirma () {}
	
	/**
	 * Almacena información referente al tipo de firma XAdES obtenido
	 * 
	 * @param tipoFirma .- Indica el nivel de firma (XAdES-BES, XAdES-T, etc...)
	 * @param esXAdES_EPES .- Modificador que indica que la firma incluye políticas
	 * @param esXAdES_A .- Modificador que indica que la firma incluye un sello de tiempo del tipo A
	 */
	public DatosTipoFirma (EnumFormatoFirma tipoXAdES,
			boolean esXAdES_EPES,
			boolean esXAdES_A) {
		
		this.tipoXAdES = tipoXAdES;
		this.esXAdES_EPES = esXAdES_EPES;
		this.esXAdES_A = esXAdES_A;
	}

	public EnumFormatoFirma getTipoXAdES() {
		return tipoXAdES;
	}
	public void setTipoXAdES(EnumFormatoFirma tipoXAdES) {
		this.tipoXAdES = tipoXAdES;
	}
	public boolean esXAdES_EPES() {
		return esXAdES_EPES;
	}
	public void setEsXAdES_EPES(boolean esXAdES_EPES) {
		this.esXAdES_EPES = esXAdES_EPES;
	}
	public boolean esXAdES_A() {
		return esXAdES_A;
	}
	public void setEsXAdES_A(boolean esXAdES_A) {
		this.esXAdES_A = esXAdES_A;
	}
}
