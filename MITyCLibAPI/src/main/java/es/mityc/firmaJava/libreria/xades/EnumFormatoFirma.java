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



/**
 * Tipos de firma XML reconocidas
 *
 */

public enum EnumFormatoFirma {
	XMLSignature,
	XAdES_BES,
	XAdES_T,
	XAdES_C,
	XAdES_X,
	XAdES_XL,
	PKCS7;

	public static String getName(EnumFormatoFirma tipo) {
		switch(tipo) {
		case XMLSignature:
			return "XAdES-BES";
		case XAdES_BES:
			return "XAdES-BES";
		case XAdES_T:
			return "XAdES-T";
		case XAdES_C:
			return "XAdES-C";
		case XAdES_X:
			return "XAdES-X";
		case XAdES_XL:
			return "XAdES-XL";
		case PKCS7:
			return "PKCS-7";
		default:
			return "XAdES-BES";
		}
	}
	
	public static EnumFormatoFirma parse(String tipo) {
		if (tipo != null && tipo.length() > 0) {
			if (tipo.equals("XAdES-BES"))
				return XAdES_BES;
			else if (tipo.equals("XAdES-BES"))
				return XAdES_BES;
			else if (tipo.equals("XAdES-T"))
				return XAdES_T;
			else if (tipo.equals("XAdES-C"))
				return XAdES_C;
			else if (tipo.equals("XAdES-X"))
				return XAdES_X;
			else if (tipo.equals("XAdES-XL"))
				return XAdES_XL;
			else if (tipo.equals("PKCS-7"))
				return PKCS7;
			else 
				return null;
		}
		
		return null;
	}
}

