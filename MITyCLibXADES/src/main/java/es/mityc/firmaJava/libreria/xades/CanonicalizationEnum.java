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

import adsi.org.apache.xml.security.transforms.Transforms;

public enum CanonicalizationEnum {
	
	UNKNOWN("unknown"),
	C14N_OMIT_COMMENTS(Transforms.TRANSFORM_C14N_OMIT_COMMENTS),
	C14N_WITH_COMMENTS(Transforms.TRANSFORM_C14N_WITH_COMMENTS),
	C14N_EXCL_OMIT_COMMENTS(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS),
	C14N_EXCL_WITH_COMMENTS(Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS);
	
	private String value;
	
	private CanonicalizationEnum(String value) {
		this.value = value;
	}
	
	@Override
	public String toString() {
		return value;
	}
	
	public static CanonicalizationEnum getCanonicalization(String value) {
		if (value != null) {
			if (Transforms.TRANSFORM_C14N_OMIT_COMMENTS.equals(value))
				return C14N_OMIT_COMMENTS;
			else if (Transforms.TRANSFORM_C14N_WITH_COMMENTS.equals(value))
				return C14N_WITH_COMMENTS;
			else if (Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS.equals(value))
				return C14N_EXCL_OMIT_COMMENTS;
			else if (Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS.equals(value))
				return C14N_EXCL_WITH_COMMENTS;
		}
		return UNKNOWN;
	}

}
