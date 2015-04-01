/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES 1.1.7".
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
package es.mityc.javasign.pkstore.iexplorer;

import java.security.Provider;

/**
 * <p>Proveedor que implementa el algoritmo de firma SHA1withRSA para Internet Explorer
 * 5.5 o superior en sistemas operativos Windows 98 2ª Edition o superiores.</p>
 *
 */

public final class MITyCMSProvider extends Provider {
	
	/** Nombre del proveedor específico para MS.*/
	public static final String PROVIDER_MS = "MITyCMSProvider";
	/** Descripción del proveedor. */
	private static final String PROVIDER_MS_DESCRIPTION = "MITyCMSProvider v1.0, implementación de SHA1withRSA basado en KeyStore de Microsoft y OpenOCES - OpenSign";
	/** Nombre del algoritmo de firma implementado en este proveedor. */
	private static final String SIGNATURE_SHA1_WITH_RSA = "Signature.SHA1withRSA";
	/** Nombre de la clase que gestiona las labores de firma. */
	private static final String ENGINE_CLASS = IESignEngine.class.getName(); //"es.mityc.javasign.pkstore.iexplorer.IESignEngine";

    /**
     * <p>Crea una nueva instancia de ProveedorCriptograficoMS.</p>
     */
    public MITyCMSProvider() {
        super(PROVIDER_MS, 1.0, PROVIDER_MS_DESCRIPTION);
        super.put(SIGNATURE_SHA1_WITH_RSA, ENGINE_CLASS);
    }
}
