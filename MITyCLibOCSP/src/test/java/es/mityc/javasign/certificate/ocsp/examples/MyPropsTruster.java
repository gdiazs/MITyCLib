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
package es.mityc.javasign.certificate.ocsp.examples;

import es.mityc.javasign.trust.PropsTruster;
import es.mityc.javasign.trust.TrustAdapter;

/**
 * <p>Gestiona las entidades de confianza que admite MITyC.</p>
 * <p>Esta clase se basa en ficheros de configuración para parametrizar los certificados admitidos (en /trust/mitycsimple.properties).</p>
 * 
 */
public class MyPropsTruster extends PropsTruster {

	/** Fichero de configuración. */
	private static final String CONF_FILE = "trust/mytruster.properties";

	/**
	 * <p>Constructor.</p>
	 * @param fileconf
	 */
	private MyPropsTruster() {
		super(CONF_FILE);
	}

	/**
	 * <p>Devuelve una instancia única del gestionador de confianza del MITyC.</p>
	 * @return Instancia de este gestionador de confianza
	 */
	public static TrustAdapter getInstance() {
		if (instance == null) {
			instance = new MyPropsTruster();
		}
		return instance;
	}
}
