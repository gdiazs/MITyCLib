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
import es.mityc.javasign.trust.TrustAbstract;

/**
 * Interfaz que han de implementar los validadores de policies que gestiona el manager de policies.
 * 
 * Además los validadores de policies deben tener un constructor por defecto sin parámetros.
 *
 */
public interface IValidacionPolicy {
	
	/**
	 * Este método deberá encargarse de validar que la firma cumple la policy implementada.
	 * 
	 * @param nodoFirma nodo raíz (de firma) de la firma que se está validando
	 * @param resultadoValidacion resultado de la validacion de una firma
	 * 
	 * @return devuelve el resultado de la validación de la policy
	 */
	public PolicyResult validaPolicy(Element nodoFirma, final ResultadoValidacion resultadoValidacion);
	
	/**
	 * Devuelve una cadena que sirve para identificar la policy
	 * @return identificación de la policy
	 */
	public String getIdentidadPolicy();
	
	/**
	 * Permite indicar cual es el administrador de confianza a emplear 
	 * durante la validación de la politica.
	 * @param truster Una instancia que extienda de TrustAbstract
	 */
	public void setTruster(TrustAbstract truster);
}
