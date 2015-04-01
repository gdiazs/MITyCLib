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
package es.mityc.javasign.pkstore.pkcs11;

import java.security.Provider;

/**
 * <p>Relación entre Provider específico de PKCS11 y el slot asociado.</p>
 */
public class SunP11SlotData implements IProviderData {

	/** Proveedor asociado. */
	private Provider provider;
	/** SlotID asociado en el proveedor. */
	private long slotID;
	/** Nombre del tipo de KeyStore que maneja este proveedor. */
	private String keyStoreType;
	
	/**
	 * <p>Constructor.</p>
	 * @param prov Provider de PKCS11
	 * @param slot SlotID asociado al provider
	 * @param type Nombre del tipo de KeyStore manejado por este proveedor
	 */
	public SunP11SlotData(Provider prov, long slot, String type) {
		this.provider = prov;
		this.slotID = slot;
		this.keyStoreType = new String(type);
	}
	
	/**
	 * <p>Devuelve el slotID.</p>
	 * @return slotID
	 */
	public long getSlotID() {
		return slotID;
	}
	
	/**
	 * <p>Devuelve el provider.</p>
	 * @return Provider
	 */
	public Provider getProvider() {
		return provider;
	}
	
	/**
	 * <p>Devuelve el tipo de KeyStore que gestiona el provider de este slot.</p>
	 * @return Cadena con el tipo de KeyStore
	 */
	public String getKeyStoreTypeName() {
		return keyStoreType;
	}
	
	/**
	 * <p>Compara exclusivamente a través del slotID asociado.</p>
	 * @param obj Objeto a comparar
	 * @return <code>true</code> si tienen el mismo slotID, <code>false</code> en otro caso
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(final Object obj) {
		if (obj instanceof SunP11SlotData) {
			if (slotID == ((SunP11SlotData) obj).slotID) {
				return true;
			}
		} else if (obj instanceof Long) {
			if (slotID == ((Long) obj).longValue()) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * <p>El hashCode de este elemento depende únicamnete de su SlotID.</p>
	 * @return HashCode del slotId
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return (int) (slotID ^ (slotID >>> 32));
	}
}
