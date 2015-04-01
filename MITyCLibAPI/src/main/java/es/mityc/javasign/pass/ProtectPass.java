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
package es.mityc.javasign.pass;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <p>Protege el acceso a una contraseña encriptándola mediante PBE.</p>
 * 
    */
public final class ProtectPass {
	
	/** LOGGER. */
	private static final Log LOGGER = LogFactory.getLog(ProtectPass.class);
	
	/**
	 * <p>Constructor privado.</p>
	 */
	private ProtectPass() { }
	
	/**
	 * <p>Protege una contraseña.</p>
	 * @param args 0: contraseña a proteger
	 */
	public static void main(String[] args) {
		if ((args != null) && (args.length == 2)) {
			System.out.println("Recuperando ofuscador " + args[0]);
			try {
				IPassSecurity sec = PassSecurityFactory.getInstance().getPassSecurityManager(args[0], false);
				if (sec == null) {
					System.out.println("No se encuentra el ofuscador indicado");
				} else {
					String res = sec.protect(args[0]);
					System.out.println("Contraseña protegida: " + res);
					String orig = sec.recover(res);
					if ((orig == null) || (args[0].compareTo(orig)) != 0) {
						LOGGER.fatal("Error en el proceso de seguridad. Contraseña protegida no es equivalente a contraseña proporcionada.");
						System.out.println("Error en el proceso de seguridad. Contraseña protegida no es equivalente a contraseña proporcionada.");
					}
				}
			} catch (PassSecurityException ex) {
				LOGGER.fatal("Error preparando configuración de seguridad: " + ex.getMessage());
				LOGGER.debug("", ex);
				System.out.println("Error no esperado preparando configuración de seguridad: " + ex.getMessage());
			}
		} else {
			System.out.println("Ejemplo de uso:");
			System.out.println("   ProtectPass <id_ofuscador> <contraseña>");
			System.out.println("         id_ofuscador  identificador del ofuscador");
			System.out.println("         contraseña    contraseña que se quiere proteger");
		}
	}
	
}
