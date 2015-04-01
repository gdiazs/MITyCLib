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
/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package es.mityc.javasign.pkstore.pkcs11;

import java.security.cert.X509Certificate;

import es.mityc.javasign.pkstore.IPassStoreKS;

/**
 * <p>Recoge las contraseñas para acceder a servicios de dispositivos externos.</p>
 * 
 */
public class HandlerPassPKCS11Store implements IPassStoreKS {
	
	/**
	 * <p>Crea una instancia para recoger contraseñas de dispositivos externos.</p>
	 * 
	 * @param title Título de la ventana
	 */
	public HandlerPassPKCS11Store(final String title) {
		// TODO: guardar el título de la ventana
	}

	/**
	 * <p>Devuelve la contraseña de acceso al dispositivo externo.</p>
	 * 
	 * @param certificate Certificado (irrelevante)
	 * @param alias Alias (irrelevante)
	 * @return contraseña (PIN)
	 */
	public char[] getPassword(final X509Certificate certificate, final String alias) {
		// TODO: presenta una ventana de diálogo que tiene como título el indicado en la creación de esta instancia. Ha de presentar una etiqueta
		// TODO: que será PIN y un cuadro de texto para introducir la contraseña (es decir, un JPasswordField). Además deberá tener un botón de 
		// TODO: aceptar. Cuando se pulse aceptar se devolverá el contenido del cuadro de texto.
		throw new UnsupportedOperationException("Not implemented yet");
	}

}
