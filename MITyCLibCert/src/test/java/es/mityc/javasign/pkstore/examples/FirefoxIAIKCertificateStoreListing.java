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
/*
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
package es.mityc.javasign.pkstore.examples;

import static org.junit.Assert.fail;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.mozilla.MozillaStoreJSS;

/**
 * <p>
 * Ejemplo que lista el almacén de certificados de Firefox
 * </p>
 * 
 */
public class FirefoxIAIKCertificateStoreListing extends GenericCertificateStoreListing {

    /**
     * Directorio donde se encuentra el perfil de Mozilla del que se desean
     * listar los certificados. Dependiendo del sistema operativo, la ruta será
     * de una forma u otra:
     * <ul>
     * <li>Windows:
     * <code>C:/Documents and Settings/<b>usuario</b>/Datos de programa/Mozilla/Firefox/Profiles/<b>perfil</b></code>
     * </li>
     * <li>Linux: <code>~/.mozilla/firefox/<b>perfil</b></code></li>
     * </ul>
     */
    private static final String MOZILLA_PROFILE_DIRECTORY = "";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args Argumentos del programa
     */
    public static void main(String[] args) {
        FirefoxIAIKCertificateStoreListing certificateStoreListing = new FirefoxIAIKCertificateStoreListing();
        certificateStoreListing.execute();
    }

    @Override
    protected IPKStoreManager getPKStoreManager() {
        try {
			return new MozillaStoreJSS(MOZILLA_PROFILE_DIRECTORY);
		} catch (CertStoreException e) {
			fail("Error al crear el almacén" + e.getMessage());
			return null;
		}
    }
}
