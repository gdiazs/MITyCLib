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

import java.security.NoSuchProviderException;

import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.pkcs11.ConfigMultiPKCS11;
import es.mityc.javasign.pkstore.pkcs11.DefaultPassStoreP11;
import es.mityc.javasign.pkstore.pkcs11.MultiPKCS11Store;

/**
 * <p>
 * Ejemplo que lista el almacén de certificados de un dispositivo criptográfico
 * que cumpla con el estándar PKCS#11, como puede ser el DNIe.
 * </p>
 * 
 */
public class MultiPKCS11CertificateStoreListing extends
        GenericCertificateStoreListing {

    /**
     * <p>Libreria para poder acceder a los almacenes del DNIe.</p>
     * <p>Dependiendo del sistema operativo, la ruta será una u otra
     * <ul>
     * <li>Windows: <code>C:/WINDOWS/system32/UsrPkcs11.dll</code></li>
     * <li>Linux: <code>/usr/lib/libopensc-dnie.so</code></li>
     * </ul>
     * </p>
     */
    private static final String LIB_DNIE = "";

    /**
     * <p>
     * Punto de entrada al programa.
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        MultiPKCS11CertificateStoreListing certificateStoreListing = new MultiPKCS11CertificateStoreListing();
        certificateStoreListing.execute();
    }

    /**
     * <p>Obtiene acceso al DNIe vía PKCS#11.</p>
     * @return interfaz de acceso al DNIe
     * @throws CertStoreException lanzada si no se puede acceder al almacén
     */
    @Override
    protected IPKStoreManager getPKStoreManager() throws CertStoreException  {
        ConfigMultiPKCS11 config = new ConfigMultiPKCS11();
        try {
        	config.addSunProvider("DNIe", LIB_DNIE);
        } catch (NoSuchProviderException ex) {
        	throw new CertStoreException(ex.getMessage());
        }
        return new MultiPKCS11Store(config, new DefaultPassStoreP11());
    }

}
