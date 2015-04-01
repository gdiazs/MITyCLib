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
import es.mityc.javasign.pkstore.DefaultPassStoreKS;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.mscapi.MSCAPIStore;

/**
 * <p>
 * Ejemplo que lista el almacén de certificados de Windows a través del proveedor
 * de seguridad SunMSCAPI-MITyC, siempre y cuando el JAR correspondiente a dicho 
 * proveedor esté accesible en el classpath, o mediante el proveedor SunMSCAPI
 * en caso contrario. En el caso de usar el proveedor SunMSCAPI será necesario 
 * hacer uso de Java 1.6+. En el caso de usar el proveedor SunMSCAPI-MITyC, será
 * suficiente con utilizar Java 1.5+
 * </p>
 * 
 */
public class MSCAPICertificateStoreListing extends GenericCertificateStoreListing {

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        MSCAPICertificateStoreListing certificateStoreListing = new MSCAPICertificateStoreListing();
        certificateStoreListing.execute();
    }

    @Override
    protected IPKStoreManager getPKStoreManager() {
        try {
            return new MSCAPIStore(new DefaultPassStoreKS());
        } catch (CertStoreException e) {
        	fail("Error al crear el almacén " + e.getMessage());
            return null;
        }
    }

}
