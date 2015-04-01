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
package es.mityc.javasign.pkstore.mscapi.mityc;

import static org.junit.Assert.fail;

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;

import org.junit.Ignore;
import org.junit.Test;

import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.StoreTests;

/**
 * <p>Tests de funcionamiento de las operaciones sobre el almacén de IExplorer.</p>
 * <p>Requisitos:<ul>
 *  <li>tener cargado el certificado de test Usr0061.p12 en el almacén de certificados windows MY del usuario actual (current user) donde se lanza el test.</li>
 *  <li>tener cargado el certificado de test Usr0061.p12 en el almacén de certificados windows MY de la máquina local (local machine) donde se lanza el test.</li>
 * </ul>
 * </p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class TestMSCAPIMITyC extends StoreTests {
	
	/**
	 * <p>Comprueba el acceso de los certificados del almacén de Windows para el usuario actual.</p>
	 */
	@Test
	public void testGetCertificates() {
		IPKStoreManager sm = null;
		try {
			sm = new MSCAPIMITyCStore(null);
		} catch (CertStoreException ex) {
			fail("No se pudo obtener acceso al almacén: " + ex.getMessage());
		}
		X509Certificate cert = getCertificate(sm);
		if (cert == null) {
			fail("No se pudo obtener un certificado del almacén");
		}
	}
	
    /**
     * <p>Comprueba el acceso de los certificados del almacén de Windows para la máquina local.</p>
     */
    @Test
    public void testGetCertificatesLocalMachine() {
        IPKStoreManager sm = null;
        try {
            sm = new MSCAPIMITyCStore(null, MSCAPIMITyCStore.LocationStoreType.LocalMachine);
        } catch (CertStoreException ex) {
            fail("No se pudo obtener acceso al almacén: " + ex.getMessage());
        }
        X509Certificate cert = getCertificate(sm);
        if (cert == null) {
            fail("No se pudo obtener un certificado del almacén");
        }
    }
    
	/**
	 * <p>Comprueba que se puede firmar mediante el almacén de Windows.</p>
	 */
	@Test
	public void sign() {
		IPKStoreManager sm = null;
		try {
			sm = new MSCAPIMITyCStore(null);
		} catch (CertStoreException ex) {
			fail("No se pudo obtener acceso al almacén: " + ex.getMessage());
		}
		X509Certificate testCert = loadCertificate(this.getClass().getResourceAsStream("/keystores/usr0061.cer"));
		if (testCert == null) {
			fail("El certificado us0032 no está disponible en el almacén. Este test necesita que se importe el certificado en el MY" +
				 " del almacén de windows para poder ejecutarse");
		}
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(testCert);
		checkSign(sm);
	}

	/**
     * <p>Lista todos los certificados del almacén de la máquina local por la salida estandar.</p>
     */
	@Ignore @Test
    public void testListSignCertificatesLocalMachine() {
        IPKStoreManager sm = null;
        try {
            sm = new MSCAPIMITyCStore(null, MSCAPIMITyCStore.LocationStoreType.LocalMachine);
        } catch (CertStoreException ex) {
            fail("No se pudo obtener acceso al almacén: " + ex.getMessage());
        }
        System.out.println("----------------------------------------------");
        System.out.println("-- Certificados de firma para local machine --");
        System.out.println("----------------------------------------------");
        listSignCertificates(sm, System.out);
    }

    /**
     * <p>Lista todos los certificados del almacén del usuario actual por la salida estandar.</p>
     */
    @Ignore @Test
    public void testListSignCertificatesCurrentUser() {
        IPKStoreManager sm = null;
        try {
            sm = new MSCAPIMITyCStore(null, MSCAPIMITyCStore.LocationStoreType.CurrentUser);
        } catch (CertStoreException ex) {
            fail("No se pudo obtener acceso al almacén: " + ex.getMessage());
        }
        System.out.println("---------------------------------------------");
        System.out.println("-- Certificados de firma para current user --");
        System.out.println("---------------------------------------------");
        listSignCertificates(sm, System.out);
    }

    /**
     * <p>Lista todos los certificados de confianza del almacen de la máquina local por la salida estandar.</p>
     */
    @Ignore @Test
    public void testListTrustCertificatesLocalMachine() {
        IPKStoreManager sm = null;
        try {
            sm = new MSCAPIMITyCStore(null, MSCAPIMITyCStore.LocationStoreType.LocalMachine);
        } catch (CertStoreException ex) {
            fail("No se pudo obtener acceso al almacén: " + ex.getMessage());
        }
        System.out.println("--------------------------------------------------");
        System.out.println("-- Certificados de confianza para local machine --");
        System.out.println("--------------------------------------------------");
        listTrustCertificates(sm, System.out);
    }

    /**
     * <p>Lista todos los certificados de confianza del almacen de la máquina local por la salida estandar.</p>
     */
    @Ignore @Test
    public void testListTrustCertificatesCurrentUser() {
        IPKStoreManager sm = null;
        try {
            sm = new MSCAPIMITyCStore(null, MSCAPIMITyCStore.LocationStoreType.CurrentUser);
        } catch (CertStoreException ex) {
            fail("No se pudo obtener acceso al almacén: " + ex.getMessage());
        }
        System.out.println("-------------------------------------------------");
        System.out.println("-- Certificados de confianza para current user --");
        System.out.println("-------------------------------------------------");
        listTrustCertificates(sm, System.out);
    }
}
