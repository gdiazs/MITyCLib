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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;

import es.mityc.firmaJava.ocsp.OCSPCliente;
import es.mityc.javasign.certificate.CertStatusException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.ICertStatusRecoverer;
import es.mityc.javasign.ssl.AllTrustedManager;
import es.mityc.javasign.ssl.SimpleSSLManager;

/**
 * <p>
 * Clase de ejemplo para la validación básica (es decir, sólo se valida el
 * certificado, no toda la ruta de certificación) de un certificado contra un
 * servidor OCSP utilizando la librería OCSP.
 * </p>
 * <p>
 * La configuración de la red a utilizar (si se usa proxy o no) vienen dados por
 * las constantes definidas en la clase padre <code>BaseOCSPValidation</code>
 * </p>
 * <p>
 * La configuración del certificado a validar y el OCSP a utilizar, para
 * simplificar el código del programa, viene dado por una serie de constantes.
 * Las constantes usadas, y que pueden ser modificadas según las necesidades
 * específicas, son las siguientes:
 * </p>
 * <ul>
 * <li><code>OCSP_RESPONDER</code></li>
 * <li><code>CERTIFICATE_TO_CHECK</code></li>
 * </ul>
 * 
 */
public class AuthBasicOCSPValidation extends BaseOCSPValidation {

    /**
     * <p>
     * Dirección del servidor OCSP a utilizar para realizar la validación
     * </p>
     */
    public final static String OCSP_SERVER = "https://ocsp.dnielectronico.es/";//"https://ocsp.quovadisoffshore.com/";//"http://ocsp.dnie.es/";//"http://ocsp.ctpa.mityc.es";//"https://globus-grid.certiver.com ";

    /**
     * Lista de OCSPs bajo SSL
     * 
     * https://ocsp.dnie.es/
     * https://pki.pinkroccade.com/
     * https://www.d-trust.net/internet/content/d-trust-roots.html
     * https://europki.iaik.at/
     * https://www.si-ca.org
     * https://www.certum.pl
     * https://ca.notariato.it/
     * https://globus-grid.certiver.com
     * http://ocsp.digsigtrust.com:80/
     * http://ocsp.verisign.com
     * http://onsite-ocsp.verisign.com
     */
    
    /**
     * <p>
     * Recurso que se corresponde con el certificado cuyo estado se desea
     * comprobar
     * </p>
     */
    public final static String CERTIFICATE_TO_CHECK = "/keystores/usr0061.cer";
    
    /**
     * <p>
     * Si se necesita autenticación SSL basada en certificados para conectar con
     * el OCSP
     * </p>
     */
    public static final Boolean SSL_AUTHENTICATION = true;
    
    /**
     * <p>
     * Recurso PKCS12 que contiene el certificado de identificación del usuario.
     * </p>
     */
    public final static String PKCS12_RESOURCE = "/keystores/usr0061.p12";
    
    /**
     * <p>Constraseña de acceso a la clave privada del usuario</p>
     */
    public final static String PKCS12_PASSWORD = "usr0061";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
    	AuthBasicOCSPValidation authOCSPValidation = new AuthBasicOCSPValidation();
        authOCSPValidation.execute();
    }

    @Override
    protected String getCertificateToCheck() {
        return CERTIFICATE_TO_CHECK;
    }

    @Override
    protected String getOCSPResponder() {
        return OCSP_SERVER;
    }

    @Override
    protected void doOCSPValidation(X509Certificate certificate,
    		ICertStatusRecoverer certStatusRecoverer) {

        // Estructura que almacenará la respuesta del servidor OCSP
        ICertStatus resultOCSPValidation = null;

        try {
            // Se realiza la consulta
            resultOCSPValidation = certStatusRecoverer.getCertStatus(certificate);

        } catch (CertStatusException e) {
        	 System.err.println("Error en la comprobación del estado del certificado");
             e.printStackTrace();
             throw new RuntimeException(e);
		}

        if (resultOCSPValidation != null) {
        	ICertStatus.CERT_STATUS respuesta = resultOCSPValidation.getStatus();
            switch (respuesta) {
            case valid:
                System.out.println("El certificado consultado es válido.");
                break;
            case revoked:
                System.out.println("El certificado consultado fue revocado el " + 
                        resultOCSPValidation.getRevokedInfo().getRevokedDate() + ".");
                break;
            default:
                System.out.println("Se desconoce el estado del certificado.");
            }
        } else {
            System.out.println("Hubo un error al contactar con el servidor OCSP");
        }
    }
    
    /**
     * Prepara una conexión por SSL
     * con autenticación mediante certificados X509.
     */
    private void prepareSSL() {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(this.getClass().getResourceAsStream(PKCS12_RESOURCE), PKCS12_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, PKCS12_PASSWORD.toCharArray());
            OCSPCliente.setSSLManager(new SimpleSSLManager(new AllTrustedManager(), kmf.getKeyManagers()[0]));
        } catch (CertificateException e) {
            System.out.println("Error al establecer la configuración de seguridad de la comunicación con la TSA.");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            System.out.println("Error al establecer la configuración de seguridad de la comunicación con la TSA.");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error al establecer la configuración de seguridad de la comunicación con la TSA.");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IOException e) {
            System.out.println("Error al establecer la configuración de seguridad de la comunicación con la TSA.");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            System.out.println("Error al establecer la configuración de seguridad de la comunicación con la TSA.");
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
