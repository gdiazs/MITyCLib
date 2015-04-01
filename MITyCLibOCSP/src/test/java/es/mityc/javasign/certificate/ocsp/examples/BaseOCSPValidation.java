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
import java.io.InputStream;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import es.mityc.javasign.certificate.ICertStatusRecoverer;
import es.mityc.javasign.certificate.ocsp.OCSPLiveConsultant;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.trust.TrustFactory;

/**
 * <p>
 * Clase base de ejemplo para la validación de un certificado contra un servidor
 * OCSP
 * </p>
 * <p>
 * Para simplificar el código del programa se usan una serie constantes para la
 * configuración de la conexión a utilizar. Las constantes usadas, y que pueden
 * ser modificadas según las necesidades específicas, son las siguientes:
 * </p>
 * <ul>
 * <li><code>TRUSTER_NAME</code></li>
 * <li><code>USE_PROXY</code></li>
 * <li><code>IS_PROXY_AUTH</code></li>
 * <li><code>PROXY_USER</code></li>
 * <li><code>PROXY_PASSWORD</code></li>
 * <li><code>PROXY_SERVER</code></li>
 * <li><code>PROXY_PORT</code></li>
 * </ul>
 * <p>
 * 
 */

public abstract class BaseOCSPValidation {

    /**
     * <p>
     * Nombre del validador de confianza a utilizar
     * </p>
     */
    public final static String TRUSTER_NAME = "my";
    

    /**
     * <p>
     * Si se necesita o no usar proxy para ejecutar el ejemplo
     * </p>
     */
    public final static Boolean USE_PROXY = false;

    /**
     * <p>
     * Si el proxy es o no autenticado
     * </p>
     */
    public final static Boolean IS_PROXY_AUTH = false;

    /**
     * <p>
     * Usuario del proxy, para el caso de proxy autenticado
     * </p>
     */
    public final static String PROXY_USER = "";

    /**
     * <p>
     * Usuario del proxy, para el caso de proxy autenticado
     * </p>
     */
    public final static String PROXY_PASSWORD = "";

    /**
     * <p>
     * Host correspondiente al proxy, en el caso de que exista
     * </p>
     */
    public final static String PROXY_SERVER = "";

    /**
     * <p>
     * Puerto correspondiente al proxy, en el caso de que exista
     * </p>
     */
    public final static Integer PROXY_PORT = null;

    /**
     * <p>
     * Método abstracto que deberán implementar los ejemplos finales que
     * devuelve el recurso asociado al certificado que se desea comprobar.
     * </p>
     * 
     * @param certificate
     *            Certificado a valdiar
     * @param ocspServer
     *            Servidor OCSP a utilizar
     */
    protected abstract String getCertificateToCheck();

    /**
     * <p>
     * Método abstracto que deberán implementar los ejemplos finales que realizan
     * la validacion OCSP que devuelve el OCSP responder a utilizar
     * </p>
     */
    protected abstract String getOCSPResponder();

    /**
     * <p>
     * Método abstracto que deberán implementar los ejemplos finales que realiza
     * la validación OCSP del certificado X509 <code>certificate</code> 
     * utilizando el recuperador de estados de certificados 
     * <code>certStatusRecoverer</code>. El método debería imprimir por salida 
     * estándar el resultado de dicha validación.
     * </p>
     * 
     * @param certificate
     *            Certificado X509 a valdiar
     * @param certStatusRecoverer
     *            Recuperador de estados de certificados
     */
    protected abstract void doOCSPValidation(X509Certificate certificate, ICertStatusRecoverer certStatusRecoverer);

    /**
     * <p>
     * Ejecución del ejemplo.
     * </p>
     */
    protected void execute() {
        try {

            // Se configura la conexion a utilizar
            configureConnection();

            // Se obtiene el recurso a comprobar
            String certificateToCheck = getCertificateToCheck();

            // Se obtiene el certificado X509 asociado al recurso
            X509Certificate cert = getX509CertificateFromResource(certificateToCheck);

            // Se obtiene el servidor contra el que se desea realizar la validación
            String ocspServer = getOCSPResponder();

            // Se obtiene el validador de confianza de certificados
            TrustAbstract truster = TrustFactory.getInstance().getTruster(TRUSTER_NAME);
            if (truster == null) {
                System.out.println("No se ha encontrado el validador de confianza por lo que el ejemplo no se puede ejecutar");
                return;
            }

            // Se instancia la clase OCSPLiveConsultant a partir del servidor OCSP y del validador de confianza
            ICertStatusRecoverer certStatusRecoverer = new OCSPLiveConsultant(ocspServer, truster);
            
            // Mostramos el resultado por consola
            System.out.println("---------------------------");
            System.out.println("------- RESULTADO ---------");
            System.out.println("---------------------------");

            doOCSPValidation(cert, certStatusRecoverer);

        } catch (CertificateException e) {
            e.printStackTrace();
            return;
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
    }

    /**
     * </p>Método para obtener un certificado a partir de un recurso.</p>
     * 
     * @param certificateResource
     *            El recurso asociado al certificado
     * @return El certificado de tipo X509Certificate
     * @throws CertificateException
     *             Si ocurre algún error con el certificado
     * @throws IOException
     *             Si ocurre algún error de entrada/salida
     */
    private X509Certificate getX509CertificateFromResource(
            String certificateResource) throws CertificateException,
            IOException {

        X509Certificate cert = null;

        InputStream is = this.getClass().getResourceAsStream(certificateResource);
        CertificateFactory cf;

        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(is);
        is.close();

        // Mostramos algunos datos del certificado por consola
        System.out.println("-----------------------------");
        System.out.println("-- CERTIFICADO A COMPROBAR --");
        System.out.println("-----------------------------");
        System.out.println("Emisor: " + cert.getIssuerDN());
        System.out.println("Número de serie: " + cert.getSerialNumber());
        System.out.println("Válido a partir del: " + cert.getNotBefore());
        System.out.println("Válido hasta: " + cert.getNotAfter());

        return cert;
    }

    /**
     * <p>
     * Método para configurar la conexión a utilizar según el valor de las
     * constantes declaradas en la clase
     * </p>
     * <p>
     * Las posibles configuraciones son las siguientes:
     * </p>
     * <ul>
     * <li>Proxy</li>
     * <li>Proxy autenticado</li>
     * <li>Conexión directa</li>
     * </ul>
     */
    private void configureConnection() {
        if (USE_PROXY) {
            System.setProperty("http.proxyHost", PROXY_SERVER);
            System.setProperty("http.proxyPort", Integer.toString(PROXY_PORT));
            if (IS_PROXY_AUTH) {
                Authenticator.setDefault(new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(PROXY_USER,
                                PROXY_PASSWORD.toCharArray());
                    }
                });
            } else {
                Authenticator.setDefault(null);
            }
        }
    }
}