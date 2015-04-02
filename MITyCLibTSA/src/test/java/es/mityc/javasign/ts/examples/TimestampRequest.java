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
package es.mityc.javasign.ts.examples;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;

import es.mityc.javasign.ssl.AllTrustedManager;
import es.mityc.javasign.ssl.SimpleSSLManager;
import es.mityc.javasign.ts.HTTPTimeStampGenerator;
import es.mityc.javasign.tsa.ITimeStampGenerator;
import es.mityc.javasign.tsa.TimeStampException;

/**
 * <p>
 * Ejemplo que muestra como pedir un sello de tiempo de unos datos determinados.
 * </p>
 * <p>
 * Para simplificar el código del programa se usan una serie constantes para su
 * configuración. Las constantes usadas, y que pueden ser modificadas según las
 * necesidades específicas, son las siguientes:
 * </p>
 * <ul>
 * <li><code>TSA_URL</code></li>
 * <li><code>ALGORITHM</code></li>
 * <li><code>DATA</code></li>
 * <li><code>SSL_AUTHENTICATION</code></li>
 * <li><code>PKCS12_RESOURCE</code></li>
 * <li><code>PKCS12_PASSWORD</code></li>
 * <li><code>USE_PROXY</code></li>
 * <li><code>IS_PROXY_AUTH</code></li>
 * <li><code>PROXY_USER</code></li>
 * <li><code>PROXY_PASSWORD</code></li>
 * <li><code>PROXY_SERVER</code></li>
 * <li><code>PROXY_PORT</code></li>
 * </ul>
 * <p>
 * El ejemplo, tal y como se distribuye, realiza una petición de sellado de
 * tiempo de los datos <code>DATA</code> a la TSA <code>TSA_URL</code>
 * utilizando el algoritmo <code>ALGORITHM</code>. No se usa ni proxy ni SSL.
 * </p>
 * 
 */
public class TimestampRequest {

    /**
     * <p>
     * URL donde escucha la TSA a la que se quiere realizar la petición.
     * </p>
     */
    public static final String TSA_URL = "";

    /**
     * <p>
     * Algoritmo del hash del sello de tiempo.
     * </p>
     */
    public static final String ALGORITHM = "SHA-1";

    /**
     * <p>
     * Datos de los que se quiere generar el sello de tiempo.
     * </p>
     */
    public static final byte[] DATA = new byte[512];

    /**
     * <p>
     * Si se necesita autenticación SSL basada en certificados para conectar con
     * la TSA
     * </p>
     */
    public static final Boolean SSL_AUTHENTICATION = false;

    /**
     * <p>
     * Recurso PKCS12 que contiene el certificado de identificación del usuario.
     * </p>
     */
    public final static String PKCS12_RESOURCE = "";
    
    /**
     * <p>Constraseña de acceso a la clave privada del usuario</p>
     */
    public final static String PKCS12_PASSWORD = "";
    
    /**
     * <p>Si se necesita o no usar proxy para ejecutar el ejemplo</p>
     */
    public final static Boolean USE_PROXY = false;

    /**
     * <p>Si el proxy es o no autenticado</p>
     */
    public final static Boolean IS_PROXY_AUTH = false;

    /**
     * <p>Usuario del proxy, para el caso de proxy autenticado</p>
     */
    public final static String PROXY_USER = "";

    /**
     * <p>Usuario del proxy, para el caso de proxy autenticado</p>
     */
    public final static String PROXY_PASSWORD = "";

    /**
     * <p>Host correspondiente al proxy, en el caso de que exista</p>
     */
    public final static String PROXY_SERVER ="";

    /**
     * <p>Puerto correspondiente al proxy, en el caso de que exista</p>
     */
    public final static Integer PROXY_PORT = null;

    /**
     * <p>
     * Punto de entrada al programa.
     * </p>
     * 
     * @param args
     *            Argumentos del programa.
     */
    public static void main(String[] args) {
        TimestampRequest timestampRequest = new TimestampRequest();
        timestampRequest.execute();
    }

    /**
     * <p>
     * Ejecución del ejemplo.
     * </p>
     */
    private void execute() {
        
        // Se configura la conexion
        configureConnection();
        
        // En el caso que sea necesario se prepara el cliente para SSL
        if (SSL_AUTHENTICATION) {
            prepareSSL();
        }

        // Instanciación del cliente
        ITimeStampGenerator cliente = new HTTPTimeStampGenerator(TSA_URL, ALGORITHM);

        // Obtención del resultado como array de bytes
        byte[] result = null;
        try {
            result = cliente.generateTimeStamp(DATA);
        } catch (TimeStampException e) {
            System.err.println("Error al generar el sello de tiempo");
            e.printStackTrace();
            return;
        }

        // Parseo del resultado como un TimeStampToken
        TimeStampToken timeStampToken;
        try {
            timeStampToken = new TimeStampToken(new CMSSignedData(result));
        } catch (TSPException e) {
            System.err.println("Error al parsear la respuseta");
            e.printStackTrace();
            return;
        } catch (IOException e) {
            System.err.println("Error al parsear la respuseta");
            e.printStackTrace();
            return;
        } catch (CMSException e) {
            System.err.println("Error al parsear la respuseta");
            e.printStackTrace();
            return;
        }

        // Impresion de resultados por salida estándar
        System.out.println("--------------------------------");
        System.out.println("-- TOKEN DE SELLADO DE TIEMPO --");
        System.out.println("--------------------------------");
        System.out.println("Número de serie del token: "
                + timeStampToken.getTimeStampInfo().getSerialNumber());
        System.out.println("Fecha generación del token: "
                + timeStampToken.getTimeStampInfo().getGenTime());
        System.out.println("OID política del token: "
                + timeStampToken.getTimeStampInfo().getPolicy());
        System.out.println("OID algoritmo de hash: "
                + timeStampToken.getTimeStampInfo().getMessageImprintAlgOID());
        System.out.println("");
        System.out.println("---------------------");
        System.out.println("-- TOKEN EN BASE64 --");
        System.out.println("---------------------");
        System.out.println(new String(Base64.encode(result)));
    }

    /**
     * Prepara el cliente de la TSA para poder establecer una conexión por SSL
     * con autenticación mediante certificados X509.
     */
    private void prepareSSL() {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(this.getClass().getResourceAsStream(PKCS12_RESOURCE), PKCS12_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, PKCS12_PASSWORD.toCharArray());
            HTTPTimeStampGenerator.setSSLManager(new SimpleSSLManager(new AllTrustedManager(), kmf.getKeyManagers()[0]));
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
        if(USE_PROXY) {
            System.setProperty("http.proxyHost", PROXY_SERVER);
            System.setProperty("http.proxyPort", Integer.toString(PROXY_PORT));
            if (IS_PROXY_AUTH) {
                Authenticator.setDefault(new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(PROXY_USER, PROXY_PASSWORD.toCharArray());
                    }
                });
            } else {
                Authenticator.setDefault(null);
            }
        }
    }

}
