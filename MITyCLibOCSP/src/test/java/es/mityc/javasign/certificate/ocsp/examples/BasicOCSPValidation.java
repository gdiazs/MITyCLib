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

import java.security.cert.X509Certificate;

import es.mityc.javasign.certificate.CertStatusException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.ICertStatusRecoverer;

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
public class BasicOCSPValidation extends BaseOCSPValidation {

    /**
     * <p>
     * Dirección del servidor OCSP a utilizar para realizar la validación
     * </p>
     */
    private final static String OCSP_RESPONDER = "";

    /**
     * <p>
     * Recurso que se corresponde con el certificado cuyo estado se desea
     * comprobar
     * </p>
     */
    private final static String CERTIFICATE_TO_CHECK = "/usr0061.cer";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        BasicOCSPValidation basicOCSPValidation = new BasicOCSPValidation();
        basicOCSPValidation.execute();
    }

    @Override
    protected String getCertificateToCheck() {
        return CERTIFICATE_TO_CHECK;
    }

    @Override
    protected String getOCSPResponder() {
        return OCSP_RESPONDER;
    }

    @Override
    protected void doOCSPValidation(X509Certificate certificate, 
            ICertStatusRecoverer certStatusRecoverer) {

        // Estructura que almacenará la respuesta del servidor OCSP
        ICertStatus certStatus = null;
            // Se realiza la consulta
        try {
        	certStatus = certStatusRecoverer.getCertStatus(certificate);
        } catch (CertStatusException e) {
            System.err.println("Error al comprobar el estado del certificado");
            e.printStackTrace();
            System.exit(-1);
        }
        
        if (certStatus != null) {
            switch (certStatus.getStatus()) {
            case valid:
                System.out.println("El certificado consultado es válido.");
                break;
            case revoked:
                System.out.println("El certificado consultado fue revocado el " + 
                certStatus.getRevokedInfo().getRevokedDate() + ".");
                break;
            default:
                System.out.println("Se desconoce el estado del certificado.");
            }
        } else {
            System.out.println("Hubo un error al contactar con el servidor OCSP " + getOCSPResponder());
        }
    }
}