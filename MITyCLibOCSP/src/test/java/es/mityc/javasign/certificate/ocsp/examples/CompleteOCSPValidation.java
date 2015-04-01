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
import java.util.Iterator;
import java.util.List;

import es.mityc.javasign.certificate.CertStatusException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.ICertStatusRecoverer;

/**
 * <p>
 * Clase de ejemplo para la validación de un certificado, y de toda la cadena de
 * certificación, contra un servidor OCSP utilizando la librería OCSP.
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
public class CompleteOCSPValidation extends BaseOCSPValidation {

    /**
     * <p>
     * Dirección del servidor OCSP a utilizar para realizar la validación
     * </p>
     */
    public final static String OCSP_RESPONDER = "";

    /**
     * <p>
     * Recurso que se corresponde con el certificado cuyo estado se desea
     * comprobar
     * </p>
     */
    public final static String CERTIFICATE_TO_CHECK = "/usr0061.cer";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        CompleteOCSPValidation completeOCSPValidation = new CompleteOCSPValidation();
        completeOCSPValidation.execute();
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
        List<ICertStatus> resultOCSPValidation = null;
        try {
            // Se realiza la consulta
            resultOCSPValidation = certStatusRecoverer.getCertChainStatus(certificate);
        } catch (CertStatusException e) {
            System.err.println("Error al comprobar el estado de la cadena del certificado");
            e.printStackTrace();
            System.exit(-1);
        }

        /*
         * En la primera posición de la lista tenemos el resultado del
         * certificado. En el resto de posiciones tenemos el resto de la cadena.
         * Todos los resultados deberíon ser correctos para que el certificado
         * pueda ser considerado correcto, aunque esto puede ser decision de la
         * política de cada uno
         */
        if (resultOCSPValidation != null && resultOCSPValidation.size() >= 1) {
            Iterator<ICertStatus> iterator = resultOCSPValidation.iterator();
            int i = 0;
            while (iterator.hasNext()) {
                ICertStatus certStatus = iterator.next();
                switch (certStatus.getStatus()) {
                case valid:
                    System.out.println("El certificado " + i + 
                            (i == 0 ? " (es decir, el original consultado)" : "") + 
                            " de la cadena es válido.");
                    break;
                case revoked:
                    System.out.println("El certificado " + i +
                            (i == 0 ? " (es decir, el original consultado)" : "") + 
                            " de la cadena fue revocado el " + 
                            certStatus.getRevokedInfo().getRevokedDate() + ".");
                    break;
                default:
                    System.out.println("Se desconoce el estado del certificado " + i + 
                            (i == 0 ? " (es decir, el original consultado)" : "") + 
                            " de la cadena.");
                    break;
                }
                i++;
            }
        } else {
            System.out.println("Hubo un error al contactar con el servidor OCSP " + getOCSPResponder());
        }
    }
}