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
package es.mityc.javasign.pkstore.examples;

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;

/**
 * <p>
 * Clase base que deberían extender los diferentes ejemplos para listar
 * almacenes de certificados.
 * </p>
 * 
 */
public abstract class GenericCertificateStoreListing {

    /**
     * <p>
     * Método abstracto que deberan implementar los ejemplos finales que
     * devuelve una implementación concreta de <code>IPKStoreManager</code>.
     * </p>
     * 
     * @return Una implementación concreta de <code>IPKStoreManager</code>
     * @throws CertStoreException Lanzada si no se puede acceder al almacén de certificados
     */
    protected abstract IPKStoreManager getPKStoreManager() throws CertStoreException;

    /**
     * <p>
     * Ejecución del ejemplo. Realiza un listado del almacen de certificados
     * determinado por salida estándar
     * </p>
     */
    public void execute() {

        // Obtenemos el PKStoreManager
    	IPKStoreManager pkStoreManager = null;
        try {
            pkStoreManager = getPKStoreManager();
        } catch (CertStoreException e) {
            System.err.println("Error al acceder al almacén de certificados: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Imprimimos los certificados de firma por consola
        System.out.println("---------------------------");
        System.out.println("-- CERTIFICADOS DE FIRMA --");
        System.out.println("---------------------------");
        List<X509Certificate> signCertificates;
        try {
            signCertificates = pkStoreManager.getSignCertificates();
        } catch (CertStoreException e) {
            System.err.println("Error al acceder al almacén de certificados: " + e.getMessage());
            e.printStackTrace();
            return;
        }
        printCertificates(signCertificates);

        // Imprimimos los certificados de confianza por consola
        System.out.println("-------------------------------");
        System.out.println("-- CERTIFICADOS DE CONFIANZA --");
        System.out.println("-------------------------------");
        List<X509Certificate> trustCertificates;
        try {
            trustCertificates = pkStoreManager.getTrustCertificates();
       } catch (CertStoreException e) {
            System.err.println("Error al acceder al almacén de certificados");
            e.printStackTrace();
            return;
        } catch (UnsupportedOperationException e) {
            System.out.println("No se soporta la obtención de certificados de confianza para este tipo de almacén");
            return;
        }
        printCertificates(trustCertificates);

    }

    /**
     * <p>
     * Método para imprimir una lista de certificados por salida estándar.
     * </p>
     * 
     * @param certificates
     *            Listado de certificados a imprimir
     */
    private void printCertificates(List<X509Certificate> certificates) {
        if (certificates.isEmpty()) {
            System.out.println("No existen certificados");
            System.out.println("");
        } else {
            Iterator<X509Certificate> iteratorCertificates = certificates.iterator();
            while (iteratorCertificates.hasNext()) {
                X509Certificate certificate = (X509Certificate) iteratorCertificates.next();
                printCertificate(certificate);
                System.out.println("");
            }
        }
    }

    /**
     * <p>
     * Método para imprimir un certificado por salida estándar.
     * </p>
     * 
     * @param certificate
     *            Certificado a imprimir
     */
    private void printCertificate(X509Certificate certificate) {
        System.out.println("Propietario: " + certificate.getSubjectX500Principal().getName());
        System.out.println("Emisor: " + certificate.getIssuerX500Principal().getName());
        System.out.println("Número de serie: " + certificate.getSerialNumber());
        System.out.println("Válido a partir del: " + certificate.getNotBefore());
        System.out.println("Válido hasta: " + certificate.getNotAfter());
    }
}
