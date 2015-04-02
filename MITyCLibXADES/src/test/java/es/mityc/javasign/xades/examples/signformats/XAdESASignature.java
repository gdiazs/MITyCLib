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
package es.mityc.javasign.xades.examples.signformats;

import org.w3c.dom.Document;

import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.role.SimpleClaimedRole;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.certificate.ocsp.OCSPLiveConsultant;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.trust.TrustFactory;
import es.mityc.javasign.xades.examples.GenericXMLSignature;
import es.mityc.javasign.xml.refs.InternObjectToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * <p>
 * Clase de ejemplo para la firma XAdES-A sobre una firma XAdES-BES enveloped de
 *  un documento
 * </p>
 * <p>
 * Para realizar la firma se utilizará el almacén PKCS#12 definido en la
 * constante <code>GenericXMLSignature.PKCS12_FILE</code>, al que se accederá
 * mediante la password definida en la constante
 * <code>GenericXMLSignature.PKCS12_PASSWORD</code>. El directorio donde quedará
 * el archivo XML resultante será el indicado en al constante
 * <code>GenericXMLSignature.OUTPUT_DIRECTORY</code>
 * </p>
 * 
 */
public class XAdESASignature extends GenericXMLSignature {

    /**
     * <p>
     * Recurso a firmar
     * </p>
     */
    private final static String RESOURCE_TO_SIGN = "/examples/ExampleToSign.xml";

    /**
     * <p>
     * Fichero donde se desea guardar la firma
     * </p>
     */
    private final static String SIGN_FILE_NAME = "XAdES-A-Sign.xml";

    /**
     * <p>
     * URL de una TSA para poder hacer el sellado de tiempo
     * </p>
     */
    private final static String URL_TSA = "http://localhost:41280/tsa";

    /**
     * <p>
     * URL de un OCSP para hacer las validaciones de los certificados
     * </p>
     */
    private final static String URL_OCSP = "http://ocsp.ctpa.mityc.es";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        XAdESASignature signature = new XAdESASignature();
        signature.execute();
    }

    @Override
    protected DataToSign createDataToSign() {
        DataToSign dataToSign = new DataToSign();
        // Se instancia el truster a emplear en la validación
        TrustFactory tf = TrustFactory.getInstance();
		TrustAbstract truster = tf.getTruster("mityc");
        // Se establece el validador OCSP a utilizar
        dataToSign.setCertStatusManager(new OCSPLiveConsultant(URL_OCSP, truster));
        // Se establece el nivel de firma
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_XL);
        // Se indica el esquema XAdES a utilizar
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        // Se establece la codificación más generica para buscar interoperabilidad
        dataToSign.setXMLEncoding("UTF-8");
        // Se añade un rol de firma
        dataToSign.addClaimedRol(new SimpleClaimedRole("Rol de firma"));
        // Se configura la firma para realizar firma envuelta (el XML a firmar contiene a la firma)
        dataToSign.setEnveloped(true);
        // Se indican los nodos a firmar
        dataToSign.addObject(new ObjectToSign(new InternObjectToSign("titulo"), "Documento de ejemplo", null, "text/xml", null));
        dataToSign.setParentSignNode("titulo");

        Document docToSign = getDocument(RESOURCE_TO_SIGN);
        dataToSign.setDocument(docToSign);
        return dataToSign;
    }

    @Override
    protected String getSignatureFileName() {
        return SIGN_FILE_NAME;
    }
}
