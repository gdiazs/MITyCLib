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
import es.mityc.javasign.xades.examples.GenericXMLSignature;
import es.mityc.javasign.xml.refs.AllXMLToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * <p>
 * Clase de ejemplo para la firma XAdES-EPES enveloped de un documento. La
 * política a usar es la implícita, pero se especifica de forma explícita.
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
public class XAdESEPESSignature extends GenericXMLSignature {

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
    private final static String SIGN_FILE_NAME = "XAdES-EPES-Sign.xml";

    /**
     * <p>
     * Clave de la política que se desea aplicar. Dicha política debe estar
     * definida en el fichero <code>META-INF/xades/policy.properties</code>
     * </p>
     */
    private final static String POLICY_TO_APPLY = "implied";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        XAdESEPESSignature signature = new XAdESEPESSignature();
        signature.execute();
    }

    @Override
    protected DataToSign createDataToSign() {
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setPolicyKey(POLICY_TO_APPLY);
        dataToSign.setAddPolicy(true);
        dataToSign.setXMLEncoding("UTF-8");
        // Se añade un rol de firma
        dataToSign.addClaimedRol(new SimpleClaimedRole("Rol de firma"));
        dataToSign.setEnveloped(true);
        dataToSign.addObject(new ObjectToSign(new AllXMLToSign(), "Documento de ejemplo", null, "text/xml", null));
        Document docToSign = getDocument(RESOURCE_TO_SIGN);
        dataToSign.setDocument(docToSign);
        return dataToSign;
    }

    @Override
    protected String getSignatureFileName() {
        return SIGN_FILE_NAME;
    }
}
