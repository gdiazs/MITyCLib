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
package es.mityc.javasign.xades.examples.signtypes;

import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.xades.examples.GenericXMLSignature;
import es.mityc.javasign.xml.refs.InternObjectSignToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * <p>
 * Clase de ejemplo para la firma XAdES-BES enveloping de un documento. El
 * ejemplo firmará el recurso indicado en la constante
 * <code>RESOURCE_TO_SIGN</code> y el nombre del fichero resultante será el
 * indicado por la constante <code>SIGN_FILE_NAME</code>.
 * </p>
 * <p>
 * Para realizar la firma se utilizará el almacén PKCS#12 definido en la
 * constante <code>GenericXMLSignature.PKCS12_FILE</code>, al que se accederá
 * mediante la password definida en la constante
 * <code>GenericXMLSignature.PKCS12_PASSWORD</code>. El directorio donde quedará
 * el archivo XML resultante será el indicado en al constante
 * <code>GenericXMLSignature.OUTPUT_DIRECTORY</code>
 * </p>
 * </p>
 * 
 */
public class EnvelopingSignature extends GenericXMLSignature {

    /**
     * Recurso a firmar
     */
    private final static String RESOURCE_TO_SIGN = "/examples/ExampleToSign.xml";

    /**
     * <p>
     * Fichero donde se desea guardar la firma
     * </p>
     */
    private final static String SIGN_FILE_NAME = "Enveloping-Sign.xml";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        EnvelopingSignature signature = new EnvelopingSignature();
        signature.execute();

    }

    @Override
    protected DataToSign createDataToSign() {
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setXMLEncoding("UTF-8");
        dataToSign.setEnveloped(false);
        InternObjectSignToSign objectToSign = new InternObjectSignToSign();
        objectToSign.setData(getDocument(RESOURCE_TO_SIGN).getDocumentElement());
        dataToSign.addObject(new ObjectToSign(objectToSign, "Documento de ejemplo", null, "text/xml", null));
        return dataToSign;
    }

    @Override
    protected String getSignatureFileName() {
        return SIGN_FILE_NAME;
    }

}
