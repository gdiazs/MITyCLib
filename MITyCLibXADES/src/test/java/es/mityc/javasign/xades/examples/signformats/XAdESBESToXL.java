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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Authenticator;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFirmaElectronica;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.DataToSign.XADES_X_TYPES;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.certificate.ocsp.OCSPLiveConsultant;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.trust.TrustFactory;
import es.mityc.javasign.ts.HTTPTimeStampGenerator;
import es.mityc.javasign.ts.TSPAlgoritmos;
import es.mityc.javasign.utils.SimpleAuthenticator;
import es.mityc.javasign.xades.examples.GenericXMLSignature;
import es.mityc.javasign.xml.xades.LocalFileStoreElements;

/**
 * <p>
 * Clase de ejemplo para el incremento del nivel de firma de una XAdES-BES enveloped.
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
public class XAdESBESToXL extends GenericXMLSignature {

    /**
     * <p>
     * Recurso a firmar
     * </p>
     */
    private final static String RESOURCE_TO_SIGN = "XAdES-BES-Sign.xml";

    /**
     * <p>
     * Fichero donde se desea guardar la firma
     * </p>
     */
    private final static String SIGN_FILE_NAME = "XAdES-XL-reSign.xml";
    /**
     * <p>
     * URL de una TSA para poder hacer el sellado de tiempo
     * </p>
     */
    private final static String URL_TSA = "http://minister-8jgxy9.mityc.age:41280/tsa";
    /**
     * <p>
     * URL de un OCSP para hacer las validaciones de los certificados
     * </p>
     */
    private final static String URL_OCSP = "http://ocsp.dnielectronico.es/";
    /**
     * <p>
     * Nombre del validador de confianza a utilizar
     * </p>
     */
    private final static String TRUSTER_NAME = "my";
    
    /**
     * <p>
     * URL del proxy, en caso de que sea necesario.
     * <p>
     */
    private final static String PROXY_URL = "proxy.mityc.age";
    
    /**
     * <p>
     * Puerto a atacar del proxy indicado.
     * <p>
     */
    private final static int PROXY_PORT = 80;
    
    /**
     * <p>
     * Usuario para autenticarse en el proxy.
     * </p>
     */
    private final static String PROXY_USER = "AdminDesarrollo";
    
    /**
     * <p>
     * Contraseña para autenticarse frente al proxy.
     * </p>
     */
    private final static String PROXY_PASS = "";
    
    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
    	// Se obtiene la firma XAdES a contrafirmar, resultado del proceso de firma de nivel XAdES-BES
    	File f = new File(RESOURCE_TO_SIGN);
    	if (f == null || !f.exists()) {
    		System.err.println("No se encuentra la firma a subir de nivel: " + f.getAbsolutePath()
    				+ "\nEjecute en primer lugar el ejemplo de firma de nivel XAdES-BES");
    		return;
    	}
        
        // Se contrafirma la firma previamente generada
        XAdESBESToXL levelRiser = new XAdESBESToXL();
        levelRiser.execute();
    }

    @Override
    protected DataToSign createDataToSign() {
        DataToSign dataToSign = new DataToSign();
        
        // Nivel de firma deseado
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_XL);
        dataToSign.setXAdESXType(XADES_X_TYPES.TYPE_1);
        
        // Condiciones de entorno
        dataToSign.setBaseURI("./");
        dataToSign.setXMLEncoding("UTF-8");
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setAlgDigestXmlDSig(UtilidadFirmaElectronica.DIGEST_ALG_SHA256);
        
        // Documento que contiene la firma a subir de nivel
        Document docToSign = getDocument(RESOURCE_TO_SIGN);
        dataToSign.setDocument(docToSign);
        
        // Generador de sellos de tiempo
        dataToSign.setTimeStampGenerator(new HTTPTimeStampGenerator(URL_TSA, TSPAlgoritmos.SHA1));
        
         // Validador de confianza de certificados
        TrustAbstract truster = TrustFactory.getInstance().getTruster(TRUSTER_NAME);
        if (truster == null) {
            System.out.println("No se ha encontrado el validador de confianza");
            System.exit(-1);
        }
        dataToSign.setCertStatusManager(new OCSPLiveConsultant(URL_OCSP, truster));
        
        // Handler de ficheros para firmas XAdES-C
        dataToSign.setElementsStorer(new LocalFileStoreElements());
        
        return dataToSign;
    }
    
    /**
     * <p>
     * Ejecución del ejemplo. La ejecución consistirá en la firma de los datos
     * creados por el método abstracto <code>createDataToSign</code> mediante el
     * certificado declarado en la constante <code>PKCS12_FILE</code>. El
     * resultado del proceso de firma será almacenado en un fichero XML en el
     * directorio correspondiente a la constante <code>OUTPUT_DIRECTORY</code>
     * del usuario bajo el nombre devuelto por el método abstracto
     * <code>getSignFileName</code>
     * </p>
     */
    @Override
    protected void execute() {
        /*
         * Creación del objeto que contiene tanto los datos a firmar como la
         * configuración del tipo de firma
         */
        DataToSign dataToSign = createDataToSign();
        
        // Se recupera la ID de la firma a subir de nivel
        Document doc = dataToSign.getDocument();
        NodeList list = doc.getElementsByTagNameNS(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_SIGNATURE);
        String id = null;
        if (list == null || list.getLength() < 1) {
        	System.out.println("No se pudo recuperar el Id de la firma a subir de nivel");
        	System.exit(-1);
        } else {
        	id = ((Element) list.item(0)).getAttribute("Id");
        }
        
        if (PROXY_URL != null) {
        	System.setProperty("http.proxyHost", PROXY_URL);
        	System.setProperty("http.proxyPort", Integer.toString(PROXY_PORT));
        	Authenticator.setDefault(new SimpleAuthenticator(PROXY_USER, PROXY_PASS));
        }

        // Firmamos el documento
        Document docSigned = null;
        try {
            FirmaXML firma = new FirmaXML();
            docSigned = firma.raiseLevel(
            		dataToSign,		// Configuración de firma
            		id);			// Identificador de la firma a subir de nivel
        } catch (Exception ex) {
            System.err.println("Error realizando la firma");
            ex.printStackTrace();
            return;
        }

        // Guardamos la firma a un fichero en el home del usuario
        String filePath = OUTPUT_DIRECTORY + File.separatorChar + SIGN_FILE_NAME;
        System.out.println("Firma salvada en en: " + filePath);
        saveDocumentToFile(docSigned, filePath);
    }

    /**
     * <p>
     * Devuelve el <code>Document</code> correspondiente al
     * <code>resource</code> pasado como parámetro
     * </p>
     * 
     * @param resource
     *            El recurso que se desea obtener
     * @return El <code>Document</code> asociado al <code>resource</code>
     */
    @Override
    protected Document getDocument(String resource) {
        Document doc = null;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        try {
            doc = dbf.newDocumentBuilder().parse(new FileInputStream(resource));
        } catch (ParserConfigurationException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (SAXException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IllegalArgumentException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        }
        return doc;
    }

	@Override
	protected String getSignatureFileName() {
		return File.separatorChar + SIGN_FILE_NAME;
	}
	
    /**
     * <p>
     * Escribe el documento a un fichero.
     * </p>
     * 
     * @param document
     *            El documento a imprmir
     * @param pathfile
     *            El path del fichero donde se quiere escribir.
     */
    private void saveDocumentToFile(Document document, String pathfile) {
        try {
            FileOutputStream fos = new FileOutputStream(pathfile);
            UtilidadTratarNodo.saveDocumentToOutputStream(document, fos, true);
        } catch (FileNotFoundException e) {
            System.err.println("Error al salvar el documento");
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
