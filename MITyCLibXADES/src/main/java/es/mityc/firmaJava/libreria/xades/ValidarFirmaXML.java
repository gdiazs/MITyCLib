/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES".
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
package es.mityc.firmaJava.libreria.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import adsi.org.apache.xml.security.Init;
import adsi.org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import adsi.org.apache.xml.security.exceptions.XMLSecurityException;
import adsi.org.apache.xml.security.signature.Reference;
import adsi.org.apache.xml.security.signature.SignedInfo;
import adsi.org.apache.xml.security.signature.XMLSignature;
import adsi.org.apache.xml.security.signature.XMLSignatureException;
import adsi.org.apache.xml.security.signature.XMLSignatureInput;
import adsi.org.apache.xml.security.transforms.Transforms;
import adsi.org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.Base64;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.utilidades.I18n;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.utilidades.URIEncoder;
import es.mityc.firmaJava.libreria.utilidades.UtilidadCertificados;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFechas;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFicheros;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFirmaElectronica;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.utilidades.Utilidades;
import es.mityc.firmaJava.libreria.xades.elementos.xades.Cert;
import es.mityc.firmaJava.libreria.xades.elementos.xades.CertificateValues;
import es.mityc.firmaJava.libreria.xades.elementos.xades.DataObjectFormat;
import es.mityc.firmaJava.libreria.xades.elementos.xades.EncapsulatedX509Certificate;
import es.mityc.firmaJava.libreria.xades.elementos.xades.EncodingEnum;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SignaturePolicyIdentifier;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SigningTime;
import es.mityc.firmaJava.libreria.xades.errores.BadFormedSignatureException;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;
import es.mityc.firmaJava.ocsp.ConstantesOCSP;
import es.mityc.firmaJava.ocsp.RespuestaOCSP;
import es.mityc.firmaJava.trust.ConfianzaEnum;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.ConstantsXAdES;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.asn1.ASN1Utils;
import es.mityc.javasign.certificate.CertStatusException;
import es.mityc.javasign.certificate.ElementNotFoundException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.ICertStatus.CERT_STATUS;
import es.mityc.javasign.certificate.ICertStatusRecoverer;
import es.mityc.javasign.certificate.IOCSPCertStatus;
import es.mityc.javasign.certificate.IRecoverElements;
import es.mityc.javasign.certificate.OCSPResponderID;
import es.mityc.javasign.certificate.RevokedInfo;
import es.mityc.javasign.certificate.UnknownElementClassException;
import es.mityc.javasign.certificate.ocsp.OCSPStatus;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.trust.NotTrustedException;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.trust.TrustException;
import es.mityc.javasign.trust.UnknownTrustException;
import es.mityc.javasign.ts.TSPAlgoritmos;
import es.mityc.javasign.ts.TimeStampValidator;
import es.mityc.javasign.tsa.ITimeStampValidator;
import es.mityc.javasign.tsa.TSValidationResult;
import es.mityc.javasign.tsa.TimeStampException;
import es.mityc.javasign.xml.resolvers.IPrivateData;
import es.mityc.javasign.xml.resolvers.IResourceData;
import es.mityc.javasign.xml.resolvers.MITyCResourceResolver;
import es.mityc.javasign.xml.resolvers.ResolverPrivateData;
import es.mityc.javasign.xml.resolvers.XAdESResourceResolverSpi;
import es.mityc.javasign.xml.xades.LocalFileStoreElements;
import es.mityc.javasign.xml.xades.ReferenceProxy;
import es.mityc.javasign.xml.xades.policy.IValidacionPolicy;
import es.mityc.javasign.xml.xades.policy.PoliciesManager;
import es.mityc.javasign.xml.xades.policy.PoliciesManager.PolicyKey;
import es.mityc.javasign.xml.xades.policy.PolicyResult;
import es.mityc.javasign.xml.xades.policy.PolicyResult.StatusValidation;

/**
 * Clase para la validación de la firmas XADES en los esquemas 1.1.1, 1.2.2, y 1.3.2
 *
 */
public class ValidarFirmaXML { // implements ConstantesXADES
	private List<String>			esquemasParaValidar		= 	new LinkedList<String>();

	private boolean 				esValido				= 	false;
	private ResultadoValidacion 	resultado				= 	new ResultadoValidacion();
	private DatosFirma 				datosFirma				=	null;
	private ArrayList<DatosSelloTiempo> arrayDatosSello		=   null;
	private ArrayList<DatosCRL>		arrayDatosCRL			=	null;
	private ArrayList<DatosOCSP> 	arrayDatosOCSP			=	null;
	private ArrayList<PolicyResult> politicas 				= 	new ArrayList<PolicyResult> ();
	private ArrayList<X509Certificate> cadenaCertificados	=	new ArrayList<X509Certificate> ();
	private ArrayList<String> 		firmados				= 	null;

	private DatosTipoFirma			tipoDocFirma			= 	null;

	private String 					uriXmlNS 				= 	null;
	
	private String					nombreNodoUri			=	ConstantesXADES.INCLUDE;
	private String					tipoUri					=	ConstantesXADES.URI_MAYUS;

	private static final Log LOGGER = LogFactory.getLog(ValidarFirmaXML.class);
    private static final II18nManager i18n = I18nFactory.getI18nManager(ConstantsXAdES.LIB_NAME);
    
    private IRecoverElements recoverManager = null;
    private ArrayList<ResourceResolverSpi> resolvers = null;
    private ITimeStampValidator tsValidator = null;
    private TrustAbstract truster = null;

    private static final String TSA_REVOCKED = "i18n.mityc.xades.validate.tsa.error.1";
    private static final String TSA_REVOCKED_NO_DATE = "i18n.mityc.xades.validate.tsa.error.2";
    private static final String OCSP_REVOCKED = "i18n.mityc.xades.validate.ocsp.error.1";
    private static final String OCSP_REVOCKED_NO_DATE = "i18n.mityc.xades.validate.ocsp.error.2";
    
	protected class EstructuraFirma {
		XAdESSchemas esquema;
		Element firma;
		Element signedSignatureProperties;
		Element unsignedSignatureProperties; // Puede ser nulo
		XMLSignature xmlSig;
	}

	/**
	 * Crea una nueva instancia de ValidarFirmaXML
	 */
	public ValidarFirmaXML() {
		// Activa la validación de las tres versiones de XAdES
		setXAdESSchema(XAdESSchemas.XAdES_111, true);
		setXAdESSchema(XAdESSchemas.XAdES_122, true);
		setXAdESSchema(XAdESSchemas.XAdES_132, true);
		setXAdESSchema(XAdESSchemas.XMLDSIG, true);
	}

	/**
	 * Establece cuál será el encargado de gestionar la obtención de los elementos externos de la firma relacionados con certificados
	 * y estados de certificados
	 * 
	 * @param recoverManager
	 */
	public void setRecoverElements(IRecoverElements recoverManager) {
		this.recoverManager = recoverManager;
	}
	
	/**
	 * Añade una instancia encargada de resolver los accesos a elementos firmados en la firma cuyo contenido es privado.
	 *  
	 * @param resolver objeto que implementa la interfaz IPrivateDate para el acceso a elementos privados
	 */
	public void addResolver(IPrivateData resolver) {
		addResolver(new ResolverPrivateData(resolver));
	}
	
	/**
	 * Añade una instancia encargada de resolver accesos a información.
	 * 
	 * @param resolver resolver
	 */
	public void addResolver(MITyCResourceResolver resolver) {
		if (resolvers == null) {
			resolvers = new ArrayList<ResourceResolverSpi>();
		}
		resolvers.add(resolver);
	}
	
	/**
	 * Añade una instancia encargada de resolver los accesos a elementos firmados en la firma que requieran un acceso especial.
	 *  
	 * @param resolver objeto que implementa la interfaz IResourceData para el acceso a elementos
	 */
	public void addResolver(IResourceData resolver) {
		addResolver(new XAdESResourceResolverSpi(resolver));
	}

	/**
	 * Valida la firma XML
	 * @param firmaParaValidar fichero con la firma XADES para validar
	 * @param validators lista de validadores de policies que se aplicarán en la validación (<code>null</code> si no hay policies a aplicar).
	 * @param tsValidator validador de sellos de tiempo
	 * @return List<ResultadoValidacion> lista de resultados de validación, que indican si las firmas son válidas o no, y en este último caso indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public List<ResultadoValidacion> validar(File firmaParaValidar, ExtraValidators validators, ITimeStampValidator tsValidator) throws FirmaXMLError
	{
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(firmaParaValidar);
		} catch (FileNotFoundException e) {
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR58));
			return null;
		} 
		
		FirmaXMLError excepcion = null;
		List<ResultadoValidacion> rs = null;
		try {
			rs = validar(fis, firmaParaValidar.getParentFile().toURI().toString(), validators, tsValidator);
		} catch (FirmaXMLError ex) {
			excepcion = ex;
		} finally {		
			try {
				fis.close();
			} catch (Exception ex) {}
		}
		
		if (excepcion != null)
			throw excepcion;
		
		return rs;
	}

	/**
	 * Valida la firma XML
	 * @param bFirmaParaValidar byte[] con la firma a validar
	 * @param validators lista de validadores de policies que se aplicarán en la validación (<code>null</code> si no hay policies a aplicar).
	 * @param tsValidator validador de sellos de tiempo
	 * @return List<ResultadoValidacion> lista de resultados de validación, que indican si las firmas son válidas o no, y en este último caso indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public List<ResultadoValidacion> validar(byte[] bFirmaParaValidar, ExtraValidators validators, ITimeStampValidator tsValidator) throws FirmaXMLError
	{
		// No se ha proporcionado la ruta sobre la que esta el documento a validar. Se toma por defecto XXXX
		LOGGER.debug(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_INFO2) + ConstantesXADES.ESPACIO  
				+ System.getProperty(ConstantesXADES.USER_DIR));
		File dir = new File(System.getProperty(ConstantesXADES.USER_DIR));
		return validar(bFirmaParaValidar, dir.toURI().toString(), validators, tsValidator);
	}

	/**
	 * Valida la firma XML
	 * @param bFirmaParaValidar byte[] con la firma a validar
	 * @param baseUri ruta donde se encuentran los ficheros de complemento de información (para XADES-C)
	 * @param validators lista de validadores de policies que se aplicarán en la validación (<code>null</code> si no hay policies a aplicar).
	 * @param tsValidator validador de sellos de tiempo
	 * @return List<ResultadoValidacion> lista de resultados de validación, que indican si las firmas son válidas o no, y en este último caso indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public List<ResultadoValidacion> validar(byte[] bFirmaParaValidar, String baseUri, ExtraValidators validators, ITimeStampValidator tsValidator) throws FirmaXMLError
	{
		ByteArrayInputStream bis = null;

		bis = new ByteArrayInputStream(bFirmaParaValidar);

		return validar(bis, baseUri, validators, tsValidator);
	} 
	
	/**
	 * Valida la firma XML
	 * @param inputFirmaParaValidar InputStream con la firma a validar
	 * @param baseUri ruta donde se encuentran los ficheros de complemento de información (para XADES-C)
	 * @param validators lista de validadores de policies que se aplicarán en la validación (<code>null</code> si no hay policies a aplicar).
	 * @param tsValidator validador de sellos de tiempo
	 * @return List<ResultadoValidacion> lista de resultados de validación, que indican si las firmas son válidas o no, y en este último caso indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public List<ResultadoValidacion> validar(InputStream inputFirmaParaValidar, String baseUri, ExtraValidators validators, ITimeStampValidator tsValidator) throws FirmaXMLError
	{
		if (recoverManager == null) {
			recoverManager = new LocalFileStoreElements(baseUri);
		}

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true) ;

		DocumentBuilder db = null;
		try {
			db = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException e1) {
			mostrarErrorValidacion(e1);
		}

		InputSource isour = null;
		Document doc = null;
		ByteArrayOutputStream baosLeido = null;
		byte[] cabecera = new byte[10];
		int length = 0;
		try {
			length = inputFirmaParaValidar.available();
			baosLeido = new ByteArrayOutputStream(length);

			int j = inputFirmaParaValidar.read(cabecera);
			baosLeido.write(cabecera, 0, j);
			baosLeido.flush();
			int i = j;
			byte[] buffer = new byte[4096];
			while (i < length) {
				j = inputFirmaParaValidar.read(buffer);
				baosLeido.write(buffer, 0, j);
				baosLeido.flush();
				i += j;
			}
			
			if (LOGGER.isTraceEnabled()) {
				LOGGER.debug(baosLeido);
			}

//			baosLeido = new ByteArrayOutputStream();
//			baosLeido.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><documento><parts Encoding=\"urn:ietf-org:base64\" FileName=\"PT_TDT_SFNF69_00006190_A73_ST.xml\" Id=\"fichero1\"></parts>\n<eCoBrand>UGg4Z08wcCxKZ3coSWk=</eCoBrand>\n<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:etsi=\"http://uri.etsi.org/01903/v1.3.2#\" Id=\"Signature262964\">\n<ds:SignedInfo Id=\"Signature-SignedInfo70179\">\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n<ds:Reference Id=\"SignedPropertiesID674182\" Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#Signature262964-SignedProperties940701\">\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>u+Lwgo4+aTSZ7F3OeEL1CJXXX42EZlcpItuia4nv8Ks=</ds:DigestValue>\n</ds:Reference>\n<ds:Reference URI=\"#Certificate1476119\">\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>45ZIBAcsnvMNRUln1ZGfdgEiOF4Dh5vgR2Rwey8an5Y=</ds:DigestValue>\n</ds:Reference>\n<ds:Reference Id=\"Reference-ID-891384\" URI=\"#fichero1\">\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>cjk+eoqycgVxv1jfYlc+GCgKDMFYXqhkCLyVaA0gan8=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue Id=\"SignatureValue882256\">\nk8h4+sol/JL9JChZJG1HdeUYDIUqWFDsbm0tLpPO/tu7hjUuTL+yqQvRGN1gK06g34I882bJkkLB\nT0zQx+PVaUBWIfv1OnYtXH4ST0W3xtpRtyNtfhydGzlCkE9kjqmK2qhahm9RWoHFqJCqXw61Kxmf\nA/09e6xZycYrExxhgsY=\n</ds:SignatureValue>\n<ds:KeyInfo Id=\"Certificate1476119\">\n<ds:X509Data>\n<ds:X509Certificate>\nMIIFRDCCBK2gAwIBAgIEPNL9JDANBgkqhkiG9w0BAQUFADA2MQswCQYDVQQGEwJFUzENMAsGA1UE\nChMERk5NVDEYMBYGA1UECxMPRk5NVCBDbGFzZSAyIENBMB4XDTExMDgyOTA5NTg0MFoXDTE0MDgy\nOTA5NTg0MFowgYAxCzAJBgNVBAYTAkVTMQ0wCwYDVQQKEwRGTk1UMRgwFgYDVQQLEw9GTk1UIENs\nYXNlIDIgQ0ExEjAQBgNVBAsTCTUwMTA3MDAzNTE0MDIGA1UEAxMrTk9NQlJFIFRPUlRPTEEgUEVS\nRVogU0VSR0lPIC0gTklGIDM1MTI0NDgyRDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuVf5\nzM78gdip+RyYytAvvrJQOCSgvs+WKtW+zFZUEOCl69P2QkHd9XNJHyW40jElfCIUIiYC2PG1aPb9\n8phn6fDGUzVSbTUWQAA0gqnanvQVWCyRyR0rZmnqmcHUdFleDqG7/hARtWYkqySr6O1Lsky21/Ly\nZqx3xtB4gHl9zUMCAwEAAaOCAxIwggMOMIGRBgNVHREEgYkwgYaBIXNlcmdpby50b3J0b2xhQGFi\nZXJ0aXN0ZWxlY29tLmNvbaRhMF8xGDAWBgkrBgEEAaxmAQQTCTM1MTI0NDgyRDEUMBIGCSsGAQQB\nrGYBAxMFUEVSRVoxFjAUBgkrBgEEAaxmAQITB1RPUlRPTEExFTATBgkrBgEEAaxmAQETBlNFUkdJ\nTzAJBgNVHRMEAjAAMCsGA1UdEAQkMCKADzIwMTEwODI5MDk1ODQwWoEPMjAxNDA4MjkwOTU4NDBa\nMAsGA1UdDwQEAwIFoDARBglghkgBhvhCAQEEBAMCBaAwHQYDVR0OBBYEFDy3/Qh8Rq70+ICyxLN4\nU1GRcjinMB8GA1UdIwQYMBaAFECadkSXdAfErBTLHo1POkV8MNdhMIIBMQYDVR0gBIIBKDCCASQw\nggEgBgkrBgEEAaxmAwUwggERMDQGCCsGAQUFBwIBFihodHRwOi8vd3d3LmNlcnQuZm5tdC5lcy9j\nb252ZW5pby9kcGMucGRmMIHYBggrBgEFBQcCAjCByxqByENlcnRpZmljYWRvIFJlY29ub2NpZG8g\nZXhwZWRpZG8gc2Vn+m4gbGVnaXNsYWNp824gdmlnZW50ZS5Vc28gbGltaXRhZG8gYSBsYSBDb211\nbmlkYWQgRWxlY3Ry825pY2EgcG9yIHZhbG9yIG3heGltbyBkZSAxMDAgZSBzYWx2byBleGNlcGNp\nb25lcyBlbiBEUEMuQ29udGFjdG8gRk5NVDpDL0pvcmdlIEp1YW4gMTA2LTI4MDA5LU1hZHJpZC1F\nc3Bh8WEuMB0GCSsGAQQBrGYBIQQQFg5QRVJTT05BIEZJU0lDQTAvBggrBgEFBQcBAwQjMCEwCAYG\nBACORgEBMBUGBgQAjkYBAjALEwNFVVICAWQCAQAwWwYDVR0fBFQwUjBQoE6gTKRKMEgxCzAJBgNV\nBAYTAkVTMQ0wCwYDVQQKEwRGTk1UMRgwFgYDVQQLEw9GTk1UIENsYXNlIDIgQ0ExEDAOBgNVBAMT\nB0NSTDkwNTYwDQYJKoZIhvcNAQEFBQADgYEAJuwjMNC9+iXD45+lRA6VFG/nH1cd+tXkmwbrgqz+\nufgEaErTwker6drWpQz9RMmsHUBHitWfxak/td1vsE+anLdWOFdCDzqshLs+IMQ+Bl28ZMlC7KUt\ngo3oaV/JUmAYpLzw/hZg5uX1bV6pAGY9xOsFpNws4+Gn6c84ca5/8y0=\n</ds:X509Certificate>\n</ds:X509Data>\n<ds:KeyValue>\n<ds:RSAKeyValue>\n<ds:Modulus>\nuVf5zM78gdip+RyYytAvvrJQOCSgvs+WKtW+zFZUEOCl69P2QkHd9XNJHyW40jElfCIUIiYC2PG1\naPb98phn6fDGUzVSbTUWQAA0gqnanvQVWCyRyR0rZmnqmcHUdFleDqG7/hARtWYkqySr6O1Lsky2\n1/LyZqx3xtB4gHl9zUM=\n</ds:Modulus>\n<ds:Exponent>AQAB</ds:Exponent>\n</ds:RSAKeyValue>\n</ds:KeyValue>\n</ds:KeyInfo>\n<ds:Object Id=\"Signature262964-Object902568\"><etsi:QualifyingProperties Target=\"#Signature262964\"><etsi:SignedProperties Id=\"Signature262964-SignedProperties940701\"><etsi:SignedSignatureProperties><etsi:SigningTime>2012-11-26T16:06:52+01:00</etsi:SigningTime><etsi:SigningCertificate><etsi:Cert><etsi:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>ALOkokO/Kn7a7YUiDKxE8Uka9g10TJQM9qgLEFIdjEg=</ds:DigestValue></etsi:CertDigest><etsi:IssuerSerial><ds:X509IssuerName>OU=FNMT Clase 2 CA,O=FNMT,C=ES</ds:X509IssuerName><ds:X509SerialNumber>1020460324</ds:X509SerialNumber></etsi:IssuerSerial></etsi:Cert></etsi:SigningCertificate><etsi:SignerRole><etsi:ClaimedRoles><etsi:ClaimedRole>Autor</etsi:ClaimedRole></etsi:ClaimedRoles></etsi:SignerRole></etsi:SignedSignatureProperties><etsi:SignedDataObjectProperties><etsi:DataObjectFormat ObjectReference=\"#Reference-ID-891384\"><etsi:Description>documento de lenguaje de etiquetas extensible (XML)</etsi:Description><etsi:MimeType>text/xml</etsi:MimeType><etsi:Encoding>http://www.w3.org/2000/09/xmldsig#base64</etsi:Encoding></etsi:DataObjectFormat></etsi:SignedDataObjectProperties></etsi:SignedProperties></etsi:QualifyingProperties></ds:Object></ds:Signature></documento>".getBytes());
			
			
			isour = new InputSource(new ByteArrayInputStream(baosLeido.toByteArray()));
			doc = db.parse(isour);
		} catch (FileNotFoundException e1) {
			mostrarErrorValidacion(e1);
		} catch (SAXException e1) {
			try {;
				byte[] utf8BOM = new byte[] { (byte)0xEF, (byte)0xBB, (byte)0xBF };
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Buscando BOM de XML. Buffer leído = " + cabecera[0] + " " + cabecera[1] + " " + cabecera[2]);
				if (cabecera != null && cabecera.length > 0 && (cabecera[0] == utf8BOM[0] &&
						cabecera[1] == utf8BOM[1] &&
								cabecera[2] == utf8BOM[2])) {
					
					if (LOGGER.isDebugEnabled())
						LOGGER.debug("Encontrado BOM de XML. Parseando documento...");					
					doc = db.parse(new ByteArrayInputStream(baosLeido.toByteArray(), 3, length));
				} else { // WORKAROUND para BOM no UTF-8 --> ï»¿ [-61, -81, -62, -69, -62, -65]
					byte[] utf8BOMNotUTF8 = new byte[] { -61, -81, -62, -69, -62, -65 };
					if (LOGGER.isDebugEnabled())
						LOGGER.debug("Buscando BOM no UTF8 de XML. Buffer = " + new String(cabecera) +
								"\n Buffer leído = " + cabecera[0] + " " + cabecera[1] + " " + cabecera[2] + " " + cabecera[3] + " " + cabecera[4] + " " + cabecera[5]);
					if (cabecera != null && cabecera.length > 0 && (( cabecera[0] == utf8BOMNotUTF8[0] &&
							cabecera[1] == utf8BOMNotUTF8[1] &&
							cabecera[2] == utf8BOMNotUTF8[2] &&
							cabecera[3] == utf8BOMNotUTF8[3] &&
							cabecera[4] == utf8BOMNotUTF8[4] &&
							cabecera[5] == utf8BOMNotUTF8[5] ) ||
							new String(cabecera).startsWith(new String(utf8BOMNotUTF8))) ) {
						// ï»¿ [-61, -81, -62, -69, -62, -65]
						if (LOGGER.isDebugEnabled())
							LOGGER.debug("Encontrado BOM no UTF8 de XML. Parseando documento...");						
						doc = db.parse(new ByteArrayInputStream(baosLeido.toByteArray(), 6, length));
					} else {
						mostrarErrorValidacion(e1);
					}
				}					
			} catch (IOException e) {
				mostrarErrorValidacion(e1);
			} catch (SAXException e) {
				mostrarErrorValidacion(e1);
			} finally {
				if (inputFirmaParaValidar != null) { 
					try {inputFirmaParaValidar.close();} catch (IOException e) {}
				}
				if (baosLeido != null) { 
					try {baosLeido.close();} catch (IOException e) {}
				}
			}
		} catch (@SuppressWarnings("restriction") com.sun.org.apache.xerces.internal.impl.io.MalformedByteSequenceException me) {
		    LOGGER.debug(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR28) + " - " + me.getMessage());
		} catch (IOException e1) {
			mostrarErrorValidacion(e1);
		}
		dbf = null;
		isour = null;
		db = null;

		ArrayList<ResultadoValidacion> res = validar(doc, baseUri, validators, tsValidator);
		
		// Comprueba el estado de los certificados envueltos en la firma
		ICertStatusRecoverer certStatus = (validators != null) ? validators.getCertStatus() : null;
		
		// Si hay validador de confianza lo pasa ahora
		if ((res != null) && (res.size() > 0) && (validators != null)) {
			TrustAbstract trusterCerts = validators.getTrusterCerts();
			TrustAbstract trusterOCSP = validators.getTrusterOCSP();
			TrustAbstract trusterCRL = validators.getTrusterCRL();
			TrustAbstract trusterTSA = validators.getTrusterTSA();
			ICertStatus status = null;
			CERT_STATUS statusRes = CERT_STATUS.unknown;
			if ((trusterCerts != null) || (trusterOCSP != null) || (trusterCRL != null) || (trusterTSA != null)) {
				Iterator<ResultadoValidacion> it = res.iterator();
				while (it.hasNext()) {
					ResultadoValidacion rv = it.next();
					if (rv != null) {
						DatosFirma df = rv.getDatosFirma();
						if (df != null) {
							if (trusterCerts != null) {
								status = rv.getCertStatus();
								if (status != null)
									statusRes = status.getStatus();
								if (!ICertStatus.CERT_STATUS.unknown.equals(statusRes)) {
									df.setEsCadenaConfianza(ConfianzaEnum.CON_CONFIANZA);
								} else {
									validateTrustCerts(trusterCerts, df);
								}
							}

							if (trusterOCSP != null) {
								ArrayList<DatosOCSP> ocsps = df.getDatosOCSP();
								if ((ocsps != null) && (ocsps.size() > 0)) {
                                    if (df.getTipoFirma().getTipoXAdES().compareTo(EnumFormatoFirma.XAdES_X)>=0) {
                                        //Tmirar el truster local
                                        validateTrustOCSP(trusterOCSP, df);
                                    } else {
    									Iterator<DatosOCSP> itOcsp = ocsps.iterator();
    									while (itOcsp.hasNext()) {
    										DatosOCSP docsp = itOcsp.next();
    										OCSPResp ocspr = docsp.getRespuestaOCSP();
    										if (ocspr != null) {
    											try {
    												status = certStatus.getCertStatus(docsp.getCertOCSPResponder()[0]);
    												if (status != null)
    													statusRes = status.getStatus();
    											} catch (Exception e) {
    												statusRes = CERT_STATUS.unknown;
    											}
    											docsp.setRevockedStatus(statusRes);
    											docsp.setStatus(status);
    											if (ICertStatus.CERT_STATUS.unknown.equals(statusRes)) {
    												validateTrustOCSP(trusterOCSP, df);
    											} else if (ICertStatus.CERT_STATUS.revoked.equals(statusRes)) {
    												docsp.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
    												rv.setValidate(false);
    												rv.setResultado(ResultadoEnum.INVALID);
    												RevokedInfo ri = status.getRevokedInfo();
    												Date revoked = null;
    												if (ri != null) {
    													revoked = ri.getRevokedDate();
    												}
    												if (revoked != null) {
    													SimpleDateFormat formatter = new SimpleDateFormat(ConstantesXADES.FORMATO_SOLO_FECHA);
    													rv.setLog(i18n.getLocalMessage(OCSP_REVOCKED, formatter.format(revoked)));
    													LOGGER.info(i18n.getLocalMessage(OCSP_REVOCKED, formatter.format(revoked)));
    													logv.error(i18n.getLocalMessage(OCSP_REVOCKED, formatter.format(revoked))); 
    												} else {
    													rv.setLog(i18n.getLocalMessage(OCSP_REVOCKED_NO_DATE));
    													LOGGER.info(i18n.getLocalMessage(OCSP_REVOCKED_NO_DATE));
    													logv.error(i18n.getLocalMessage(OCSP_REVOCKED_NO_DATE));
    												}
    											} else {
    												docsp.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
    											}
										    }
										}
									}
								}
							}

							if (trusterCRL != null) {
								validateTrustCRL(trusterCRL, df);
							}
							if (trusterTSA != null) {
								ArrayList<DatosSelloTiempo> tsas = df.getDatosSelloTiempo();
								if ((tsas != null) && (tsas.size() > 0)) {
									Iterator<DatosSelloTiempo> itTsas = tsas.iterator();
                                    validateTrustTSA(trusterTSA, df);
                                    while (itTsas.hasNext()) {
										DatosSelloTiempo dst = itTsas.next();
										if((df.getTipoFirma().getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_X)>=0){
										    if(itTsas.hasNext()) {
										        continue;
										    }
										}
										if(dst.esCertConfianza().equals(ConfianzaEnum.SIN_CONFIANZA)) {
										    continue;
										}
										byte[] rawTimestamp = dst.getRawTimestamp();

										X509Certificate tsaCert = null;					
										try {
											TimeStampToken tst = new TimeStampToken(new CMSSignedData(rawTimestamp));
											CertStore cs = tst.getCertificatesAndCRLs("Collection", null);
											Collection<? extends Certificate> certs = cs.getCertificates(null);
											if(certs.size() > 0) {
												Certificate cert = (Certificate)certs.iterator().next();
												if(cert instanceof X509Certificate)
													tsaCert = ((X509Certificate)cert);
											}
										}
										catch(Exception ex) { /* No se hace nada */ }

										try {
											status = certStatus.getCertStatus(tsaCert);
											if (status != null)
												statusRes = status.getStatus();
										} catch (Exception e) {
											statusRes = CERT_STATUS.unknown;
										}
										dst.setRevockedStatus(statusRes);
										if (ICertStatus.CERT_STATUS.unknown.equals(statusRes)) {
											//validateTrustTSA(trusterTSA, df);
										} else if (ICertStatus.CERT_STATUS.revoked.equals(statusRes)) {
											dst.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
											rv.setValidate(false);
											rv.setResultado(ResultadoEnum.UNKNOWN);
											RevokedInfo ri = status.getRevokedInfo();
											Date revoked = null;
											if (ri != null) {
												revoked = ri.getRevokedDate();
											}
											if (revoked != null) {
												SimpleDateFormat formatter = new SimpleDateFormat(ConstantesXADES.FORMATO_SOLO_FECHA);
												rv.setLog(i18n.getLocalMessage(TSA_REVOCKED, formatter.format(revoked)));
												LOGGER.info(i18n.getLocalMessage(TSA_REVOCKED, formatter.format(revoked)));
												logv.error(i18n.getLocalMessage(TSA_REVOCKED, formatter.format(revoked))); 
											} else {
												rv.setLog(i18n.getLocalMessage(TSA_REVOCKED_NO_DATE));
												LOGGER.info(i18n.getLocalMessage(TSA_REVOCKED_NO_DATE));
												logv.error(i18n.getLocalMessage(TSA_REVOCKED_NO_DATE));
											}
										} else {
											dst.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
										}
									}
								}
							}
						}
					} 
				} // while
			}
		}
		return res;
	}
	
	/**
	 * Metodo que consultara si un certificado firmante es de confianza e incorporará el resultado de la validación al objeto df
	 * @param truster Validador de confianza para certificados firmantes
	 * @param df Objeto de la clase DatosFirma que se utilizará para obtener la cadena de firma
	 */
	private void validateTrustCerts(TrustAbstract truster, DatosFirma df) {
		try {
			truster.isTrusted(df.getCadenaFirma());
			df.setEsCadenaConfianza(ConfianzaEnum.CON_CONFIANZA);
		} catch (NotTrustedException ex) {
			df.setEsCadenaConfianza(ConfianzaEnum.SIN_CONFIANZA);
		} catch (UnknownTrustException ex) {
			df.setEsCadenaConfianza(ConfianzaEnum.NO_REVISADO);
		} catch (TrustException ex) {
			df.setEsCadenaConfianza(ConfianzaEnum.NO_REVISADO);
			LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_TRUST_1, ex.getMessage()));
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("", ex);
		}
	}
	
	/**
	 * Metodo que consultara si los emisores de respuestas OCSP de una firma son de confianza e incorporará el resultado de la validación al objeto df
	 * @param truster Validador de confianza para respuestas OCSP
	 * @param df Objeto de la clase DatosFirma que se utilizará para obtener las respuestas OCSPs y almacenar el resultado de las consultas
	 */
	private void validateTrustOCSP(TrustAbstract truster, DatosFirma df) {
		ArrayList<DatosOCSP> ocsps = df.getDatosOCSP();
		if ((ocsps != null) && (ocsps.size() > 0)) {
			Iterator<DatosOCSP> it = ocsps.iterator();
			while (it.hasNext()) {
				DatosOCSP docsp = it.next();
				OCSPResp ocspr = docsp.getRespuestaOCSP();
				if (ocspr != null) {
					try {
						truster.isTrusted(ocspr);
						docsp.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
					} catch (NotTrustedException ex) {
						docsp.setEsCertConfianza(ConfianzaEnum.SIN_CONFIANZA);
					} catch (UnknownTrustException ex) {
						docsp.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
					} catch (TrustException ex) {
						docsp.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
						LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_TRUST_2, ex.getMessage()));
						if (LOGGER.isDebugEnabled())
							LOGGER.debug("", ex);
					}
				}
			}
		}
	}
	
	/**
	 * Metodo que consultara si los emisores de CRLs de una firma son de confianza e incorporará el resultado de la validación al objeto df
	 * @param truster Validador de confianza para CRLs
	 * @param df Objeto de la clase DatosFirma que se utilizará para obtener las CRLs y almacenar el resultado de las consultas
	 */
	private void validateTrustCRL(TrustAbstract truster, DatosFirma df) {
		ArrayList<DatosCRL> crls = df.getDatosCRL();
		if ((crls != null) && (crls.size() > 0)) {
			Iterator<DatosCRL> it = crls.iterator();
			while (it.hasNext()) {
				DatosCRL dcrl = it.next();
				X509CRL crl = dcrl.getX509CRL();
				if (crl != null) {
					try {
						truster.isTrusted(crl);
						dcrl.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
					} catch (NotTrustedException ex) {
						dcrl.setEsCertConfianza(ConfianzaEnum.SIN_CONFIANZA);
					} catch (UnknownTrustException ex) {
						dcrl.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
					} catch (TrustException ex) {
						dcrl.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
						LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_TRUST_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled())
							LOGGER.debug("", ex);
					}
				}
			}
		}
	}
	
	/**
	 * Metodo que consultara si los emisores de sellos de tiempo de una firma son de confianza e incorporará el resultado de la validación al objeto df
	 * @param truster Validador de confianza para sellos de tiempo
	 * @param df Objeto de la clase DatosFirma que se utilizará para obtener los sellos de tiempo y almacenar el resultado de las consultas
	 */
	private void validateTrustTSA(TrustAbstract truster, DatosFirma df) {
			ArrayList<DatosSelloTiempo> tsts = df.getDatosSelloTiempo();
			if ((tsts != null) && (tsts.size() > 0)) {
				Iterator<DatosSelloTiempo> it = tsts.iterator();
				while (it.hasNext()) {
					DatosSelloTiempo dst = it.next();
					byte[] rawTimestamp = dst.getRawTimestamp();
					TimeStampToken tst;
                    try {
                        tst = new TimeStampToken(new CMSSignedData(rawTimestamp));
                        try {
                            truster.isTrusted(tst);
                            dst.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
                        } catch (NotTrustedException ex) {
                            dst.setEsCertConfianza(ConfianzaEnum.SIN_CONFIANZA);
                        } catch (UnknownTrustException ex) {
                            dst.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
                        } catch (TrustException ex) {
                            dst.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
                            LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_TRUST_4, ex.getMessage()));
                            if (LOGGER.isDebugEnabled())
                                LOGGER.debug("", ex);
                        }
                    } catch (TSPException e) {
                        dst.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
                        LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_TRUST_4, e.getMessage()));
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("", e);
                        }
                    } catch (IOException e) {
                        dst.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
                        LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_TRUST_4, e.getMessage()));
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("", e);
                        }
                    } catch (CMSException e) {
                        dst.setEsCertConfianza(ConfianzaEnum.NO_REVISADO);
                        LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_TRUST_4, e.getMessage()));
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("", e);
                        }
                    }
				}
			}

	}
	
	/**
	 * <p>Establece el Locale del sistema antiguo de internacionalización.</p>
	 * @param locale Localización a aplicar
	 */
	public void setLocale(String locale) {
		I18n.setLocale(locale, locale.toUpperCase());
	}
	
	/**
	 * <p>Establece si se validará el esquema XAdES indicado.</p>
	 * <p>Por defecto todas las versiones de esquema XAdES se intentan validar. Si no se quiere admitir una versión de XAdES se ha de
	 * desactivar.</p>
	 * @param schema Esquema XAdES
	 * @param activate <code>true</code> si se quiere que se valide el esquema, <code>false</code> si no se quiere validar
	 */
	public void setXAdESSchema(XAdESSchemas schema, boolean activate) {
		if (schema != null) {
			if (activate) {
				esquemasParaValidar.add(schema.getSchemaUri());
			} else {
				esquemasParaValidar.remove(schema.getSchemaUri());
			}
		}
	}

	/**
	 * Valida la firma XML
	 * @param doc Document con la firma XADES para validar
	 * @param baseUri ruta donde se encuentran los ficheros de complemento de información (para XADES-C)
	 * @param validators lista de validadores de policies que se han de aplicar en la validación
	 * @param timestampValidators lista de validadores de sellos de tiempo que se han de aplicar en la validación
	 * @return ValidationResult Este objeto indica si la firma es válida o no, y en este último caso
	 * indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public ArrayList<ResultadoValidacion> validar(Document doc, String baseUri, ExtraValidators validators, ITimeStampValidator timeStampValidator) throws FirmaXMLError
	{
		ArrayList<ResultadoValidacion> resultados = new ArrayList<ResultadoValidacion>();

		es.mityc.javasign.utils.Utils.addBCProvider();

		try {
			// se establece la clase encargada de validar sellos de tiempo
			if (tsValidator == null) {
				tsValidator = timeStampValidator;
			}

			// Se recupera la lista de esquemas que se pueden validar
			uriXmlNS = ConstantesXADES.SCHEMA_DSIG;

			if (esquemasParaValidar.isEmpty())
			{
				// No se han encontrado esquemas para validar en el fichero de propiedades
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR1));
				throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR1));
			}

			// Validamos que el fichero de firma sea un XML bien formado
			Init.init() ;

			// Se recupera el nodo de firma Signature
			NodeList listaFirmas = doc.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_SIGNATURE);
			if (listaFirmas.getLength() == 0)
			{
				// Error en la validación. No se pudo encontrar el nodo de firma
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR2));
				throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR2));
			}

			// Si el documento tiene múltiples firmas existe más de un nodo de firma
			int longitud = listaFirmas.getLength();
			LOGGER.debug(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_INFO1) + ConstantesXADES.ESPACIO +  longitud); // Firmas presentes

			// Confianza
			truster = (validators != null) ? validators.getTrusterCerts() : null;

			// Políticas configuradas por parámetro
			List<IValidacionPolicy> policies = (validators != null) ? validators.getPolicies() : null;
			
			// Cada firma se valida como una firma única 
			for(int i=0; i < longitud; i++) {
				resultados.add(validaFirma(listaFirmas.item(i), baseUri, policies));			
			}

			// Se completa la estructura de firmas y contrafirmas
			Iterator<ResultadoValidacion> itResVal = resultados.iterator(); // Para cada firma validada
			while (itResVal.hasNext()) {
				ResultadoValidacion rv = itResVal.next(); // Se recuperan las firmas una a una
				// Se recuperan los datos de la firma validada
				DatosFirma datos = rv.getDatosFirma();
				// Se incializa la estructura "Contrafirmado Por"
				rv.setContrafirmadoPor(new ArrayList<ResultadoValidacion> ());			
				if (datos != null) {
					// Se recupera la Id de la firma (Id del nodo SignatureValue)
					String id = datos.getSigValueId();
					if (id != null) {
						// Se recorren todas las firmas buscando dicha Id en su estructura "Contrafirma a"
						Iterator<ResultadoValidacion> itResVal2 = resultados.iterator();
						while (itResVal2.hasNext()) {
							ResultadoValidacion rv2 = itResVal2.next();
							DatosFirma datos2 = rv2.getDatosFirma();
							// Si hay datos de firma y no se trata de la misma firma
							if (datos2 != null && !id.equals(datos2.getSigValueId())) {
								// Se recupera la estructura de ids contrafirmados
								ArrayList<String> contrafirmaA = datos2.getContraFirma();
								// Si la id se encuentra en dicha estructura se añade el 
								// resultado de validación a la estructura "Contrafirmado por"
								if (contrafirmaA != null && contrafirmaA.contains(id))
									rv.addContrafirmadoPor(rv2);
							}
						}
					}
				}
			}

			// Comprueba el estado de los certificados envueltos en la firma
			ICertStatusRecoverer certStatus = (validators != null) ? validators.getCertStatus() : null;
			if (certStatus != null) {
				Iterator<ResultadoValidacion> it = resultados.iterator();
				while (it.hasNext()) {
					ResultadoValidacion rv = it.next();
					// Si la firma es válida y es XAdES-BES, EPES o T, chequea el estado del certificado de firma
					if (rv.isValidate()) {
						Date firstTimestamp = null;
						if (EnumFormatoFirma.XAdES_T.compareTo(rv.getEnumNivel()) <= 0) {
							ArrayList<DatosSelloTiempo> listTS = rv.getDatosFirma().getDatosSelloTiempo();
							if (listTS != null) {
								Iterator<DatosSelloTiempo> itTS = listTS.iterator();
								while (itTS.hasNext()) {
									DatosSelloTiempo dst = itTS.next();
									if (firstTimestamp == null) 
										firstTimestamp = dst.getFecha();
									else if (firstTimestamp.after(dst.getFecha()))
										firstTimestamp = dst.getFecha();
								}
							}
						}
                        CertPath cp = rv.getDatosFirma().getCadenaFirma();
                        X509Certificate certificate = (X509Certificate)cp.getCertificates().get(0);
						if (EnumFormatoFirma.XAdES_X.compareTo(rv.getEnumNivel()) > 0) {
    						try {
    							ICertStatus respYCerts = certStatus.getCertStatus(certificate);
    							if (respYCerts != null) {
    								rv.setCertStatus(respYCerts);
    								if (ICertStatus.CERT_STATUS.revoked.equals(respYCerts.getStatus())) {
    									if (firstTimestamp != null) {
    										RevokedInfo ri = respYCerts.getRevokedInfo();
    										Date revoked = (ri != null) ? ri.getRevokedDate() : null;
    										// TODO: Hay que tener en cuenta la precisión del sello de tiempo
    										if ((revoked != null) && (firstTimestamp.before(revoked))) {
    											rv.setValidate(false);
    											rv.setResultado(ResultadoEnum.UNKNOWN);
    											rv.setLog(null);
    											continue;
    										}
    									} else {
    										RevokedInfo ri = respYCerts.getRevokedInfo();
    										Date revoked = (ri != null) ? ri.getRevokedDate() : null;
    										// TODO: Hay que tener en cuenta la precisión del sello de tiempo
    										Date signingTime = rv.getDatosFirma().getFechaFirma();
    										if ((revoked != null) && (signingTime.before(revoked))) {
    											rv.setValidate(false);
    											rv.setResultado(ResultadoEnum.UNKNOWN);
    											rv.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_15, revoked) + "\n"
    													+ i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_17, signingTime));
    											continue;
    										}
    									}
    
    									RevokedInfo ri = respYCerts.getRevokedInfo();
    									if (ri != null) {
    										Date revoked = ri.getRevokedDate();
    										if (revoked != null) {
    											SimpleDateFormat formatter = new SimpleDateFormat(ConstantesXADES.FORMATO_SOLO_FECHA);
    											rv.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_15, formatter.format(revoked)));
    											LOGGER.info(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_15, formatter.format(revoked)));
    										} else {
    											LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR165));
    										}
    									} else {
    										LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR165));
    									}
    
    									if (EnumFormatoFirma.XAdES_C.compareTo(rv.getEnumNivel()) <= 0) {
    										BasicOCSPResp basicResponse = getOCSPResponseFromSignature(rv, certificate);
    										if (basicResponse != null) {
    											SingleResp[] responses = basicResponse.getResponses();
    											if (responses.length == 1) {
    												SingleResp resp = responses[0];
    												Object status = resp.getCertStatus();
    												if (status == CertificateStatus.GOOD) {
    													SimpleDateFormat f = new SimpleDateFormat("dd/MM/yyyy H:mm:ss");
    													String log = rv.getLog();
    													if (log != null && log.length() > 0) {
    														log = log + "\nSe adjuntan respuestas OCSP con fecha: " + f.format(basicResponse.getProducedAt()); 
    													} else {
    														log = "El certificado firmante esta revocado.\nSe adjuntan respuestas OCSP con fecha: " + f.format(basicResponse.getProducedAt()); ;
    													}
    													rv.setLog(log);
    													rv.setValidate(true);
    													rv.setResultado(ResultadoEnum.VALID);
    												} else {
    													rv.setValidate(false);
    													rv.setResultado(ResultadoEnum.INVALID);
    													rv.setLog(null);
    												}
    											}
    										} else {
    											rv.setValidate(false);
    											rv.setResultado(ResultadoEnum.INVALID);
    											rv.setLog(null);
    										}
    									} else {
    										rv.setValidate(false);
    										rv.setResultado(ResultadoEnum.INVALID);
    										rv.setLog(null);
    									}
    
    									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR165));
    									continue; // Se pasa a la siguiente firma
    								} else if (ICertStatus.CERT_STATUS.unknown.equals(respYCerts.getStatus())) {
    									if (EnumFormatoFirma.XAdES_C.compareTo(rv.getEnumNivel()) <= 0) {
    										BasicOCSPResp basicResponse = getOCSPResponseFromSignature(rv, certificate);
    										if (basicResponse != null) {
    											SingleResp[] responses = basicResponse.getResponses();
    											if (responses.length == 1) {
    												SingleResp resp = responses[0];
    												Object status = resp.getCertStatus();
    												if (status == CertificateStatus.GOOD) {
    													SimpleDateFormat f = new SimpleDateFormat("dd/MM/yyyy H:mm:ss");
    													rv.setLog("El certificado firmante tiene un estado de revocación desconocido.\nSe adjuntan respuestas OCSP con fecha: " + f.format(basicResponse.getProducedAt()));
    													rv.setValidate(true);
    													rv.setResultado(ResultadoEnum.VALID);
    												} else {
    													rv.setValidate(false);
    													rv.setResultado(ResultadoEnum.UNKNOWN);
    													rv.setLog(null);
    												}
    											}
    										} else {
    											rv.setValidate(false);
    											rv.setResultado(ResultadoEnum.UNKNOWN);
    											rv.setLog(null);
    										}
    									} else {
    										rv.setValidate(false);
    										rv.setResultado(ResultadoEnum.UNKNOWN);
    										rv.setLog(null);
    									}
    									LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR166));
    									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR166));
    									continue; // Se pasa a la siguiente firma
    									//									}
    								} else {
    									if (LOGGER.isTraceEnabled())
    										LOGGER.trace(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR167));
    									logv.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR167));
    								}
    							} else {
    								if (EnumFormatoFirma.XAdES_C.compareTo(rv.getEnumNivel()) <= 0) {
    									BasicOCSPResp basicResponse = getOCSPResponseFromSignature(rv, certificate);
    									if (basicResponse != null) {
    										SingleResp[] responses = basicResponse.getResponses();
    										if (responses.length == 1) {
    											SingleResp resp = responses[0];
    											Object status = resp.getCertStatus();
    											if (status == CertificateStatus.GOOD) {
    												SimpleDateFormat f = new SimpleDateFormat("dd/MM/yyyy H:mm:ss");
    												rv.setLog("El certificado firmante tiene un estado de revocación desconocido.\nSe adjuntan respuestas OCSP con fecha: " + f.format(basicResponse.getProducedAt()));
    												rv.setValidate(true);
    												rv.setResultado(ResultadoEnum.VALID);
    											} else {
    												rv.setValidate(false);
    												rv.setResultado(ResultadoEnum.UNKNOWN);
    												rv.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR166));
    											}
    										}
    									} else {
    										rv.setValidate(false);
    										rv.setResultado(ResultadoEnum.UNKNOWN);
    										rv.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR166));
    									}
    								} else {
    									rv.setValidate(false);
    									rv.setResultado(ResultadoEnum.UNKNOWN);
    									rv.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR166));
    									LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR166));
    									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR166));
    								}
    							}
    						} catch (CertStatusException ex) {
    							rv.setResultado(ResultadoEnum.UNKNOWN);
    							rv.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_14));
    							LOGGER.info(ex.getMessage(), ex);
    							logv.error(ex.getMessage());
    							continue; // Se pasa a la siguiente firma
    						}
						} // Si es < X
						else {
						    //Recorrer todas las respustas OCSP de la firma y si alguna está revoked o unknown rellenar los resultados
						    if ( arrayDatosOCSP != null){
						        for (DatosOCSP currentOCSP: arrayDatosOCSP) {
						            if (currentOCSP.getRevockedStatus().equals(CERT_STATUS.revoked)){
						                rv.setValidate(false);
                                        rv.setResultado(ResultadoEnum.INVALID);
                                        rv.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_19, currentOCSP.getCertConsultado()));
						            } else if (currentOCSP.getRevockedStatus().equals(CERT_STATUS.unknown)){
                                        rv.setValidate(false);
                                        rv.setResultado(ResultadoEnum.UNKNOWN);
                                        rv.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_20, currentOCSP.getCertConsultado()));
                                    } else {
                                        //TODO ver la caduciada
                                        //Recuperar el Certificado 
                                        
                                    }
                                    
						        }
						    } else {
                                rv.setValidate(false);
                                rv.setResultado(ResultadoEnum.INVALID);
                                rv.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_21));
						    }
						    
						    BasicOCSPResp basicResponse = getOCSPResponseFromSignature(rv, certificate);
                            if (basicResponse != null) {
                                SingleResp[] responses = basicResponse.getResponses();
                                if (responses.length == 1) {
                                    SingleResp resp = responses[0];
                                    Object status = resp.getCertStatus();
                                    if (status == CertificateStatus.GOOD) {
                                        rv.setValidate(true);
                                        rv.setResultado(ResultadoEnum.VALID);
                                    } else {
                                        rv.setValidate(false);
                                        rv.setResultado(ResultadoEnum.INVALID);
                                        rv.setLog(null);
                                    }
                                }
                            } else {
                                rv.setValidate(false);
                                rv.setResultado(ResultadoEnum.INVALID);
                                rv.setLog(null);
                            }						    
						}
					}
				}
			}

			doc = null;

			return resultados;
		} finally {
			try {
				Security.removeProvider(ConstantsAPI.PROVIDER_BC_NAME);
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(e);
				}
			}
		}
	}

    private BasicOCSPResp getOCSPResponseFromSignature(ResultadoValidacion rv,
            X509Certificate certificate) {
        BasicOCSPResp basicResponse = null;
        try {
        	ArrayList<DatosOCSP> datos = rv.getDatosFirma().getDatosOCSP();
        	for (int i = 0; i < datos.size(); ++i) {
        		if (datos.get(i).getCertConsultado().equals(certificate.getSubjectX500Principal().toString())) {
        			basicResponse = (BasicOCSPResp) datos.get(i).getRespuestaOCSP().getResponseObject();
        			break;
        		}
        	}

        } catch (Throwable e) { LOGGER.debug("Error al acceder a las datos OCSP", e);}
        return basicResponse;
    }
	
	/**
	 * Valida la firma XML
	 * @param doc Document con la firma XADES para validar
	 * @param baseUri ruta donde se encuentran los ficheros de complemento de información (para XADES-C)
	 * @param validators lista de validadores de policies que se han de aplicar en la validación
	 * @return ValidationResult Este objeto indica si la firma es válida o no, y en este último caso
	 * indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public ArrayList<ResultadoValidacion> validar(Document doc, String baseUri, ExtraValidators validators) throws FirmaXMLError
	{
		return validar(doc,baseUri,validators,null);
	}	
	
	   /**
     * Valida la firma XML
     * @param firma Nodo de la firma a validar
     * @param baseUri ruta donde se encuentran los ficheros de complemento de información (para XADES-C)
     * @param policies lista de validadores de policies que se han de aplicar en la validación
     * indica la razón por la cual la firma no es válida
     * @return ResultadoValidacion Objeto con el resultado de la validación de la firma.
     */
    public ResultadoValidacion validar(Node firma, String baseUri, List<IValidacionPolicy> policies) {
        es.mityc.javasign.utils.Utils.addBCProvider();

        try{
            if (uriXmlNS == null) {
                uriXmlNS = ConstantesXADES.SCHEMA_DSIG;
            }
            
            Init.init() ;
            
            return validaFirma(firma, baseUri, policies);
        } finally {
            try {
                Security.removeProvider(ConstantsAPI.PROVIDER_BC_NAME);
            } catch (Exception e) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(e);
                }
            }
        }
    }
	/**
	 * Valida la firma XML
	 * @param firma Nodo de la firma a validar
	 * @param baseUri ruta donde se encuentran los ficheros de complemento de información (para XADES-C)
	 * @param policies lista de validadores de policies que se han de aplicar en la validación
	 * indica la razón por la cual la firma no es válida
	 * @return ResultadoValidacion Objeto con el resultado de la validación de la firma.
	 */
	private ResultadoValidacion validaFirma(Node firma, String baseUri, List<IValidacionPolicy> policies) { 
		// Si no tiene aplicada una dirección base pone el directorio de trabajo
		if (baseUri == null) {
			baseUri = new File("./").getAbsolutePath();
		}
		
		// Pasa las políticas indicadas al array de resultados de las políticas
		politicas = new ArrayList<PolicyResult> ();
		if ((policies != null) && (policies.size() > 0)) {
			Iterator<IValidacionPolicy> it = policies.iterator();
			while (it.hasNext()) {
				IValidacionPolicy valPol = it.next();
				if (valPol != null) {
					PolicyResult pr = new PolicyResult();
					pr.setPolicyVal(valPol);
					politicas.add(pr);
				}
			}
		}
			
		resultado = new ResultadoValidacion();
		X509Certificate cert = null;
		XMLSignature firmaDocumento = null;
		String uriDS = null;
		
		try {
			firmaDocumento = new XMLSignature((Element)firma, baseUri);
			if (resolvers != null) {
				Iterator<ResourceResolverSpi> it = resolvers.iterator();
				while (it.hasNext()) {
					firmaDocumento.addResourceResolver(it.next());
				}
			}
			uriDS = firmaDocumento.getBaseNamespace();
		} catch (XMLSignatureException e) {
			LOGGER.error(e.getMessage(), e);
			resultado.setDatosFirma(new DatosFirma());
			resultado.setDoc(firma.getOwnerDocument());
			resultado.setFirmados(new ArrayList<String> ());
			// Error en la validación. Se produjo un error genérico
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR7) + 
					ConstantesXADES.DOS_PUNTOS_ESPACIO + e.getMessage());
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);
			return resultado;
		} catch (XMLSecurityException e) {
			LOGGER.error(e.getMessage(), e);
			resultado.setDatosFirma(new DatosFirma());
			resultado.setDoc(firma.getOwnerDocument());
			resultado.setFirmados(new ArrayList<String> ());
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR7) + 
					ConstantesXADES.DOS_PUNTOS_ESPACIO + e.getMessage());
			resultado.setValidate(false);
			return resultado;
		}
		
		try {
			resultado.setBaseURI(new URI(URIEncoder.encode(baseUri, "UTF-8")));
		} catch (URISyntaxException ex) {
			LOGGER.error(ex.getMessage(), ex);
		} catch (UnsupportedEncodingException ex) {
			LOGGER.error(ex.getMessage(), ex);
		}
		
		// Se instancia la estructura que almacena los datos recogidos de la firma
		datosFirma = new DatosFirma();
		firmados = new ArrayList<String> ();
		arrayDatosSello = new ArrayList<DatosSelloTiempo>();
		arrayDatosCRL = new ArrayList<DatosCRL>();
		arrayDatosOCSP = new ArrayList<DatosOCSP> ();
		ArrayList<String> cfA = new ArrayList<String>();
		resultado.setDatosFirma(datosFirma);
		resultado.setDoc(firma.getOwnerDocument());
		resultado.setFirmados(firmados);
		
		// Se obtiene el nodo raíz de la firma		
		EstructuraFirma estructuraFirma = obtenerEsquema((Element)firma); // En este punto se obtiene el esquema de la firma
		if (estructuraFirma == null || estructuraFirma.esquema == null) {
			// No se han encontrado esquemas para validar
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR1));
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR1));
			
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR1));
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.UNKNOWN);			
		} else {
			estructuraFirma.xmlSig = firmaDocumento;
			datosFirma.setEsquema(estructuraFirma.esquema);
			logv.info("Xml Schema: " + estructuraFirma.esquema);
		}
		
		// Se obtiene el identificador del nodo que contiene el valor de la firma
		ArrayList<Element> signatureValues = null;
		try {
			signatureValues = UtilidadTratarNodo.obtenerNodos((Element)firma, 
				2, new NombreNodo(uriXmlNS, ConstantesXADES.SIGNATURE_VALUE));
		} catch (FirmaXMLError e) {
			LOGGER.error(e.getMessage(), e);
			logv.error(e.getMessage());
			
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR5));
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);			
			return resultado;
		}
		
		if (signatureValues != null && signatureValues.size() > 0) {
			String id = ((Element)signatureValues.get(0)).getAttribute(ConstantesXADES.ID);
			if (id != null && !ConstantesXADES.CADENA_VACIA.equals(id))
				datosFirma.setSigValueId(id);
		}
				
		// Se obtienen las constantes dependientes del esquema
		getConstantesEsquema(estructuraFirma.esquema);		
		
		// Se genera la cadena de certificados, obtenemos el certificado firmante, se valida el valor de firma
		// y se almacena la cadena de firma generada en los datos de firma
		if (estructuraFirma != null && estructuraFirma.esquema != null) {
			obtenerCadenaCertificados(estructuraFirma);
		}
		
		// Obtiene el listado de elementos Reference
		ArrayList<Element> nodosReference = new ArrayList<Element>();
		SignedInfo si = firmaDocumento.getSignedInfo();
		for (int i = 0; i < si.getLength(); i++) {
			try {
				Reference ref = si.item(i);
				nodosReference.add(si.item(i).getElement());
				DatosNodosFirmados dnf = new DatosNodosFirmados();
				dnf.setReference(new ReferenceProxy(ref));
				datosFirma.addDatosNodoFirmado(dnf);
			} catch (XMLSecurityException ex) {
				LOGGER.warn(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_7, ex.getMessage()));
			}
		}
		
		int nodeFileReferenceLength = nodosReference.size(); 
		for (int f=0; f<nodeFileReferenceLength ; f++)
		{
			Element elementReference = nodosReference.get(f);
			String referenceUri = elementReference.getAttribute(ConstantesXADES.URI_MAYUS);
			
			if (referenceUri != null) {
				firmados.add(referenceUri);
			}
			
			if (referenceUri != ConstantesXADES.CADENA_VACIA &&
					referenceUri.startsWith(ConstantesXADES.ALMOHADILLA)) {
				// TODO: permitir sentencias XPATH/XPOINTER
				Element nodo = UtilidadTratarNodo.getElementById(firma.getOwnerDocument(), referenceUri.substring(1));

				if (nodo != null) {
					// Se chequea si la firma contiene algún nodo reference apuntando a un signatureValue distinto del propio
					if (nodo.getLocalName().equals(ConstantesXADES.SIGNATURE_VALUE) &&
							!referenceUri.substring(1).equals(datosFirma.getSigValueId())) {
						// En éste caso, se valida que en el nodo CounterSignature de la firma "padre", sólo exista una firma
						Node cs = firma.getParentNode(); // ¿Nodo CounterSignature?
						if (cs.getNodeType() == Element.ELEMENT_NODE) {
							if (((Element)cs).getLocalName().equals(ConstantesXADES.COUNTER_SIGNATURE)) { // TODO: comprobar que es del esquema xades
								if (cs.getChildNodes() == null || cs.getChildNodes().getLength() != 1) {
									LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR172));
									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR173));
									
									resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR173));
									resultado.setValidate(false);
									resultado.setResultado(ResultadoEnum.INVALID);
									
									return resultado;
								}
							}
						}
						cfA.add(referenceUri.substring(1));
					}
				} 
			}
		}
		
		if (cfA != null && cfA.size() > 0)
			datosFirma.setContraFirma(cfA);
		
		// Se obtiene el nodo padre de la firma para chequear si se trata de una contrafirma
		Node padre = firma.getParentNode();
		if (padre != null) {
			if (ConstantesXADES.COUNTER_SIGNATURE.equals(padre.getLocalName())) {
				// Es una contrafirma, se valida que contenga alguna referencia al SignatureValue de la firma que lo contiene
				boolean hayReferencia = false;
				
				// Se obtiene el nodo SignatureValue, que estará 4 niveles por encima, según esquema
				Node sigNode = padre.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode();
				NodeList hijosSigNode = sigNode.getChildNodes();
				Element sigValueNode = null;
				for (int i=0; i<hijosSigNode.getLength() ; i++) {
					if (ConstantesXADES.SIGNATURE_VALUE.equals(hijosSigNode.item(i).getLocalName()))
						sigValueNode = ((Element)hijosSigNode.item(i));
				}
				
				if (sigValueNode == null) {
					// Firma inválida. No se pudo obtener el nodo de firma
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
					
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
					resultado.setValidate(false);
					resultado.setResultado(ResultadoEnum.INVALID);			
					return resultado;
				}
				
				// Se obtienen las uris de todos los nodos reference de la contrafirma y se comparan con el obtenido previamente
				for (int f=0; f<nodeFileReferenceLength ; f++) {
					Element elementReference = nodosReference.get(f);
					String uri = elementReference.getAttribute(ConstantesXADES.URI_MAYUS);
					
					if (uri != null && uri != ConstantesXADES.CADENA_VACIA &&
							uri.startsWith(ConstantesXADES.ALMOHADILLA)) {
								
						Element nodoSigValue = UtilidadTratarNodo.getElementById(firma.getOwnerDocument(), uri.substring(1));
						if (nodoSigValue != null && nodoSigValue.equals(sigValueNode)) {
							hayReferencia = true;
							if (XAdESSchemas.XAdES_132.equals(estructuraFirma.esquema)) {
								String tipo = elementReference.getAttribute(ConstantesXADES.TYPE);
								if (!ConstantesXADES.SCHEMA_COUNTER_SIGNATURE.equals(tipo)) {
									LOGGER.warn("Atención. Nodo Reference no está incluyendo tipo Contrafirma (ETSI TS 101 903 v1.3.2 7.2.4.1");
								}
							}
						}
					}
				}
				
				if (!hayReferencia) {
					// La contrafirma no está firmando el nodo SignatureValue de la firma que lo contiene
					LOGGER.error("Contrafirma mal formada: No se encuentra una referencia bien formada al nodo \"" +
							sigValueNode.getAttribute(ConstantesXADES.ID) + "\"");
					logv.error("La contrafirma no esta firmando el nodo SignatureValue de la firma que lo contiene");
					
					resultado.setLog("Contrafirma inválida. La firma validada no contrafirma a la firma que lo contiene");
					resultado.setValidate(false);
					resultado.setResultado(ResultadoEnum.INVALID);			
					return resultado;
				}
			}
		}

		if (cadenaCertificados != null && cadenaCertificados.size() != 0)  {
			cert = cadenaCertificados.get(0);
			logv.info("Signing Certificate: " + cert.getSubjectDN().toString());
		}
		else { // No se encontró el certificado firmante
			if (estructuraFirma.esquema != null) {
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
				resultado.setValidate(false);
				resultado.setResultado(ResultadoEnum.INVALID);
				return resultado;
			}
			else { 
				return resultado;
			}
		}
			
		if (cert != null) {
			try {
				esValido = firmaDocumento.checkSignatureValue(cert);
			} catch (XMLSignatureException ex) {
				LOGGER.error(ex,ex);
				// Error en la validación. La firma no tiene un formato correcto
				LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR105));
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR105));
				
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR105));
				resultado.setValidate(false);
				resultado.setResultado(ResultadoEnum.INVALID);
				return resultado;
			}
			if (esValido) {
				logv.info("XMLDSig Core Validation: Passed");
				resultado.setIntegrity(true);
			} else {
				// Chequeo de integridad
				for (int i = 0; i < nodosReference.size(); i++) {
					Element elementReference = nodosReference.get(i);
					// Se recupera el valor declarado
					NodeList childs = elementReference.getElementsByTagName("*");
					String method = null;
					String digest = null;
					for (int j = 0; j < childs.getLength(); ++j) {
						if (childs.item(j).getLocalName().contains(ConstantesXADES.DIGEST_VALUE)) {
							digest = childs.item(j).getFirstChild().getNodeValue();
						} else if (childs.item(j).getLocalName().contains(ConstantesXADES.DIGEST_METHOD)) {
							NamedNodeMap attribs = childs.item(j).getAttributes();
							for (int k = 0; k < attribs.getLength(); ++k) {
								if (attribs.item(k).getLocalName().contains(ConstantesXADES.ALGORITHM)) {
									method = attribs.item(k).getNodeValue();
								}
							}
						}
					}
					byte abyte0[] = Base64.decode(digest);
					
					// Se calcula el valor real
					String uri = elementReference.getAttribute(ConstantesXADES.URI_MAYUS);
					byte abyte1[] = null;
					if (uri != null && uri != ConstantesXADES.CADENA_VACIA) {
						if (uri.startsWith(ConstantesXADES.ALMOHADILLA)) {
							uri = uri.substring(1);
						}
						Element nodoReferenciado = UtilidadTratarNodo.getElementById(firma.getOwnerDocument(), uri);
				        
				        try {
				        	if (nodoReferenciado != null) {
				    			MessageDigestAlgorithm alg = MessageDigestAlgorithm.getInstance(nodoReferenciado.getOwnerDocument(), method);
				    			alg.reset();
				    			// Se tiene en cuenta la canonicalización  
					    		NodeList nodosCanonicalizationMethod = ((Element)elementReference.getParentNode()).getElementsByTagNameNS(ConstantesXADES.SCHEMA_DSIG, 
					    					ConstantesXADES.CANONICALIZATION_METHOD);
					    		int numNodosCanonicalization = nodosCanonicalizationMethod.getLength();
					    		CanonicalizationEnum canonicalization = null;
					    		if (numNodosCanonicalization > 0) {
					    			Element nodoCanonicalizationMethod = (Element)nodosCanonicalizationMethod.item(0);
					    			String meth = nodoCanonicalizationMethod.getAttribute(ConstantesXADES.ALGORITHM);
					    			canonicalization = CanonicalizationEnum.getCanonicalization(meth);
					    			if (canonicalization.equals(CanonicalizationEnum.UNKNOWN)) { 
					    				canonicalization = CanonicalizationEnum.C14N_OMIT_COMMENTS;
					    			}
					    		}
					    		if (uri.equals(ConstantesXADES.CADENA_VACIA)) {				            	
					    			Transforms tr = new Transforms(firma.getOwnerDocument());
					    			tr.addTransform(canonicalization.toString());
					    			XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodoReferenciado);
					    			xmlSignatureInput.setExcludeNode(firma);
					    			XMLSignatureInput resultado = tr.performTransforms(xmlSignatureInput);

					    			alg.update(resultado.getBytes());
					    		} else {
					    				alg.update(UtilidadTratarNodo.obtenerByte(nodoReferenciado, canonicalization));
					    		}
				    			abyte1 = alg.digest();
				    		} else {
				    			byte[] file = UtilidadFicheros.readFile(new File(new File(new URI(baseUri)).getAbsolutePath() + File.separator + uri));
				    			MessageDigest md = UtilidadFirmaElectronica.getMessageDigest(method);
				    			md.reset();
				    			md.update(file);
				    			abyte1 = md.digest();
				    		}
				        } catch(Exception e) {
				        	LOGGER.debug("Error al comprobar la integridad", e);
				        }
				        
				        // Se comparan ambos resultados
				        boolean flag = MessageDigestAlgorithm.isEqual(abyte0, abyte1);
				        resultado.setIntegrity(flag);
				        if (flag) {
				        	if (LOGGER.isDebugEnabled())
				        		LOGGER.debug("La referencia que apunta a \"" + uri + "\" pasa el chequeo de integridad");
				        } else {
				        	if (LOGGER.isDebugEnabled()) {
				        		LOGGER.debug("La referencia que apunta a \"" + uri + "\" NO pasa el chequeo de integridad");
				        		LOGGER.debug("Leído: " + Base64.encodeBytes(abyte0));
				        		LOGGER.debug("Calculado: " + Base64.encodeBytes(abyte1));
				        	}
				        	break;
				        }
					}
				}
				
				// Firma inválida
				LOGGER.debug("XMLDSig Core Validation: Not passed");
				logv.error("XMLDSig Core Validation: Not passed");
				
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR105));
				resultado.setValidate(false);
				resultado.setResultado(ResultadoEnum.INVALID);
			}
		} else {
			// Error en la validación. No se ha encontrado el certificado
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR5));
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR5));
			
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR5));
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);			
			return resultado;
		}
		
		// Se obtiene la información asociada a lo firmado, si existe
		getDataObjectFormat(firma.getOwnerDocument(), estructuraFirma);
		
		// Una vez que sabemos que la firma es una firma XADES bien formada verificamos de qué tipo
		// específico de firma se trata: XADES-BES, XAdES-EPES, XADES-T, XAdES-C, XAdES-X, XADES-XL o XAdES-A
		try {
			tipoDocFirma = tipoFirma(estructuraFirma);
			logv.info ("XAdES type: " + tipoDocFirma.getTipoXAdES().name());
			datosFirma.setTipoFirma(tipoDocFirma);
		} catch (BadFormedSignatureException e) {
			LOGGER.error(e.getMessage());
			// Firma inválida. La firma no tiene un formato correcto
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR4));
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);
			logv.error("Bad XAdES format. Invalid Signature: " + e.getMessage());
			
			esValido = false;
			tipoDocFirma = new DatosTipoFirma(EnumFormatoFirma.XMLSignature, false, false);
		}
		
		// Si es una firma XADES válida continúa con el proceso de validación
		if (esValido)
		{
			if (tipoDocFirma.getTipoXAdES().equals(EnumFormatoFirma.XMLSignature)) {
				resultado.setValidate(true);
				resultado.setResultado(ResultadoEnum.VALID);
				resultado.setEnumNivel(EnumFormatoFirma.XMLSignature);
				return resultado;
			}
			
			if (validarXadesBes(estructuraFirma)) 
			{		
				if (tipoDocFirma.esXAdES_EPES()) {  // El documento es una firma XADES-EPES válida
					LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO5));
					
					logv.info("XAdES-EPES validation: Valid");
					
					resultado.setNivelValido(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO5));  
				} else {  							// El documento es una firma XADES-BES válida
					LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO1));
					
					logv.info("XAdES-BES validation: Valid");
					
					resultado.setNivelValido(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO1));  
				}  

				resultado.setEnumNivel(EnumFormatoFirma.XAdES_BES);
				resultado.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_14));

				// Almacenamos los roles de la firma
				datosFirma.setRoles(obtenerRoles(estructuraFirma));

				// Validación para XADES-T. Realiza la validación tanto si la firma es XADES-T como XADES-XL
				if((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_BES)>0)
				{
					// Valida el sello de tiempo de la firma XADES-T
					if(validarSelloTiempoXadesT(estructuraFirma))
					{
						// El documento es una firma XADES-T válida
						LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO2));						
						resultado.setEnumNivel(EnumFormatoFirma.XAdES_T);
						resultado.setNivelValido(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO2));
						datosFirma.setDatosSelloTiempo(arrayDatosSello);

						// Valida los campos CompleteCertificateRefs y CompleteRevocationRefs de la firma XADES-C

						if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_T)>0) {

							// Se valida XADES-C
							// AppPerfect: Falso positivo
							if (validarXadesC(uriDS, cert, estructuraFirma)) {
								LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO4));
								
								logv.info("XAdES-C validation: Valid");
								
								resultado.setEnumNivel(EnumFormatoFirma.XAdES_C);
								resultado.setNivelValido(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO4));
								resultado.setLog(ConstantesXADES.CADENA_VACIA);
								datosFirma.setDatosOCSP(arrayDatosOCSP);
								datosFirma.setDatosCRL(arrayDatosCRL);

								// Validación para XADES-XL. Solo se realiza si la firma es XADES-XL
								if((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_X)>=0)
								{
									// La firma XADES-XL está formado por otros formatos de firma XADES intermedios:
									// XADES-X y XADES-C que es necesario validar antes de validar XADES-XL

									// Validamos el sello de tiempo de XADES-X (La firma XAdES_XL quedó validada al validar XAdES-C)
									// AppPerfect: Falso positivo
									if (validarSelloTiempoXadesX(estructuraFirma, ConstantesXADES.SIG_AND_REFS_TIME_STAMP) || validarSelloTiempoXadesX(estructuraFirma, ConstantesXADES.REFS_ONLY_TIME_STAMP))
									{
										// La firma es una XAdES-X/XL válida
										resultado.setEnumNivel((tipoDocFirma.getTipoXAdES()));  
										if (EnumFormatoFirma.XAdES_X.compareTo((tipoDocFirma.getTipoXAdES())) == 0) {
											resultado.setNivelValido(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO7));
											LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO7));
											
											logv.info("XAdES-X validation: Valid");
											
										} else {  
											resultado.setNivelValido(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO3));
											LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO3));
											
											logv.info("XAdES-XL validation: Valid");
											
										}
										datosFirma.setDatosSelloTiempo(arrayDatosSello);
										datosFirma.setDatosOCSP(arrayDatosOCSP);
									} 
								}
							} else {
                                datosFirma.setDatosOCSP(arrayDatosOCSP);							    
							}
						}
					}
					else
					{
						// Si el sello de tiempo de la firma XADES-T no es válido, se modifica la respuesta ya se que
						// que la firma XADES-T está incluida dentro de una firma XADES-XL o no. En el primer caso se
						// debe distinguir el primer sello de tiempo perteneciente a XADES-T del segundo sello de
						// tiempo perteneciente a XADES-X
						String sello = ConstantesXADES.CADENA_VACIA;
						if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_XL)==0)
							sello = ConstantesXADES.LIBRERIAXADES_PRIMER;

						// El valor del sello de tiempo de la firma no es válido
						LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8) +	ConstantesXADES.ESPACIO +
								sello + ConstantesXADES.ESPACIO +
								I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO +
								(tipoDocFirma.getTipoXAdES()) + ConstantesXADES.ESPACIO +
								I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR10));
						// Se escribe el log de sello de tiempo inválido si el Log contiene el mensaje por defecto
						// TODO: quitarlo cuanto antes
						if (i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_14).equals(resultado.getLog())) {
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8) +	ConstantesXADES.ESPACIO +
									sello + ConstantesXADES.ESPACIO +
									I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO +
									(tipoDocFirma.getTipoXAdES().name()) + ConstantesXADES.ESPACIO +
									I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR10));
						}
						esValido = false;
					}
				} else {
					try {
						cert.checkValidity(new Date(System.currentTimeMillis()));
					} catch (CertificateExpiredException e) {
						// El certificado firmante esta caducado
						LOGGER.info("El certificado firmante ha caducado");
						logv.info("El certificado firmante ha caducado");
						resultado.appendLog("El certificado firmante ha caducado");
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.INVALID);			
						esValido = false;
					} catch (CertificateNotYetValidException e) {
						// El certificado firmante esta caducado
						LOGGER.info("El certificado firmante aún no es válido");
						logv.info("El certificado firmante aún no es válido");
						resultado.appendLog("El certificado firmante aún no es válido");
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.INVALID);			
						esValido = false;
					}
				}
			}
			resultado.setValidate(esValido);
			if (!ResultadoEnum.UNKNOWN.equals(resultado.getResultado())) {
				resultado.setResultado(esValido?ResultadoEnum.VALID:ResultadoEnum.INVALID);
			}
			
			if (tipoDocFirma.esXAdES_A()) {
				// Se valida XADES-A
				try {
					if (validaXadesA(estructuraFirma)) {
						LOGGER.info("La firma contiene un sello de tiempo XAdES-A válido");
					} else {
						LOGGER.info("La firma contiene un sello de tiempo XAdES-A NO válido");
						logv.info("La firma contiene un sello de tiempo del tipo XAdES-A NO válido");

						if (resultado.getLog() != null) {
	                        resultado.setLog("Un sello de tiempo de tipo A es inválido - " + resultado.getLog());						    
						} else {
	                        resultado.setLog("Un sello de tiempo de tipo A es inválido");						    
						}
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.INVALID);
						return resultado;
					}
				} catch (Exception e) {
					LOGGER.error(e.getMessage(), e);
				}
			}
			
			if (esValido) { // Se comprueba la fecha de firma
				Date fechaFirma = datosFirma.getFechaFirma();
				if (EnumFormatoFirma.XAdES_BES.compareTo(datosFirma.getTipoFirma().getTipoXAdES()) > 0) {
					fechaFirma = datosFirma.getDatosSelloTiempo().get(0).getFecha();
				}

				if (fechaFirma != null) {
					if (fechaFirma.after(new Date())) {
						esValido = false;
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR170));  
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR170));  

						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR170));
					}

					// Se valida que la fecha de firma quede dentro del periodo de validez del certificado de firma
					Date notAfter = cert.getNotAfter();
					Date notBefore = cert.getNotBefore();
					if (fechaFirma.after(notAfter) || fechaFirma.before(notBefore)) {
						esValido = false;
						// La fecha de firma no esta dentro del periodo de validez del certificado firmante
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR159));
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR159));

						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR159));
					}
				}
			}
			
			// Validación del Nodo Policy del nivel EPES, si existe
			buscaXadesEpes(estructuraFirma);
		}
		
		// Valida las policies indicadas
		//if (esValido && (politicas.size() > 0)) {
		if (politicas.size() > 0) {		
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Se validan " + politicas.size() + " políticas");
			}
			Iterator<PolicyResult> it = politicas.iterator();
			while (it.hasNext()) {
				PolicyResult pr = it.next();
				if (pr.getPolicyVal() != null) {
					try {
						IValidacionPolicy valPol = pr.getPolicyVal();
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Manager de política empleado: " + valPol.getIdentidadPolicy());
						}
						if (truster != null) {
							valPol.setTruster(truster);
						}
						PolicyResult prTemp = valPol.validaPolicy((Element)firma, resultado);
						pr.copy(prTemp);
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Política validada con éxito: " + pr.getResult());
						}
					} catch (Throwable th) {
						// Error validando política
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR109), th);
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Error al validar la política: " + th.getMessage());
						}
						
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.INVALID);
						// Error al validar una Policy. Validez de la firma desconocida
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR71));
						pr.setResult(PolicyResult.StatusValidation.unknown);
						pr.setDescriptionResult(th.getMessage());
						break;
					}
					
					if (PolicyResult.StatusValidation.invalid.equals(pr.getResult())) {
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.INVALID);
						resultado.setLog(pr.getDescriptionResult());
					} else if (PolicyResult.StatusValidation.unknown.equals(pr.getResult())) {
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.UNKNOWN);
						resultado.setLog(pr.getDescriptionResult());
					}

					// TODO: dejar aviso en el log de resultados sobre si la policy es inválida
					// TODO: incluir la información extraida de la política (documentacion y URIs; incluir noticias si se valida correctamente)
				} else {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("No se encontró validador para " + pr.getPolicyID());
					}
				}
				
				// Se obtienen los datos de la política
				StatusValidation sv = pr.getResult();
    			String policyDescResult = pr.getDescriptionResult();
    			PolicyResult.DownloadPolicy[] policyDownload = pr.getDownloable();
    			String[] policyNotices = pr.getNotices();
    			
				boolean valido = false;
				String policyID = null;
    			if (PolicyResult.StatusValidation.valid.equals(sv)) {
    				policyID = "Accomplished policy: " + pr.getPolicyID();
    				valido = true;
    			} else if (PolicyResult.StatusValidation.invalid.equals(sv)) {
    				policyID = "Unaccomplished policy: " + pr.getPolicyID();
    			} else if (PolicyResult.StatusValidation.unknown.equals(sv)) {
    				if (pr.getPolicyID() == null)
    					policyID = "Implied policy";
    				else
    					policyID = "Unkown policy";
    				valido = true;
    			}
				
				logv.abreTag(valido);
				logv.info(policyID, 2);
				if (!valido && policyDescResult != null)
					logv.info(policyDescResult, 2);
				for (int i = 0; policyDownload != null && i < policyDownload.length; ++i) {
					String value = policyDownload[i].uri.toString();
					if (PolicyResult.StatusValidation.unknown.equals(policyDownload[i].status))
						value = "(Unknown integrity): ".concat(value);
					else if (PolicyResult.StatusValidation.valid.equals(policyDownload[i].status))
						value = "(Checked integrity): ".concat(value);
					else 
						continue;
					logv.info("Download URI " + value, 2);
				}
				for (int i = 0; policyNotices != null && i < policyNotices.length; ++i) {
					logv.info("Notice: " + policyNotices[i].toString(), 2);
				}
				logv.cierraTag(valido);				
			}
		}
		
		if (politicas.size() > 0) {
			datosFirma.setPoliticas(politicas);
		}

		return resultado;
	}

	/**
	 * Busca si la firma tiene indicada alguna política y la añade al listado de políticas a validar.
	 * 
	 * @param policies listas de políticas a validar
	 * @return
	 */
	private void buscaXadesEpes(EstructuraFirma estructuraFirma) {
		
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Buscando nodos de políticas");
		}
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		// Se valida la politica de firmas si existe el nodo
		ArrayList<Element> signaturePolicyList = null;
		try {
			signaturePolicyList = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.LIBRERIAXADES_POLICY_SIGNATUREPOLICYIDENTIFIER));
		} catch (FirmaXMLError e) {
			LOGGER.error(e.getMessage(), e);
			logv.error(e.getMessage());
			
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR5));
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);			
			return;
		}

		int numNodosSigPolicy = 0;
		if (signaturePolicyList != null)
			numNodosSigPolicy = signaturePolicyList.size();
		
		if (numNodosSigPolicy == 0 && (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaURI))) {
			// El nodo SignaturePolicyIdentifier es requerido por el esquema XAdES 1.1.1
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR110));
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR111));
			esValido = false;
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);
			return;
		}
		
		if (numNodosSigPolicy == 1) {
			// Se recoge el nodo SignaturePolicyIdentifier
			Element signaturePolicyIdentifierNode = (Element) signaturePolicyList.get(0);
			SignaturePolicyIdentifier spi;
			try {
				spi = new SignaturePolicyIdentifier(estructuraFirma.esquema);
				if (!spi.isThisNode(signaturePolicyIdentifierNode))
					// No se ha encontrado política
					throw new InvalidInfoNodeException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR112));
				spi.load((signaturePolicyIdentifierNode));
			} catch (InvalidInfoNodeException ex) {
				//El nodo encontrado no es un SignaturePolicyIdentifier válido
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR164) + 
						ConstantesXADES.ESPACIO + ex.getMessage(), ex);
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR164) + 
						ConstantesXADES.ESPACIO + ex.getMessage());
				
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR114));
				esValido = false;
				resultado.setValidate(false);
				resultado.setResultado(ResultadoEnum.INVALID);
				return;
			}

			// Se busca el validador asociado
			PoliciesManager policiesManager = PoliciesManager.getInstance();
			PolicyKey clave = policiesManager.newPolicyKey(null, ConstantesXADES.LIBRERIAXADES_IMPLIEDPOLICY_MANAGER);
			if (!spi.isImplied()) {
				clave.hash = Utilidades.binary2String(Base64Coder.decode(spi.getSignaturePolicyId().getSigPolicyHash().getDigestValue().getValue()));
				clave.uri = spi.getSignaturePolicyId().getSigPolicyId().getIdentifier().getUri();
			}
			IValidacionPolicy valPol = policiesManager.getValidadorPolicy(clave);
			if (valPol == null) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("No se pudo encontrar validador para la política " + clave.uri);
					LOGGER.debug("Hash obtenido " + clave.hash);
					LOGGER.debug("Políticas disponibles: " + politicas.size());
				}
				PolicyResult pr = new PolicyResult();
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR104));
				pr.setResult(PolicyResult.StatusValidation.unknown);
				pr.setPolicyID(clave.uri);
				politicas.add(pr);
			} else if (!politicas.contains(valPol)) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Validador de política nuevo: " + valPol.getIdentidadPolicy());
					LOGGER.debug("Para la política " + clave.uri);
					LOGGER.debug("Hash obtenido " + clave.hash);
					LOGGER.debug("Políticas disponibles: " + politicas.size());
				}
				PolicyResult pr = new PolicyResult();
				pr.setPolicyVal(valPol);
				politicas.add(pr);
			}
		}
		else if (numNodosSigPolicy > 1) {
			// Demasiadas políticas en un nodo de firma
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR115));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR115));
			
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR116));
			esValido = false;
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);
			return;
		}
	}
	

	private void mostrarErrorValidacion(Exception ex) throws FirmaXMLError{
		// El documento de firma no es un documento XML bien formado
		LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR28), ex);
		throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR28));
	}
	
	/**
	 * Mecanismo para proporcionar información mediante DataObjectFormat
	 * @param estructuraFirma
	 */
	private void getDataObjectFormat(Document doc, EstructuraFirma estructuraFirma) {
		
		// Se preparar las varibles que recogerán la información
		DatosNodosFirmados datos = null;
		ArrayList<Element> signedDataObjectProperties = null;
		DataObjectFormat dof = null;
		Element dataOF = null;
		Node attId = null;
		
		// Se recoge el nodo SignedDataObjectProperties, si existe
		try {
			signedDataObjectProperties = UtilidadTratarNodo.obtenerNodos(estructuraFirma.firma, 4, 
        		new NombreNodo(estructuraFirma.esquema.getSchemaUri(), ConstantesXADES.XADES_SIGNED_DATA_OBJECT_PROPERTIES));
        } catch (FirmaXMLError e) {
        	LOGGER.debug("No se pudo recoger el nodo SignedDataObjectProperties", e);
        }
  	                          
        if(signedDataObjectProperties != null && signedDataObjectProperties.size() == 1) {
        	Element signedDOP = signedDataObjectProperties.get(0);
        	// Se cogen todos los hijos de SignedDataObjectProperties
        	NodeList dataOFs = signedDOP.getChildNodes();
        	int dofLength = dataOFs.getLength();
        	Node item = null;
        	for(int i = 0; i < dofLength; ++i) {
        		item = dataOFs.item(i);
        		if (!(item instanceof Element))
        			continue;
        		dataOF = (Element) item; // Se recoge el nodo DataObjectFormat
        		
        		dof = new DataObjectFormat(estructuraFirma.esquema);
        		try {
					dof.load(dataOF); // Se lee el nodo DataObjectFormat
				} catch (InvalidInfoNodeException e) {
					LOGGER.error(e.getMessage(), e);
					continue;
				}
				
				// Busca el Reference relacionado con este DataObjectFormat
        		
				// Se rellenan los datos del fichero firmado
				if (dataOF.getAttributes() != null && dataOF.getAttributes().getLength() > 0) {
					if (dataOF.getAttributes() != null) {
						attId = dataOF.getAttributes().getNamedItem(ConstantesXADES.XADES_TAG_OBJECT_REFERENCE);
					}
					if (attId != null) {
						// TODO: obtener correctamente el element señalado por ObjectReference
						String uri = attId.getTextContent();
						if ((uri != null) && (uri.startsWith("#"))) {
							datos = datosFirma.getDatosNodoFimadoByReferenceId(uri.substring(1));						
							if (datos != null) {
								if (dof.getObjectIdentifier() != null) {
									datos.setObjectIdentifier(dof.getObjectIdentifier());
								}
								if (dof.getDescription() != null) {
									datos.setDescription(dof.getDescription().getValue());
								}
								if (dof.getMimeType() != null) {
									datos.setMimeType(dof.getMimeType().getValue());
								}
								if (dof.getEnconding() != null) {
									datos.setEncoding(dof.getEnconding().getValue());
								}
							} else {
								LOGGER.warn(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_8, uri));
							}
						}
					}
				}
				if (datos == null) {
					// TODO: firma con DataObjectFormat mal formado (no apunta a un reference válido), avisar
				}
        	}
        	
        } else {
        	LOGGER.debug("El nodo SignedDataObjectProperties no existe o no es único");
        }
	}
	
	/**
	 * Valida XAdES-BES.
	 * @return true Si la fecha de firma es anterior a la actual, si el certificado firmante es el que
	 *              aparece en el nodo SigningCertificate y si existe al menos un nodo Reference con una URI apuntando al nodo SignedProperties.
	 *              y dicho nodo contiene un attributo de tipo Type con un valor dependiente del esquema
	 */
	private boolean validarXadesBes(EstructuraFirma estructuraFirma) {
		
		if (estructuraFirma.firma == null) {
			esValido = false;
			// No se encuentra la firma a validar
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR76));
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR76));
			return false;
		}
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		// Se valida, si existe, que SigningTime no sea posterior a la fecha actual		
		Date fechaFirma = obtenerFechaFirma(estructuraFirma);
		// Se almacena su valor
		datosFirma.setFechaFirma(fechaFirma);
		
		// Se obtiene la cadena de certificados contenida en SigningCertificate si existe
		ArrayList<DatosX509> certificadosSigning = new ArrayList<DatosX509> ();
		DatosX509 datos = new DatosX509();
		ArrayList<Element> nodosSigningCertificate = UtilidadTratarNodo.obtenerNodos(estructuraFirma.signedSignatureProperties, null, 
				new NombreNodo(esquemaURI, ConstantesXADES.LIBRERIAXADES_SIGNINGCERTIFICATE));
		if (nodosSigningCertificate != null && nodosSigningCertificate.size() > 0) {
			Node nodoSigningCertificate = nodosSigningCertificate.get(0);
			ArrayList<Element> nodosCert = UtilidadTratarNodo.getElementChildNodes((Element)nodoSigningCertificate, false);
			if (nodosCert == null) {
				esValido = false;
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));			
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
				return false;
			}
			int nodosCertSize = nodosCert.size();
			Element nodoCert = null;
			for(int i = 0; i < nodosCertSize; ++i) {
				nodoCert = (Element) nodosCert.get(i);
				// Carga el elemento con la información de identificación del certificado
				Cert cert = new Cert(estructuraFirma.esquema);
				try {
					cert.load(nodoCert);
				} catch (InvalidInfoNodeException ex) {
					esValido = false;
					// Firma inválida. No se pudo obtener el certificado firmante
					resultado.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_13));
					// Error al obtener la codificación
					LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_11, ex.getMessage()));
					
					logv.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_13) + ex.getMessage());
					
					return false;
				}
				datos.setAlgMethod(cert.getCertDigest().getDigestMethod().getAlgorithm());
				datos.setDigestValue(cert.getCertDigest().getDigestValue().getValue());
				try {
					datos.setIssuer(new X500Principal(cert.getIssuerSerial().getIssuerName()));
				} catch (IllegalArgumentException ex) {
					esValido = false;
					// Firma inválida. No se pudo obtener el certificado firmante
					resultado.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_13));
					// Error al obtener la codificación
					LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_12, ex.getMessage()));
					
					logv.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_13) + ex.getMessage());
					
					return false;
				}
				datos.setSerial(cert.getIssuerSerial().getSerialNumber());
				
				certificadosSigning.add(datos);
			}
		} 

		if (certificadosSigning.size() > 0) { // Si no existe éste nodo, no es preciso validarlo

			// Se compara el certificado firmante (1º de la cadena) contra todos los signingCertificate
			X509Certificate certFirmante = cadenaCertificados.get(0);
			X500Principal certFirmIssuer = certFirmante.getIssuerX500Principal();
			BigInteger certFirmSerial = certFirmante.getSerialNumber();

			boolean coincidencia = false;
			for (int i = 0; i < certificadosSigning.size(); ++i) {
				DatosX509 certAComparar = certificadosSigning.get(i);
				if ((UtilidadCertificados.isSameName(certFirmIssuer, certAComparar.getIssuer())) &&
					(certFirmSerial.equals(certAComparar.getSerial()))) {
					// En caso de que haya alguno coincidente, se busca 1ºKeyInfo/1ºX509Data/X509IssuerSerial
					ArrayList<Element> nodosKeyInfo = new ArrayList<Element>();
					try {
						nodosKeyInfo = UtilidadTratarNodo.obtenerNodos(firma, 2, 
							new NombreNodo(uriXmlNS, ConstantesXADES.LIBRERIAXADES_KEY_INFO));
					} catch (FirmaXMLError e) {
						esValido = false;
						// Firma inválida. No se pudo obtener el certificado firmante
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						// Error al obtener la codificación
						LOGGER.error(e.getMessage(), e);
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3) + e.getMessage());
						
						return false;
					}
					if (nodosKeyInfo.size() > 0) {
						Element nodoKeyInfo = (Element)nodosKeyInfo.get(0); // Tomamos el primer nodo KeyInfo
						Element primerNodoX509Data = (Element)nodoKeyInfo.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_X509_DATA).item(0);
						NodeList nodosIssuerSerial = primerNodoX509Data.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_X509_SERIAL_ISSUER);
						if (nodosIssuerSerial.getLength() > 0) {
							// y si existe, se comprueba que el valor de ese nodo sea el mismo que el indicado en 
							// el nodo de información "certAComparar"
							X500Principal issuer = null;
							BigInteger serial = null;
							Element nodoIssuerSerial = (Element)nodosIssuerSerial.item(0);
							NodeList issuerVals = nodoIssuerSerial.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_X_509_ISSUER_NAME);
							if (issuerVals != null) {
								Element issuerValElement = (Element)issuerVals.item(0);
								String issuerName = issuerValElement.getFirstChild().getNodeValue();
								try {
									issuer = new X500Principal(issuerName);
								} catch (IllegalArgumentException ex) {
									esValido = false;
									// Firma inválida. No se pudo obtener el certificado firmante
									resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
									// Error al obtener la codificación
									LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
									
									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3) + ex.getMessage());
									
									return false;
								} catch (NullPointerException ex) {
									esValido = false;
									// Firma inválida. No se pudo obtener el certificado firmante
									resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
									// Error al obtener la codificación
									LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
									
									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3) + ex.getMessage());
									
									return false;
								}
							}
							NodeList serialVals = nodoIssuerSerial.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_X_509_SERIAL_NUMBER);
							if (serialVals != null) {
								Element serialValElement = (Element)serialVals.item(0);
								serial = new BigInteger(serialValElement.getFirstChild().getNodeValue());
							}
							
							if ((UtilidadCertificados.isSameName(certAComparar.getIssuer(), issuer)) &&
								(certAComparar.getSerial().equals(serial))) {
								// El nodo IssuerSerial es válido
							} else {
								esValido = false;
								// Firma inválida. No se pudo obtener el nodo de firma
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
								// No coincide la información del nodo X509IssuerSerial con el certificado de firma
								LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR85));
								
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR85));
								
								return false;
							}
						}
					}
					// Se comprueba que el digest de certFirmante sea igual al encontrado con mismo issuer y serial
					// Cálculo del digest del certificado de firma
					MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(certAComparar.getAlgMethod());
					byte[] digestCertFirmante = null;
					try {
						digestCertFirmante = haseador.digest(certFirmante.getEncoded());
					} catch (CertificateEncodingException e) {
						esValido = false;
						// Firma inválida. No se pudo recuperar el certificado de firma
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						// No se puede codificar el certificado firmante para calcular su digest
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
						
						return false;
					}
					if (Utilidades.isEqual(digestCertFirmante, Base64Coder.decode(certAComparar.getDigestValue()))) {
						// El certificado de firma se corresponde con el nodo SigningCertificate, por lo que es válido
						coincidencia = true;
						// Se elimina el coincidente para la siguiente validación
						certificadosSigning.remove(i);
						
						logv.info("Signing certificate is valid");
						
						break;
					} else {
						esValido = false;
						// Firma inválida. El certificado firmante no es válido
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR136));
						// No coinciden los valores de digest del nodo de firma con los de la cadena generada
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR86));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR86));
						
						return false;
					}
				}	
			}

			// Si no se encontró ninguna coincidencia con el certificado firmante se da la firma por inválida
			if (!coincidencia) {
				esValido = false;
				// Firma inválida. El certificado de firma es inválido
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR136));
				// El certificado de firma esta incorrectamente identificado
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR87));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR87) + " because it not match the information contained in the SigningCertificate node.");
				
				return false;
			}

			// Se comprueba que en el resto de SigningCertificate, tenga coincidencia con alguno dentro de las cadenas generadas
			int validos = 0;
			for (int i = 0; i < certificadosSigning.size(); ++i) {
				DatosX509 certAComparar = certificadosSigning.get(i);
				for (int x = 0; x < cadenaCertificados.size(); ++x) {
					X509Certificate certContenidos = (X509Certificate)cadenaCertificados.get(x);
					X500Principal certContIssuer = certContenidos.getIssuerX500Principal();
					BigInteger certContSerial = certContenidos.getSerialNumber();

					if ((UtilidadCertificados.isSameName(certContIssuer, certAComparar.getIssuer())) &&
						(certContSerial.equals(certAComparar.getSerial()))) {
						// Cálculo del digest del certificado de firma
						MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(certAComparar.getAlgMethod());
						byte[] digestCertContenidos = null;
						try {
							digestCertContenidos = haseador.digest(certContenidos.getEncoded());
						} catch (CertificateEncodingException e) {
							esValido = false;
							// No se puede codificar el certificado contenido en KeyInfo para calcular su digest
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
							// Se produjo un error: CertificateEncodingException
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_8), e);
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52) + e.getMessage());
							
							return false;
						}
						if (Utilidades.isEqual(digestCertContenidos, Base64Coder.decode(certAComparar.getDigestValue()))) {
							// Certificado válido
							validos++;
							continue;
						} else {
							esValido = false;
							// Firma inválida. El certificado firmante no es válido
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR136));
							// No coinciden los valores de digest de los nodos SigningCertificate con los de la cadena de firma
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR88));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR88));
							
							return false;
						}
					} 
				}
			}
			
			if (validos < certificadosSigning.size()) {
				esValido = false;
				// Hay certificados dentro del nodo SigningCertificate sin coincidencia con los certificados de referencia
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR89));
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR89));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR89));
				
				return false;
			}
		}
		
		// Se valida que exista un Reference con la URI apuntando al Id de SignedProperties (dependiente del esquema)
		ArrayList<Element> nodosSignedProperties = new ArrayList<Element> ();
		try {
			nodosSignedProperties = UtilidadTratarNodo.obtenerNodos(firma, 3, 
					new NombreNodo(esquemaURI, ConstantesXADES.SIGNED_PROPERTIES));
		} catch (FirmaXMLError e) {
			esValido = false;
			// Firma inválida. No se pudo recuperar las propiedades firmadas del documento
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR139));
			// No se encuentra el nodo SignedProperties
			LOGGER.error(e.getMessage(), e);			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR77));			
			return false;
		}
		
		if (nodosSignedProperties.size() == 0) {
			esValido = false;
			// Firma inválida. No se pudo recuperar las propiedades firmadas del documento
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR139));
			// No se encuentra el nodo SignedProperties
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR77));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR77));
			
			return false;
		}
			
		Element nodoSignedProperties = (Element)nodosSignedProperties.get(0);
		Node signedPropertiesId = nodoSignedProperties.getAttributes().getNamedItem(ConstantesXADES.ID);
		if (signedPropertiesId == null) {
			esValido = false;
			// Firma inválida. No se pudo recuperar el identificador de las propiedades firmadas
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR140));
			// El nodo SignedProperties no tiene Id
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR78));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR78));
			
			return false;
		}
		
		String nodoId = signedPropertiesId.getNodeValue();
		
		List<DatosNodosFirmados> references = datosFirma.getDatosNodosFirmados();
		
		if (references.size() == 0) {
			esValido = false;
			// Firma inválida. No se pudo recuperar ningún nodo de referencias
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR141));
			// No se pudo hallar ningún nodo Reference
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR79));
			
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR79));
			
			return false;
		}
		
		String tipoEsperado = UtilidadFirmaElectronica.obtenerTipoReference(esquemaURI);
		
		for (DatosNodosFirmados dnf : references) {
			// Busca el nodo firmado que se corresponde con el SignedProperties
			// La uri utilizada corresponde al esquema xmldSig
			String id = dnf.getId();
			if (id == null) {
				continue;
			}
			if (id.equals(nodoId)) {
				Element reference = dnf.getElementReference();
				if (reference != null) {
					Node referenceType = reference.getAttributes().getNamedItem(ConstantesXADES.TYPE);
					if (referenceType == null) {
						continue;
					}
					if ((tipoEsperado).equals(referenceType.getNodeValue())) {
						// comprueba que esa referencia no tiene aplicadas transformadas que lo modifiquen (excepto la canonicalización)
						if (!dnf.canBeModifiedByTransforms()) {
							return true;
						}
					}
				}
			}
		}
		
		// Si se alcanza éste punto es porque no se encontró ninguna coincidencia
		esValido = false;
		// Firma inválida. No existe ninguna referencia para las propiedades firmadas
		resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR142));
		// No se pudo hallar ningún nodo Reference con la URI del nodo SignedProperties
		LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR80));
		
		logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR80));
		
		return false;
	}
	
	/**
	 * Valida el sello de tiempo correspondiente a la firma XADES-T
	 * @return Falso si el sello no está bien formado o si la firma no se corresponde con el elemento
	 * de firma del documento
	 */
	private boolean validarSelloTiempoXadesT(EstructuraFirma estructuraFirma) {
		
		if (tsValidator == null) {
		    tsValidator = new TimeStampValidator();
		}
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		ArrayList<Element> nodosSignatureTimeStamp = new ArrayList<Element> ();
		NodeList nodesEncapsulatedTimeStamp = null;
		Element encapsulatedTimeStampElement = null;

		try {
			// Se recoge el nodo SignatureTimeStamp
			try {
				nodosSignatureTimeStamp = UtilidadTratarNodo.obtenerNodos(firma, 5, 
						new NombreNodo(esquemaURI, ConstantesXADES.LIBRERIAXADES_SIGNATURETIMESTAMP));
			} catch (FirmaXMLError e) {
				esValido = false;
				// Firma inválida. No se pudo recuperar el sello de tiempo correspondiente al nivel XAdES-T
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR143));
				// No se puede encontrar el nodo SignatureTimeStamp
				LOGGER.error(e.getMessage(), e);	
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR91));
				return esValido;
			}
			
			if (nodosSignatureTimeStamp.size() <= 0) {
				esValido = false;
				// Firma inválida. No se pudo recuperar el sello de tiempo correspondiente al nivel XAdES-T
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR143));
				// No se puede encontrar el nodo SignatureTimeStamp
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR91));	
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR91));
				
				return esValido;
			}
			
			// Se chequea la existencia de un único hijo con una URI apuntando al nodo SignatureValue
			Element nodoSigTimeStamp = (Element)nodosSignatureTimeStamp.get(0);
			NodeList nodosUri = nodoSigTimeStamp.getElementsByTagNameNS(esquemaURI, nombreNodoUri);
			int nodosLenght = nodosUri.getLength();
			if ( (nodosLenght == 0 && !esquemaURI.equals(ConstantesXADES.SCHEMA_XADES_132)) || nodosLenght > 1) {
				// Número de nodos HashDataInfo o nodos Include inesperado (Salvo si es esquema 1.3.2)
				esValido = false;
				// Firma inválida. El nivel XAdES T tiene un número de referencias inesperado
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR144));
				// Número de nodos de referencia inesperado: XXXX
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR94) + 
						ConstantesXADES.ESPACIO + nodosLenght);
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR94) + 
						ConstantesXADES.ESPACIO + nodosLenght);	
				
				return esValido;
			}
			// Se chequea que el nodo HashDataInfo (del esquema 1.1.1) no contenga ningún hijo "Transforms"
			if (esquemaURI.equals(ConstantesXADES.SCHEMA_XADES_111)) {
				NodeList nodosTransforms = ((Element)nodosUri.item(0)).getElementsByTagNameNS(uriXmlNS, ConstantesXADES.TRANSFORMS);
				int transformsLenght = nodosTransforms.getLength();
				if (transformsLenght > 0) {
					// No se puede validar el nodo Transforms, hijo de HashDataInfo, porque no se puede tratar transformadas
					esValido = false;
					// Tipo de firma no soportado. No se pueden tratar transformadas
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR145));
					// No se puede validar el nodo Transforms, hijo de HashDataInfo, porque no se puede tratar transformadas
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR93));	
					return esValido;
				}
			}
			// Puede darse el caso de una firma con esquema 1.3.2 sin Include, en ese caso, no debe validarse esta parte
			if ( !(nodosLenght == 0 && esquemaURI.equals(ConstantesXADES.SCHEMA_XADES_132)) ) {
				NamedNodeMap nodosUriAttrb = nodosUri.item(0).getAttributes();
				if (nodosUriAttrb == null || 
						nodosUriAttrb.getNamedItem(tipoUri) == null) {
					esValido = false;
					// Firma inválida. No se pudo leer la referencia del sello de tiempo
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR146));
					// No se puede recuperar la URI del nodo HashDataInfo o del nodo Include
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR92));	
					return esValido;
				}
				String timeStampUri = null;
				try {
					timeStampUri = URLDecoder.decode(nodosUriAttrb.getNamedItem(tipoUri).getNodeValue(), ConstantesXADES.UTF8);
				} catch (UnsupportedEncodingException ex) {
					esValido = false;
					// No se puede decodificar la URI a UTF-8
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR30), ex);
					// Firma inválida. No se pudo leer la referencia del sello de tiempo
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR146));
					return esValido;
				}
				Element nodoReferenciado = UtilidadTratarNodo.getElementById(firma, timeStampUri.substring(1));
				if (nodoReferenciado == null || !ConstantesXADES.SIGNATURE_VALUE.equals(nodoReferenciado.getLocalName())
						// El nodo SignatureValue referenciado debe ser hijo de el nodo de firma actual (no de una contrafirma)
						|| !nodoReferenciado.getParentNode().equals((Element)firma)) {
					esValido = false;
					// Firma inválida. No se pudo recuperar el elemento referenciado por el sello de tiempo
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR147));
					// No se puede recuperar el nodo SignatureValue con Id igual a XXXX
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95) + 
							ConstantesXADES.ESPACIO + ConstantesXADES.SIGNATURE_VALUE + ConstantesXADES.ESPACIO + 
							I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR100));	
					return esValido;
				}
			}
			
			CanonicalizationEnum canonicalization = getCanonicalizationMethodTS(esquemaURI, nodoSigTimeStamp);
			if(!esValido) {
			    return esValido;
			}
			
			// Se chequea la validez del sello de tiempo encapsulado	
			nodesEncapsulatedTimeStamp = nodoSigTimeStamp.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_ENCTIMESTAMP);
			encapsulatedTimeStampElement = (Element)nodesEncapsulatedTimeStamp.item(0);
			
			// Se recoge el encoding, si existe, para los esquemas XAdES 1.2.2 y 1.3.2
	        esValido = validateEncodingTS(esquemaURI, encapsulatedTimeStampElement);
	        if (!esValido) {
	            return esValido;
	        }
	        
            byte[] nodeSignatureValue = UtilidadTratarNodo.obtenerByteNodo(firma, uriXmlNS, ConstantesXADES.LIBRERIAXADES_SIGNATUREVALUE, 
                    canonicalization, 5);
            
            addDatosSelloFromBytes(encapsulatedTimeStampElement, nodeSignatureValue, TipoSellosTiempo.CLASE_T);
		} catch (FirmaXMLError e) {
			esValido = false;
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR12));
			LOGGER.error(e.getMessage(), e);
			
			logv.error(e.getMessage());
			
		} catch (TimeStampException e) {
			String sello = ConstantesXADES.CADENA_VACIA;
			if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_XL)==0)
				sello = ConstantesXADES.LIBRERIAXADES_PRIMER;

			esValido = false;
			// El sello de tiempo no tiene un formato correcto
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8) + ConstantesXADES.ESPACIO +
					sello + I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO +
					(tipoDocFirma.getTipoXAdES()) + ConstantesXADES.ESPACIO +
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR13));
			LOGGER.error(e.getMessage());
			
			logv.error(e.getMessage());
			
		} catch (Exception e) {
			String sello = ConstantesXADES.CADENA_VACIA;
			if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_XL)==0)
				sello = ConstantesXADES.LIBRERIAXADES_PRIMER;

			esValido = false;
			// El sello de tiempo no tiene un formato correcto
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8) + ConstantesXADES.ESPACIO +
					sello + I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO +
					(tipoDocFirma.getTipoXAdES()) + ConstantesXADES.ESPACIO +
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR13));
			LOGGER.error(e.getMessage());
			
			logv.error(e.getMessage());
			
		} finally {
			nodesEncapsulatedTimeStamp = null;
			encapsulatedTimeStampElement = null;
		}
		
		return esValido;
	}

	/**
	 * Este método incorpora en el array de sellos de tiempo información en objetos DatosSelloTiempo a partir de un encapsulatedTimeStamp 
	 * @param encapsulatedTimeStampElement
	 * @param nodeSignatureValue
	 * @param tipoSello
	 * @throws TimeStampException
	 */
    private void addDatosSelloFromBytes(Element encapsulatedTimeStampElement, byte[] nodeSignatureValue, TipoSellosTiempo tipoSello)
            throws TimeStampException {
        String encapsulatedTS;
        byte[] timeStampBytes;
        TSValidationResult tsv;
        encapsulatedTS = encapsulatedTimeStampElement.getFirstChild().getNodeValue() ;
        timeStampBytes = Base64.decode(encapsulatedTS) ;
        DatosSelloTiempo datosSelloTiempo = new DatosSelloTiempo();

        tsv = tsValidator.validateTimeStamp(nodeSignatureValue, timeStampBytes);

        Date fechaSello = tsv.getDate();
        if (fechaSello != null) {
        	long now = System.currentTimeMillis();
        	if (tsv.getTimeAccurracy() > 0)
        		now += tsv.getTimeAccurracy();
        	if (fechaSello.after(new Date(now))) {
        		// La fecha del sello de tiempo del nivel XXXX es posterior a la actual
        		resultado.setResultado(ResultadoEnum.UNKNOWN);
        		LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR81)); 
        		resultado.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_16, fechaSello, tsv.getTimeAccurracy(), new Date(System.currentTimeMillis())));
        		LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_16, fechaSello, tsv.getTimeAccurracy(), new Date(System.currentTimeMillis())));  
        		
        		logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR81));
        	}
        }
        
        if (esValido) {
        	try {
        		datosSelloTiempo.setFecha(fechaSello);
        		datosSelloTiempo.setEmisor(tsv.getTimeStampIssuer());
        		datosSelloTiempo.setAlgoritmo(TSPAlgoritmos.getAlgName(tsv.getStampAlg()));					
        		datosSelloTiempo.setPrecision(tsv.getTimeAccurracy());
        		datosSelloTiempo.setTipoSello(tipoSello);
        		datosSelloTiempo.setRawTimestamp(tsv.getTimeStampRawToken());
        		CertPath tsaCerts = tsv.getCadena();
        		if (tsaCerts != null) {
        			if (truster != null && tsaCerts.getCertificates().size() == 1) {
        				try {
        					// Se intenta obtener la cadena completa
        					tsaCerts = truster.getCertPath((X509Certificate) tsaCerts.getCertificates().get(0));
        					// Se ordena la cadena obtenida¡
        					datosSelloTiempo.setCadena(
        							UtilidadCertificados.orderCertPath(
        									(Iterable<X509Certificate>)tsaCerts.getCertificates()));
        					datosSelloTiempo.setEsCertConfianza(ConfianzaEnum.CON_CONFIANZA);
        				} catch (Exception e) {
        					LOGGER.debug("No se pudo ordenar la cadena de certificados del sello de tiempo");
        					datosSelloTiempo.setCadena(tsaCerts);
        				}
        			} else {
        				LOGGER.debug("No se pudo recuperar la cadena de certificación");
        				datosSelloTiempo.setCadena(tsaCerts);
        			}
        		}
        		
        		logv.abreTag(true);
        		logv.info("XAdES-T TimeStamp validation: VALID", 2);
        		logv.info("Date: " + fechaSello, 2);
        		logv.info("Issuer: " + tsv.getTimeStampIssuer(), 2);
        		logv.cierraTag(true);
        		
        	} catch (Exception e) {
                // No se pudo generar los datos de la TSA
                esValido = false;
                LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR64), e);
                
                logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR64));
                
                resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR64));
            }
        	
        	arrayDatosSello.add(datosSelloTiempo);
        } else {
        	logv.abreTag(false);
        	logv.info("XAdES-T TimeStamp validation: INVALID", 2);
        	logv.info("Date: " + fechaSello, 2);
        	logv.info("Issuer: " + tsv.getTimeStampIssuer(), 2);
        	logv.cierraTag(false);
        }
    }

    /**
     * Este método obtiene el método de canonicalización de un Timestamp
     * @param esquemaURI
     * @param nodoSigTimeStamp
     * @return
     */
    private CanonicalizationEnum getCanonicalizationMethodTS(String esquemaURI,
            Element nodoSigTimeStamp) {
        // Se valida, si existe, el nodo CanonicalizationMethod    
        NodeList nodosCanonicalizationMethod = nodoSigTimeStamp.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.CANONICALIZATION_METHOD);
        int numNodosCanonicalization = nodosCanonicalizationMethod.getLength();
        CanonicalizationEnum canonicalization = CanonicalizationEnum.C14N_OMIT_COMMENTS;
        if (numNodosCanonicalization > 0) {
        	if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaURI)) {
        		esValido = false;
        		LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR102));
        		resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR102));
        		return null;
        	} else {
        		Element nodoCanonicalizationMethod = (Element)nodosCanonicalizationMethod.item(0);
        		String method = nodoCanonicalizationMethod.getAttribute(ConstantesXADES.ALGORITHM);
        		canonicalization = CanonicalizationEnum.getCanonicalization(method);
        		if (canonicalization.equals(CanonicalizationEnum.UNKNOWN)) {
        			esValido = false;
        			// No se puede validar el método de canonalización: XXXX
        			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR103) + 
        					ConstantesXADES.ESPACIO + method);
        			
        			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR103) + 
        					ConstantesXADES.ESPACIO + method);
        			
        			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR103) + 
        					ConstantesXADES.ESPACIO + method);
        			return null;
        		}
        	}
        }
        return canonicalization;
    }
	/**
     * Valida el sello de tiempo de tipo 1 implícito correspondiente a la firma XADES-X de los esquemas 1.1.1, 1.2.2 y 1.3.2
     * @param nombreNodo Nombre del nodo a buscar "SigAndRefsTimeStamp" o "RefsOnlyTimeStamp"
     * @return Falso si el sello de tiempo no está bien formado o si la firma no se corresponde con
     * los elementos combinados del documento. Los elementos son los siguientes:
     *      - SignatureValue
     *      - SignatureTimestamp
     *      - CompleteCertificateRefs
     *      - CompleteRevocationRefs
     *  Opcionalmente en el esquema 1.2.2 y 1.3.2:
     *      - AttributeCertificateRefs
     *      - AttributeRevocationRefs
     */

	private boolean validarSelloTiempoXadesX(EstructuraFirma estructuraFirma, String nombreNodo) {

        // Se obtiene el/los nodo/s SigAndRefsTimeStamp. Se validan todos los encontrados 
        ArrayList<Element> nodesTimeStamp = new ArrayList<Element> ();
        try {
            nodesTimeStamp = UtilidadTratarNodo.obtenerNodos(estructuraFirma.firma, 5, 
                new NombreNodo(estructuraFirma.esquema.getSchemaUri(), nombreNodo));
        } catch (FirmaXMLError e) {
            LOGGER.error(e.getMessage(), e);
            return false;
        }
        int numNodos = nodesTimeStamp.size();

        if (numNodos == 0)
            return false;
        
        for (int i = 0; i < numNodos; ++i) {
            esValido = validarSegundoSelloTiempo((Element)nodesTimeStamp.get(i), estructuraFirma);
            if (!esValido)
                break;          
        }
        
        return esValido;
    }
    
	/**
	 * Valida el sello de tiempo de correspondiente a la firma XADES-X de los esquemas 1.1.1, 1.2.2 y 1.3.2
	 * @return Falso si el sello de tiempo no está bien formado o si la firma no se corresponde con
	 * los elementos combinados del documento. 
	 */
	private boolean validarSegundoSelloTiempo(Element selloTiempo, EstructuraFirma estructuraFirma) {
		
		if (tsValidator == null) {
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR64));
			return false;
		}
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		TipoSellosTiempo tipoSello = TipoSellosTiempo.CLASE_X_TIPO_1;
		
		if (new NombreNodo(esquemaURI, ConstantesXADES.SIG_AND_REFS_TIME_STAMP).equals(
				new NombreNodo(selloTiempo.getNamespaceURI(), selloTiempo.getLocalName())))
			tipoSello = TipoSellosTiempo.CLASE_X_TIPO_1;
		else if (new NombreNodo(esquemaURI, ConstantesXADES.REFS_ONLY_TIME_STAMP).equals(
				new NombreNodo(selloTiempo.getNamespaceURI(), selloTiempo.getLocalName())))
			tipoSello = TipoSellosTiempo.CLASE_X_TIPO_2;	
		else {
			esValido = false;
			// El segundo sello de tiempo, del nivel XAdES-X, no es válido
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR15));
			// El sello de tiempo xxx no es un sello válido
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8)+ ConstantesXADES.ESPACIO +
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO + 
					selloTiempo.getLocalName() + ConstantesXADES.ESPACIO + 
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR10));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8)+ ConstantesXADES.ESPACIO +
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO + 
					selloTiempo.getLocalName() + ConstantesXADES.ESPACIO + 
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR10));
			
			return esValido;
		}
		
		// Se obtiene el listado de elementos de un sello de tiempo XAdES X
		ArrayList<Element> elementosSelloX = null;
		try {
			if (TipoSellosTiempo.CLASE_X_TIPO_1.equals(tipoSello))
				elementosSelloX = UtilidadXadesX.obtenerListadoXADESX1imp(esquemaURI, firma, selloTiempo);
			else 
				elementosSelloX = UtilidadXadesX.obtenerListadoXADESX2exp(esquemaURI, firma, selloTiempo);	
		} catch (BadFormedSignatureException e) {
			esValido = false;
			// No se pudo recuperar el sello de tiempo del nivel XAdES-X
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR148));
			LOGGER.error(e.getMessage(), e);
			
			logv.error(e.getMessage());
			
			return esValido;
		} catch (FirmaXMLError e) {
			esValido = false;
			// No se pudo recuperar el sello de tiempo del nivel XAdES-X
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR148));
			LOGGER.error(e.getMessage(), e);
			
			logv.error(e.getMessage());
			
			return esValido;
		}


        if (elementosSelloX.size() <= 0) {
            esValido = false;
            // Firma inválida. No se pudo recuperar el sello de tiempo correspondiente al nivel XAdES-T
            resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR143));
            // No se puede encontrar el nodo SignatureTimeStamp
            LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR91)); 
            
            logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR91));
            
            return esValido;
        }
        
		
		if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaURI) ||
				ConstantesXADES.SCHEMA_XADES_122.equals(esquemaURI)) {
			// Se obtienen las Ids de los nodos del sello de tiempo X
			ArrayList<String> elementosIdSelloX = UtilidadTratarNodo.obtenerIDs(elementosSelloX);

			// Se recogen todos los nodos Include (1.2.2) o HashDataInfo (1.1.1) dentro del sello de tiempo XAdES-X
			NodeList nodosUriRef = selloTiempo.getElementsByTagNameNS(esquemaURI, nombreNodoUri);
			int numNodosUriRef = nodosUriRef.getLength();

	        if (numNodosUriRef == 0) {
	                // Número de nodos HashDataInfo o nodos Include inesperado
	                esValido = false;
	                // Firma inválida. El nivel XAdES X tiene un número de referencias inesperado
	                resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR144));
	                // Número de nodos de referencia inesperado: XXXX
	                LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR94) + 
	                        ConstantesXADES.ESPACIO + numNodosUriRef);
	                
	                logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR94) + 
	                        ConstantesXADES.ESPACIO + numNodosUriRef); 
	                
	                return esValido;
            }
			
			
			ArrayList<String> urisRef = new ArrayList<String>(numNodosUriRef) ;
			Element nodoUriRef = null;

			// Se recoge la URI de los nodos Include o HashDataInfo por orden de aparición
			for (int j = 0; j < numNodosUriRef ; ++j) {			
				if (j == 0)
					nodoUriRef = (Element)selloTiempo.getFirstChild();
				else
					nodoUriRef = (Element)nodoUriRef.getNextSibling();

				if (nodoUriRef == null || !nombreNodoUri.equals(nodoUriRef.getLocalName())) {
					esValido = false;
					// Firma inválida. No se pudo leer la referencia del sello de tiempo
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR146));
					// No se puede recuperar el nodo Include o HasDataInfo
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95) +
							ConstantesXADES.ESPACIO + nombreNodoUri);
					return esValido;
				}
				
				// Si es esquema 1.1.1, se valida que no contenga nodos Transform
				if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaURI)) {
					NodeList nodosTransforms = nodoUriRef.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.TRANSFORMS);
					int transformsLenght = nodosTransforms.getLength();
					if (transformsLenght > 0) {
						esValido = false;
						// Tipo de firma no soportado. No se pueden tratar transformadas
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR145));
						// No se puede validar el nodo Transforms, hijo de HashDataInfo, porque no se puede tratar transformadas
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR93));	
						return esValido;
					}
				}

				// Se obtiene la URI del nodo que contiene la referencia
				NamedNodeMap atributosNodo = nodoUriRef.getAttributes();
				if (atributosNodo == null || atributosNodo.getNamedItem(tipoUri) == null) {
					esValido = false;
					// Firma inválida. No se pudo leer la referencia del sello de tiempo
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR143));
					// No se puede recuperar la URI del nodo de referencia del sello de tiempo
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR92));
					return esValido;
				}
				String uriReferencia = atributosNodo.getNamedItem(tipoUri).getNodeValue();

				urisRef.add(uriReferencia);
			}

			// Comparamos ambos listados
			for (int j = 0; j < numNodosUriRef; ++j) {			
				String idUri = urisRef.get(j).substring(1);
				if (!idUri.equals(elementosIdSelloX.get(j))) {
					// No se corresponde el orden de los nodos de referencia con el orden esperado según esquema
					esValido = false;
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR97) + 
							ConstantesXADES.ESPACIO + idUri + ConstantesXADES.ESPACIO +  
							I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR98));
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR97) + 
							ConstantesXADES.ESPACIO + idUri + ConstantesXADES.ESPACIO +  
							I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR98));	
					return esValido;
				} 
			}
		} // Fin de la validación para esquemas 1.2.2 y 1.1.1

		// Se valida, si existe, el nodo CanonicalizationMethod    
        CanonicalizationEnum canonicalization = getCanonicalizationMethodTS(esquemaURI, selloTiempo);
        if(!esValido) {
            return esValido;
        }


		// Se obtiene el array de bytes de los nodos obtenidos
		byte[] byteData = null;
		try {
			byteData = UtilidadTratarNodo.obtenerByte(elementosSelloX, canonicalization);
		} catch (FirmaXMLError e) {
			esValido = false;
			// No se ha podido calcular el valor de los elementos combinados de la firma XADES-X
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR14));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR14));
			
			LOGGER.error(e.getMessage(), e);
		}

		// Se obtiene el array de bytes del nodo EncapsulatedTimeStamp

		NodeList nodesEncapsulatedTimeStamp = selloTiempo.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_ENCTIMESTAMP);

		if (nodesEncapsulatedTimeStamp.getLength() != 1) {
			esValido = false;
			// El nodo EncapsulatedTimeStamp dentro del sello de tiempo no existe o no es único
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
					ConstantesXADES.LIBRERIAXADES_ENCTIMESTAMP + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + 
					ConstantesXADES.ESPACIO + nodesEncapsulatedTimeStamp.getLength());
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
					ConstantesXADES.LIBRERIAXADES_ENCTIMESTAMP + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + 
					ConstantesXADES.ESPACIO + nodesEncapsulatedTimeStamp.getLength());			
			
			// El segundo sello de tiempo no es válido
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_15));
			return esValido;
		}

		Element encapsulatedTimeStampElement = (Element)nodesEncapsulatedTimeStamp.item(0);
		
		esValido = validateEncodingTS(esquemaURI, encapsulatedTimeStampElement);
		if (!esValido) {
		    return esValido;
		}

		try {
            addDatosSelloFromBytes(encapsulatedTimeStampElement, byteData, tipoSello);
        } catch (TimeStampException e) {
            String sello = ConstantesXADES.CADENA_VACIA;
            if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_XL)==0)
                sello = ConstantesXADES.LIBRERIAXADES_PRIMER;

            esValido = false;
            // El sello de tiempo no tiene un formato correcto
            resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8) + ConstantesXADES.ESPACIO +
                    sello + I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO +
                    (tipoDocFirma.getTipoXAdES()) + ConstantesXADES.ESPACIO +
                    I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR13));
            LOGGER.error(e.getMessage());
            
            logv.error(e.getMessage());
            
        }

		return true;
	}

	/**
	 * Método que busca el encoding de un Timestamp. Si es desconocido retorna false.
	 * @param esquemaURI
	 * @param encapsulatedTimeStampElement
	 * @return
	 */
    private boolean validateEncodingTS(String esquemaURI,
            Element encapsulatedTimeStampElement) {
        // Se recoge el encoding, si existe, para los esquemas XAdES 1.2.2 y 1.3.2
		if (ConstantesXADES.SCHEMA_XADES_122.equals(esquemaURI) || 
				ConstantesXADES.SCHEMA_XADES_132.equals(esquemaURI)) {
			String enc = encapsulatedTimeStampElement.getAttribute(ConstantesXADES.XADES_TAG_ENCODING);
			EncodingEnum encoding = EncodingEnum.getEncoding(enc);
			if (encoding == null) {
				esValido = false;
				LOGGER.error("Encoding del sello de tiempo X desconocido: " + enc);
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR148));
			}
		}
		return esValido;
    }
	
	/**
	 * Valida que los certificados almacenados sin firmar se correspondan
	 * con los resúmenes firmados dentro del documento XADES-C
	 * En primera instancia, se leen y almacenan todos los nodos de XADES-C
	 * A continuación se sacan los ficheros .ocs de las URI´s y se validan contra la información de los nodos y/o los nodos CRLRefs
	 * Posteriormente se sacan los certificados .cer y se valida su encadenamiento, y se chequean contra los nodos
	 * Finalmente se valida que cada uno de los certificados esté asociado a una respuestaOCSP con estado good y ninguna a revoked
	 * @param uriDS Namespace base del XML con la firma
	 * @param certFirma Certificado firmante
	 * @param estructuraFirma Objeto con la estructura de la firma
	 * @return Falso si no se corresponden los dos valores
	 * @throws FirmaXMLError Si no puede calcular el digest de los certificados almacenados
	 */
	private boolean validarXadesC(String uriDS, X509Certificate certFirma, EstructuraFirma estructuraFirma)
	{
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		ArrayList<Element> completeCertificateRefs = new ArrayList<Element> ();
		ArrayList<Element> completeRevocationRefs = new ArrayList<Element> ();

		// Coleccion de datos para los certificados
		ArrayList<String> certURI = null;
		ArrayList<String> digestAlg = null;
		ArrayList<String> digestValue = null;
		ArrayList<X500Principal> issuerName = null;
		ArrayList<String> issuerSerial = null;

		// Coleccion de datos para las respuestas OCSP
		ArrayList<String> ocspURI = null;
		ArrayList<OCSPResponderID> identifierOCSP = null;
		ArrayList<Date> identifierTime = null;
		ArrayList<String> ocspDigestAlg = null;
		ArrayList<String> ocspDigestValue = null;
		ArrayList<OCSPResp> respuestasOCSP = null; // Almacenará los .ocp recuperados de los ficheros o de los nodos RevocationValues

		// Colección de datos para CRLRefs
		ArrayList<String> crlURI = null;
		ArrayList<String> crlDigestAlg = null;
		ArrayList<String> crlDigestValue = null;
		ArrayList<String> crlIssuer = null;
		ArrayList<Date> crlIssuerTime = null;
		ArrayList<BigInteger> crlNumber = null;
		ArrayList<X509CRL> crlList = null; // Almacenará los .crl recuperados de los ficheros o de los nodos RevocationValues

		// Se mira que exista el nodo CompleteCertificateRefs y el nodo CompleteRevocationRefs
		try {
			completeCertificateRefs = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.COMPLETE_CERTIFICATE_REFS));
			completeRevocationRefs = UtilidadTratarNodo.obtenerNodos(firma, 5,
				new NombreNodo(esquemaURI, ConstantesXADES.COMPLETE_REVOCATION_REFS));
		} catch (FirmaXMLError e) {
			// No se encuentra CompleteCertificateRefs o CompleteRevocationRefs
			LOGGER.error(e.getMessage(), e);			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_29));			
			// La firma es una XAdES-X mal formada porque carece del nivel XAdES-C
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR135));
			esValido = false;
		}

		if (completeCertificateRefs.size() == 0  || completeRevocationRefs.size() == 0) {
			// No se encuentra CompleteCertificateRefs o CompleteRevocationRefs
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_29));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_29));
			
			// La firma es una XAdES-X mal formada porque carece del nivel XAdES-C
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR135));
			esValido = false;
			return esValido;
		}

		// A continuación se sacan los Certificados del nodo CertRefs (CompleteCertificateRefs)
		Node certRefs = (Node)completeCertificateRefs.get(0)
			.getElementsByTagNameNS(esquemaURI, ConstantesXADES.CERT_REFS).item(0);

		// Si ha encontrado el nodo CertRefs, se pasa a capturar su contenido
		if (certRefs != null)
		{
			// Se saca la lista de certificados
			ArrayList<Element> certs = UtilidadTratarNodo.getElementChildNodes((Element)certRefs, false);
			if (certs == null) {
				esValido = false;
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));			
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
				return false;
			}
			int l = certs.size();

			certURI = new ArrayList<String>(l);
			digestAlg = new ArrayList<String>(l);
			digestValue = new ArrayList<String>(l);
			issuerName = new ArrayList<X500Principal>(l);
			issuerSerial = new ArrayList<String>(l);

			for (int i=0; i<l && esValido; i++)
			{
				// Sacamos los nodos Cert uno por uno
				Element certificate = (Element)certs.get(i); // Sacamos cert

				if (certificate != null) {
					// Obtenemos su URI, si existe, y la almacenamos
					String uri = null;
					try {
						uri = URLDecoder.decode(certificate.getAttributes().getNamedItem(tipoUri).getNodeValue(), ConstantesXADES.UTF8);
					} catch (UnsupportedEncodingException e) {
						// No se puede decodificar la URI a UTF-8
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR30));
						esValido = false;
						// No se puede decodificar la URI del nodo CertRef para la validación de XAdES-C
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR31));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR31));
						
					} catch (Exception e) {
						// No se pudo recuperar la URI del nodo CertDigest
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR65));
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR65));					
					}
					if (uri != null)
						certURI.add(uri);
					
					// y del nodo, sacamos su digest y su issuer

					Element certDigest = (Element)certificate.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_CERTDIGEST).item(0);	// Sacamos CertDigest

					Node algorithm = certDigest.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD).item(0);				// Sacamos DigestAlgorithm
					Node value = certDigest.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE).item(0);					// Sacamos DigestValue

					digestAlg.add(algorithm.getAttributes().getNamedItem(ConstantesXADES.ALGORITHM).getNodeValue()); 	// Guardamos el valor del algoritmo        			
					digestValue.add(value.getFirstChild().getNodeValue()); 								// Guardamos valor del digest

					Element issuer = (Element)certificate.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_ISSUER_SERIAL).item(0); 	// Sacamos IssuerSerial
					Node name = issuer.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_X_509_ISSUER_NAME).item(0);					// Sacamos el nombre del emisor
					Node serial = issuer.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_X_509_SERIAL_NUMBER).item(0); 				// Sacamos el serial del emisor

					String issuerRef = name.getFirstChild().getNodeValue();
					if (issuerRef == null) {
						// No se puede encontrar los elementos de respuesta OCSP para la validación
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR169));
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR169));
						esValido = false;
						// No se pueden encontrar los archivos de respuesta OCSP para la validación de XAdES-C
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR36));
					} else {
						try {
							issuerName.add(new X500Principal(issuerRef));   			// Se guarda el issuerName
						} catch (IllegalArgumentException e) {
							// El emisor de certificado indicado en CertificateRefs no es un válido
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR169));
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR169));
							esValido = false;
							// El documento es una firma XADES-C mal formada
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR29));
						}
					}
					issuerSerial.add(serial.getFirstChild().getNodeValue()); 		// Guardamos el issuerSerialNumber
				}
			}					
		} else {
			esValido = false;
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95) +
					ConstantesXADES.ESPACIO + ConstantesXADES.CERT_REFS);			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95) +
					ConstantesXADES.ESPACIO + ConstantesXADES.CERT_REFS);
			return false;
		}

		// A continuación se sacan las referencias OCSP del nodo OCSPRefs (CompleteRevocationRefs)
		Node ocspRefs = (Node)completeRevocationRefs.get(0)
			.getElementsByTagNameNS(esquemaURI, ConstantesXADES.OCSP_REFS).item(0);

		// Si ha encontrado el nodo OCSPRefs, se pasa a capturar su contenido
		if (ocspRefs != null && esValido)
		{
			// Se saca la lista de referencias
			ArrayList<Element> refs = UtilidadTratarNodo.getElementChildNodes((Element)ocspRefs, false);
			if (refs == null) {
				esValido = false;
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.OCSP_REFS));			
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.OCSP_REFS));
				return false;
			}
			int l = refs.size();

			ocspURI = new ArrayList<String>(l);
			identifierOCSP = new ArrayList<OCSPResponderID>(l);
			OCSPResponderID responderData = null;
			identifierTime = new ArrayList<Date>(l);
			ocspDigestAlg = new ArrayList<String>(l);
			ocspDigestValue = new ArrayList<String>(l);
			String noURIOCSPidentifier = I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR32) + 
			ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR62);
			
			for (int i=0; i<l && esValido; i++)
			{
				// Sacamos los nodos OCSPRef uno por uno
				Element ocspRef = (Element)refs.get(i); // Sacamos OCSPRef

				if (ocspRef != null) {

					NodeList list = ocspRef.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_OCSP_IDENTIFIER);

					if (list.getLength() != 0) {
						// Obtenemos su URI y la almacenamos
						try {
							ocspURI.add(URLDecoder.decode((((Element)list.item(0)).getAttributes().getNamedItem(tipoUri).getNodeValue()), ConstantesXADES.UTF8));
						} catch (UnsupportedEncodingException e) {
							// No se puede decodificar la URI a UTF-8
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR30));
							esValido = false;
							// No se puede decodificar la URI del nodo OCSPRef para la validación de XAdES-C
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR32));
							
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR32));
							
						} catch (NullPointerException e) { 
							// El nodo OCSPRef no tiene URI
							LOGGER.warn(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR160));												
						} catch (Exception e) {
							// No se puede decodificar la URI a UTF-8
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR30));
							esValido = false;
							resultado.setLog(noURIOCSPidentifier);
							
							logv.error(noURIOCSPidentifier);
							
						}

						// y de él, sacamos su OCSPIdentifier y su digest
						try {
							Element certDigest = (Element)ocspRef.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_OCSP_IDENTIFIER).item(0);	// Sacamos OCSPIdentifier
							Node responder = certDigest.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_RESPONDER_ID).item(0);				// Sacamos ResponderId
							Node time = certDigest.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_PRODUCED_AT).item(0);					// Sacamos ProducedAt

							responderData = null;
							if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaURI) || ConstantesXADES.SCHEMA_XADES_122.equals(esquemaURI)) {
								X500Principal prin = new X500Principal(responder.getFirstChild().getNodeValue());
								responderData = OCSPResponderID.getOCSPResponderID(prin);
							}
							else {								
								Node responderBy = responder.getFirstChild();
								if (ConstantesXADES.BY_NAME.equals(responderBy.getLocalName())) {
									try {
										X500Principal prin = new X500Principal(responderBy.getFirstChild().getNodeValue());
										responderData = OCSPResponderID.getOCSPResponderID(prin);
									} catch (IllegalArgumentException ex) {
										esValido = false;
										// Error al instanciar la factoría de certificados
										LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
										// La respuesta OCSP almacenada en el documento XADES-XL no está bien formada
										resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_27));
										
										logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_27));
										
										return false;
									} catch (NullPointerException ex) {
										esValido = false;
										// La respuesta OCSP almacenada en el documento XADES-XL no está bien formada
										resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_27));
										
										logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_27));
										
										// Error al instanciar la factoría de certificados
										LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
										return false;
									}
								} else if (ConstantesXADES.BY_KEY.equals(responderBy.getLocalName())) {
									String hash = responderBy.getFirstChild().getNodeValue();
									try {
										responderData = OCSPResponderID.getOCSPResponderID(es.mityc.javasign.utils.Base64Coder.decode(hash));
									} catch (IllegalArgumentException ex) {
										LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_5, hash));
									}
								}
								
								if (responderData == null) {
									esValido = false;
									// No se puede leer la respuesta OCSP: Tipo de responder no reconocido
									resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR101));
									LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR101));
									
									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR101));
									
									return false;
								}
							}
							
							identifierOCSP.add(responderData); 
							
							Date fecha = UtilidadFechas.parseaFechaXML(time.getFirstChild().getNodeValue());
							if (fecha != null)
								identifierTime.add(fecha); 		// Guardamos el producedAt
							else {
								esValido = false;
								// No se puede parsear la fecha. Formato incorrecto
								LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
								
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR40));
								
								// No coincide el tiempo de respuesta del servidor OCSP con el almacenado
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR40));
							}

							// TODO: el elemento Digest es opcional y podria no aparecer. Corregir (si no aparece no hay validación de la integridad de la respuesta OCSP)
							Element ocspDigest = (Element)ocspRef.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_DIGESTALGVALUE).item(0); 	// Sacamos DigestAlgAndValue
							Node algorithm = ocspDigest.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD).item(0); 			// Sacamos DigestAlgorithm
							Node value = ocspDigest.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE).item(0); 					// Sacamos DigestValue
							
							ocspDigestAlg.add(algorithm.getAttributes().getNamedItem(ConstantesXADES.ALGORITHM).getNodeValue()); 	// Guardamos el valor del algoritmo
							ocspDigestValue.add(value.getFirstChild().getNodeValue()); 								// Guardamos valor del digest
						} catch (Exception ex) {
							// No se pueden recuperar los nodos de CompleteCertificateRefs para validar XAdES-C
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66));
							
							esValido = false;
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66));
						}
					}
					else {
						// No hay nodos OCSPRef
						LOGGER.debug(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR72));
					}
				}
			}
		}

		// Se obtienen si existen los nodos CRLRefs
		Node crlRefs = null;
		NodeList crlRefsList = completeRevocationRefs.get(0)
			.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_CRLREFS);
		if (crlRefsList != null) {
			crlRefs = crlRefsList.item(0);
		}

		// Si ha encontrado el nodo CRLRefs, se pasa a capturar su contenido
		if (crlRefs != null && esValido)
		{
			// Se saca la lista de crl
			ArrayList<Element> crls = UtilidadTratarNodo.getElementChildNodes((Element) crlRefs, false);
			if (crls == null) {
				esValido = false;
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.CRL_REFS));			
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.CRL_REFS));
				return false;
			}
			int l = crls.size();

			crlURI = new ArrayList<String>(l);
			crlDigestAlg = new ArrayList<String>(l);
			crlDigestValue = new ArrayList<String>(l);
			crlIssuer = new ArrayList<String>(l);
			crlIssuerTime = new ArrayList<Date>(l);
			crlNumber = new ArrayList<BigInteger>(l);

			for (int i=0; i<l; i++)
			{
				// Sacamos los nodos crl uno por uno
				Element crl = (Element)crls.get(i); // Sacamos CRLRef

				// y del nodo, sacamos su digest y su issuer
				if (crl != null) {
					Element crlDigest = (Element)crl.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_DIGESTALGVALUE).item(0);	// Sacamos DigestAlgAndValue

					Node algorithm = crlDigest.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD).item(0);			// Sacamos DigestAlgorithm
					Node value = crlDigest.getElementsByTagNameNS(uriDS, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE).item(0);				// Sacamos DigestValue

					crlDigestAlg.add(algorithm.getAttributes().getNamedItem(ConstantesXADES.ALGORITHM).getNodeValue()); 	// Guardamos el valor del algoritmo        			
					crlDigestValue.add(value.getFirstChild().getNodeValue()); 								// Guardamos valor del digest

					Element identifier = (Element)crl.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_CRLIDENTIFIER).item(0); 	// Sacamos IssuerIdentifier
					try {
						crlURI.add(URLDecoder.decode(identifier.getAttributes().getNamedItem(tipoUri).getNodeValue(), ConstantesXADES.UTF8));	// Se obtiene la URI
					} catch (UnsupportedEncodingException e) {
						// No se puede decodificar la URI a UTF-8
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR30), e);
						esValido = false;
						// No se puede decodificar la URI del nodo CRLRef para la validación de XAdES-C
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR33));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR33));
						
					} catch (NullPointerException e) {
						// El nodo CRLRef no tiene URI
						LOGGER.warn(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR161));						
					} catch (Exception e) {
						// No se puede decodificar la URI a UTF-8
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR30), e);
						esValido = false;
						// No se puede decodificar la URI del nodo CRLRef para la validación de XAdES-C
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR33));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR33));
						
					}					

					try {
						Node issuer = identifier.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_ISSUER).item(0);					// Sacamos el Issuer
						Node issuerTime = identifier.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_ISSUERTIME).item(0); 		// Sacamos el tiempo del Issuer
						Node number = identifier.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_NUMBER).item(0); 				// Sacamos el numero de la CRL (opcional)

						String crlIssuerName = issuer.getFirstChild().getNodeValue();
						try {
							X500Principal prin = new X500Principal(crlIssuerName);
							crlIssuer.add(prin.getName());
						} catch (IllegalArgumentException ex) {
							esValido = false;
							// No se puede cargar la factoría de CRL para la validación de XAdES-C
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_44));
							// Error al instanciar la factoría de certificados
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_44));
							
							return false;
						} catch (NullPointerException ex) {
							esValido = false;
							// 	No se puede cargar la factoría de CRL para la validación de XAdES-C
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_44));
							// Error al instanciar la factoría de certificados
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_44));
							
							return false;
						}
						Date fecha = UtilidadFechas.parseaFechaXML(issuerTime.getFirstChild().getNodeValue());
						if (fecha != null) 
							crlIssuerTime.add(fecha);   	// Guardamos el issuerTime
						else {
							// No se puede parsear la fecha, el formato no es correcto
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
							esValido = false;
							// No coincide el tiempo de respuesta del servidor OCSP con el almacenado
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR40));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR40));
							
						}

						if (number != null) {
							crlNumber.add(new BigInteger(number.getFirstChild().getNodeValue())); 				// Guardamos el Number
						} else {
							crlNumber.add(null);
						}
					} catch (Exception ex) {
						// No se pueden recuperar los nodos de CompleteCertificateRefs para validar XAdES-C
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66), ex);
						esValido = false;
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66));
						
					}
				}
			}
		}

		ArrayList<Element> certificateValues = new ArrayList<Element> ();
		ArrayList<Element> revocationValues = new ArrayList<Element> ();

		try {
			certificateValues = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.CERTIFICATE_VALUES));
			revocationValues = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.REVOCATION_VALUES));
		} catch (FirmaXMLError e) {
			LOGGER.debug(e.getMessage(), e);
		}

		// Si existen los nodos, se valida como XAdES-XL
		boolean certsYOcspInterno = false;
		if (certificateValues.size() != 0 && revocationValues.size() != 0) {
			certsYOcspInterno = true;
		}

		// Se valida CompleteRevocationCerts, en primer lugar los nodos OCSPRef
		if (ocspDigestValue != null && ocspDigestValue.size() != 0 && esValido) {
			int ocspNum = ocspDigestValue.size();
			OCSPResponderID responderData = null; 
			byte[] respuesta = null;
			respuestasOCSP = new ArrayList<OCSPResp>(ocspNum);
			for (int x=0; x < ocspNum && esValido; ++x) {
				if (certsYOcspInterno) {
					Element ocsp = null;
					if (ocspURI != null && ocspURI.size() == ocspNum) {
						String uri = ocspURI.get(x);
						if (uri.startsWith(ConstantesXADES.ALMOHADILLA)) // Se chequea que sea referencia interna, si no, se busca en los Values
							ocsp = UtilidadTratarNodo.getElementById(firma.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_OCSPVALUE), uri.substring(1));
					}
					if (ocsp == null) {
						ocsp = buscarRevocationValueOCSP(ocspDigestValue.get(x), ocspDigestAlg.get(x), estructuraFirma);
						if (ocsp == null) {
							// No se puede recuperar el nodo RevocationValue
							LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95) + 
									ConstantesXADES.ESPACIO + ConstantesXADES.REVOCATION_VALUES);
							esValido = false;
							// No se puede encontrar los elementos de respuesta OCSP para la validación
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR34));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95) + 
									ConstantesXADES.ESPACIO + ConstantesXADES.REVOCATION_VALUES);
							
							return esValido;
						} else 
							respuesta = Base64.decode(ocsp.getFirstChild().getNodeValue());
					} else
						respuesta = Base64.decode(ocsp.getFirstChild().getNodeValue());
				}
				else {
					// busca la respuesta ocsp en el recoverManager configurado
					if (recoverManager != null) {
						Map<String, Object> props = new HashMap<String, Object>();
						if ((ocspURI != null) && (ocspURI.size() == ocspNum) && (ocspURI.get(x) != null)) {
							props.put(IRecoverElements.PROP_URI, ocspURI.get(x));
						} else {
							props.put(IRecoverElements.PROP_EMISSION_DATE, identifierTime.get(x));
							props.put(IRecoverElements.PROP_DIGEST_ALGORITHM, ocspDigestAlg.get(x));
							props.put(IRecoverElements.PROP_DIGEST_VALUE, Base64.decode(ocspDigestValue.get(x)));
							OCSPResponderID ocspData = identifierOCSP.get(x);
							IOCSPCertStatus.TYPE_RESPONDER typeResponder = ocspData.getTypeResponderID();
							if (typeResponder != null) {
								switch (typeResponder) {
									case BY_NAME:
										props.put(IRecoverElements.PROP_ISSUER_NAME, (X500Principal) ocspData.getIdentifierData());
										break;
									case BY_KEY:
										props.put(IRecoverElements.PROP_ISSUER_HASH, (byte[]) ocspData.getIdentifierData());
										break;
								}
							} else {
								// Si es XAdES 1.2.2 o inferior: intenta buscar qué tipo de responder es.
								try {
									props.put(IRecoverElements.PROP_ISSUER_NAME, new X500Principal((String) ocspData.getIdentifierData()));
								} catch (IllegalArgumentException ex) {
									try {
										props.put(IRecoverElements.PROP_ISSUER_HASH, Base64.decode((String) ocspData.getIdentifierData()));
									} catch (IllegalArgumentException ex1) {
										LOGGER.warn(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_6));
									}
								}
							}
						}

						IOCSPCertStatus ocsp = null;
						try {
							ocsp = recoverManager.getElement(props, IOCSPCertStatus.class);
						} catch (ElementNotFoundException ex) {
							LOGGER.warn(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_2), ex);
							if (LOGGER.isTraceEnabled()) {
								LOGGER.trace(props);
							}
						} catch (UnknownElementClassException ex) {
							LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_3, "IOCSP"), ex);
						}
						if (ocsp == null) {
							// No se puede encontrar los elementos de respuesta OCSP para la validación
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR34));

							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR34));

							esValido = false;
							// No se pueden encontrar los archivos de respuesta OCSP para la validación de XAdES-C
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR36));
						} else {
							respuesta = ocsp.getEncoded();
						}
					}
					
				}
				
				// Se valida el Digest
				String digestOCSPResponse = null;
				if (esValido) {
					MessageDigest resumenCertificadoTemp = UtilidadFirmaElectronica.getMessageDigest(ocspDigestAlg.get(x));
					byte[] resumenMensajeByte = resumenCertificadoTemp.digest(respuesta);
					digestOCSPResponse = new String(Base64Coder.encode(resumenMensajeByte));

					if (!((ocspDigestValue.get(x)).equals(digestOCSPResponse))) {
						esValido = false;
						// No coincide el valor del digest de la respuesta OCSP con el almacenado
						LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR38));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR38));
						
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR38));
					}
				}

				// Reconstruimos la respuesta 
				OCSPResp resp = null;
				if (esValido) {
					try {
						resp = new OCSPResp(respuesta);
					} catch (IOException e) {
						// No se pudo reconstruir la respuesta OCSP
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR150), e);
						esValido = false;
						// La respuesta OCSP almacenada en el documento no es válida
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR18));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR18));
						
					}
					BasicOCSPResp respuestaBasica = null;
					OCSPResponderID respuestaOCSP = null;
					Date tiempoRespuesta = null;
					try {
						try {
							respuestaBasica = (BasicOCSPResp)resp.getResponseObject();
						} catch (ClassCastException e) {
							continue;
						}
						tiempoRespuesta =respuestaBasica.getProducedAt();
						
						ResponderID respID = respuestaBasica.getResponderId().toASN1Object();
						respuestaOCSP = ASN1Utils.getResponderID(respID);
					} catch (OCSPException e) {
						// No se pudo reconstruir la respuesta OCSP
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR150), e);
						esValido = false;
						// La respuesta OCSP almacenada en el documento no es válida
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR18));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR18));
					}

					// y validamos responderId y producedAt
					  
					responderData = identifierOCSP.get(x);
					try {
						X500Principal prin1 = null;
						byte[] bprin1 = null;
						if (responderData.getIdentifierData() instanceof String) {
							prin1 = new X500Principal((String) responderData.getIdentifierData());
						} else if(responderData.getIdentifierData() instanceof X500Principal) {
							prin1 = (X500Principal) responderData.getIdentifierData();  
						} else {
							bprin1 = (byte[])responderData.getIdentifierData();
						}
						
						if(prin1!=null) {
							X500Principal prin2 = (X500Principal) respuestaOCSP.getIdentifierData();					
							if (!(prin2.equals(prin1))) {	 
								esValido = false;  
								// No coincide el Id del servidor OCSP con el almacenado
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
								LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
	
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
							}
						} else {
							byte[] bprin2 = (byte[]) respuestaOCSP.getIdentifierData();
							if(!Arrays.equals(bprin2, bprin1)) {
								esValido = false;  
								// No coincide el Id del servidor OCSP con el almacenado
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
								LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
	
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
							}
						}
					} catch (IllegalArgumentException e) {
						LOGGER.error("OCSP-ResponderID problem: " + e.getMessage());
						if (!(responderData.equals(respuestaOCSP))) {  
							esValido = false;  
							// No coincide el Id del servidor OCSP con el almacenado
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
							LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR39));
							
						}  
					}

					if (!((identifierTime.get(x)).equals(tiempoRespuesta))) {
						esValido = false;
						// No coincide el tiempo de respuesta del servidor OCSP con el almacenado.
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR40));
						LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR40));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR40));
						
					}
					// Se almacena la respuesta para validar los certificados
					if (esValido)
						respuestasOCSP.add(resp);
				}
			}
		}

		// Se valida CRLRefs
		if (crlDigestValue != null && crlDigestValue.size() != 0 && esValido) {
			int crlNum = crlDigestValue.size();
			X509CRL x509CRL = null;
			crlList = new ArrayList<X509CRL>(crlNum);
			for (int x=0; x < crlNum && esValido; ++x) {
				if (certsYOcspInterno) {
					byte[] crl = null;
					Element crlValue = null;
					if (crlURI != null && crlURI.size() == crlNum) {
						String uri = crlURI.get(x);
						if (uri.startsWith(ConstantesXADES.ALMOHADILLA)) // Se chequea que sea referencia interna, si no, se busca en los Values
							crlValue = UtilidadTratarNodo.getElementById(firma.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_CRLVALUE), uri.substring(1));
					}
					if (crlValue == null) {
						crlValue = buscarRevocationValueCRL(crlDigestValue.get(x), crlDigestAlg.get(x), estructuraFirma);
						if (crlValue == null) {
							// No hay datos para validar las CRLs
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR151));
							esValido = false;
							// No se puede encontrar los elementos de respuesta CRL para la validación de XAdES-XL
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR41));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR41));
							
							return esValido;
						} else {
							crl = Base64.decode(crlValue.getFirstChild().getNodeValue());
						}
					} else {
						crl = Base64.decode(crlValue.getFirstChild().getNodeValue());
					}
					
					if (crl != null) {
						CertificateFactory certificatefactory;
						try {
							ByteArrayInputStream bais = new ByteArrayInputStream(crl);
							certificatefactory = CertificateFactory.getInstance(ConstantesXADES.X_509);
							x509CRL = (X509CRL)certificatefactory.generateCRL(bais);
						} catch (CertificateException e) {
							// Error al instanciar la factoría de certificados
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_23), e);
							esValido = false;
							// No se pudo recontruir la lista de revocación
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR154));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR154));
							
						} catch (CRLException e) {
							// No se puede cargar la factoría de CRL para la validación de XAdES-C
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_44), e);
							esValido = false;
							// No se pudo recontruir la lista de revocación
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR154));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_44));
							
						}
					} else {
						// No hay datos para validar las CRLs
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR151));
						esValido = false;
						// No se puede encontrar los elementos de respuesta CRL para la validación de XAdES-XL
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR41));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR41));
					}
				}
				else {
					// busca la lista crl en el recoverManager configurado
					if (recoverManager != null) {
						Map<String, Object> props = new HashMap<String, Object>();
						if ((crlURI != null) && (crlURI.size() == crlNum) && (crlURI.get(x) != null)) {
							props.put(IRecoverElements.PROP_URI, crlURI.get(x));
						} else {
							// TODO: datos de emisor, fecha y número de serie
						}

						X509CRL x509crl = null;
						try {
							x509crl = recoverManager.getElement(props, X509CRL.class);
						} catch (ElementNotFoundException ex) {
							LOGGER.warn(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_2));
							if (LOGGER.isTraceEnabled()) {
								LOGGER.trace(props);
							}
						} catch (UnknownElementClassException ex) {
							LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_3, "X509CRL"), ex);
						}
						if (x509crl == null) {
							// No se pudo encontrar los ficheros CRL para validar XAdES-C
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR152));
							esValido = false;
							// No se puede encontrar los elementos de respuesta CRL para la validación de XAdES-C
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR42));

							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR152));
						} else {
							x509CRL = x509crl;
						}
					}
					
				}

				// Se valida el Digest
				String digestCRLResponse = null;
				if (esValido) {
					MessageDigest resumenCRLTemp = UtilidadFirmaElectronica.getMessageDigest(crlDigestAlg.get(x));
					try {
						byte[] resumenMensajeByte = resumenCRLTemp.digest(x509CRL.getEncoded());
						digestCRLResponse = new String(Base64Coder.encode(resumenMensajeByte));
						if (!((crlDigestValue.get(x)).equals(digestCRLResponse))) {
							esValido = false;
							// No coincide el digest de la respuesta CRL del nodo con el almacenado
							LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR43));
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR43));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR43));
							
						}
					} catch (CRLException ex) {
						esValido = false;
						// No coincide el digest de la respuesta CRL del nodo con el almacenado
						LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR43));
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR43));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR43));
					}
				}

				// Reconstruimos la crl
				if (esValido) {
					if (x509CRL != null) {
						// Se valida issuer
						X509Principal prin1 = new X509Principal(crlIssuer.get(x));
						X509Principal prin2 = new X509Principal(x509CRL.getIssuerX500Principal().getName());
						if (!(prin1.equals(prin2))) {  
							esValido = false;
							// No coincide el nombre del Issuer de la CRL con el almacenado
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR45));
							LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR45));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR45));
							
						}

						// Se valida issuerTime
						Date time = x509CRL.getThisUpdate();

						if (!((crlIssuerTime.get(x)).equals(time))) {
							esValido = false;
							// No coincide el tiempo de respuesta CRL con el valor almacenado
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR46));
							LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR46));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR46));
							
						}

						// se valida el número de CRL
						BigInteger numeroNodo = crlNumber.get(x); 	// Se recupera el numero de CRL escrito en el nodo		

						// Si existe el nodo number (opcional), se saca el número de CRL contenido en la URI
						if (numeroNodo != null) {
							BigInteger numeroRecuperado = null;
							DERInteger derInt = null;
							// AppPerfect: Falso positivo
							ASN1InputStream ais = new ASN1InputStream(x509CRL.getExtensionValue(ConstantesXADES.CRL_NUMBER_OID));
							try {
								ais = new ASN1InputStream(((DEROctetString)ais.readObject()).getOctets());
								derInt = (DERInteger)ais.readObject();
							} catch (IOException e) {
								esValido = false;
								// No se puede recuperar el número de CRL para la validación de XAdES-C
								LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR47), e);
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR47));
								
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR47));
								
							}
							numeroRecuperado = derInt.getValue();

							if (!((numeroNodo).equals(numeroRecuperado))) {
								esValido = false;
								// No coincide el número de CRL con el valor almacenado
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR48));
								LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR48));
								
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR48));
								
							}
						}
					}
				}
				// Se almacena la lista para validar los certificados
				if (esValido)
					crlList.add(x509CRL);
			}
		}
		
		// Se valida CompleteCertificateRefs
		int numCert = digestValue.size();
		ArrayList<X509Certificate> certsDeURI = new ArrayList<X509Certificate> ();
		X509Certificate certificado = null;
		for (int x=0; x < numCert && esValido; ++x) {
			if (certsYOcspInterno) {
				// El nodo referenciado por la URI puede estar en todo el documento
				Element certValue = null;
				if (certURI != null && certURI.size() == numCert) {
					String uri = certURI.get(x);
					if (uri.startsWith(ConstantesXADES.ALMOHADILLA)) // Se chequea que sea referencia interna, si no, se busca en los Values
						certValue = UtilidadTratarNodo.getElementById(firma.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_X509VALUE), certURI.get(x).substring(1));
				}
				if (certValue == null) {
					certificado = buscarCertificateValue(issuerName.get(x), new BigInteger(issuerSerial.get(x)), estructuraFirma);
					if (certificado == null) {
						// No hay datos para validar la cadena de certificados de firma
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR155));
						esValido = false;
						// No se pueden encontrar los elementos de certificado para la validación de XAdES-XL
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR49));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR155));
						
						return esValido;
					}
				} else {
					try
					{
						ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(certValue.getFirstChild().getNodeValue()));
						CertificateFactory cf = CertificateFactory.getInstance(ConstantesXADES.X_509);
						certificado = (X509Certificate)cf.generateCertificate(bais);
					} catch (CertificateException e1) {
						// Error al instanciar la factoría de certificados
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_23), e1);
						esValido = false;
						// No se pudo recontruir la cadena de certificados
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR156));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR156));
						
					} 
				}
			}
			else {
				// busca el certificado en el recoverManager configurado
				if (recoverManager != null) {
					Map<String, Object> props = new HashMap<String, Object>();
					if ((certURI != null) && (certURI.size() == numCert) && (certURI.get(x) != null)) {
						props.put(IRecoverElements.PROP_URI, certURI.get(x));
					} else {
						//TODO: datos de emisor y número de serie
					}

					X509Certificate x509cert = null;
					try {
						x509cert = recoverManager.getElement(props, X509Certificate.class);
					} catch (ElementNotFoundException ex) {
						LOGGER.warn(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_2));
						if (LOGGER.isTraceEnabled()) {
							LOGGER.trace(props);
						}
					} catch (UnknownElementClassException ex) {
						LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_3, "X509Certificate"), ex);
					}
					if (x509cert == null) {
						// No se encuentra el fichero XXXX
						LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_4, certURI, x));
						esValido = false;
						// No se pueden encontrar los archivos de certificado para la validación de XAdES-C
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR50));

						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR50));
					} else {
						certificado = x509cert;
					}
				}
			}

			// Se comprueba que el valor digest del nodo coincida con el digest de la uri
			String resumenCertificado = ConstantesXADES.CADENA_VACIA;
			try
			{
				MessageDigest resumenCertificadoTemp = UtilidadFirmaElectronica.getMessageDigest(digestAlg.get(x));
				if (resumenCertificadoTemp == null) {
					esValido = false;
					// No se encontró el algoritmo para calcular el valor del digest del certificado: XXXX
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_16) + 
							ConstantesXADES.DOS_PUNTOS_ESPACIO + digestAlg.get(x));
					// No se puede calcular la huella del certificado para la validación
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
					
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_16) + 
							ConstantesXADES.DOS_PUNTOS_ESPACIO + digestAlg.get(x));
					
					return false;
				}
				byte[] resumenMensajeByte =resumenCertificadoTemp.digest(certificado.getEncoded());
				resumenCertificado = new String(Base64Coder.encode(resumenMensajeByte));
			} catch (CertificateEncodingException e) {
				// Error al obtener la codificación: XXXX
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_23) + 
						ConstantesXADES.DOS_PUNTOS_ESPACIO + e.getMessage(), e);				
				esValido = false;
				// No se puede calcular la huella del certificado para la validación
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
				
			}

			if (!(digestValue.get(x).equals(resumenCertificado))) {
				esValido = false;
				// No coincide el certificado con el almacenado
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR53));
				LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR53));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR53));
				
			}

			// Se comprueba que coincidan los numeros de serie
			if (!(issuerSerial.get(x).equals(certificado.getSerialNumber().toString()))) {
				esValido = false;
				// No coincide el número de serie del certificado con el almacenado
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR54));
				LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR54));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR54));
				
			}

			if (esValido) {
				certsDeURI.add(certificado);
			}
		}

		// Se valida que los certificados se correspondan con la cadena de firma
		// Chequea issuer y serial, y posteriormente digest, excluyendo el primero (certificado de firma)
		X509Certificate signingCert = cadenaCertificados.get(0);
		cadenaCertificados.addAll(certsDeURI);
		ArrayList<ArrayList<X509Certificate>> certChains = UtilidadCertificados.filterCertPathsArrays(UtilidadCertificados.getCertPathsArray(cadenaCertificados), UtilidadCertificados.Filter.SIGN_SIGNER);
		if (certChains.size() > 1) {
			// No se pueden validar dos o más cadenas diferentes de certificados
			LOGGER.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR84) +
					ConstantesXADES.DOS_PUNTOS_ESPACIO + certChains.size());
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR84) +
					ConstantesXADES.DOS_PUNTOS_ESPACIO + certChains.size());
		} 
		
		ArrayList<X509Certificate> certificadoYaValidadoOCSP = new ArrayList<X509Certificate>();
		for (int z = 0; z < certChains.size(); ++z) {
			cadenaCertificados = certChains.get(z);

			Iterator<X509Certificate> certGenIter = cadenaCertificados.iterator();
			ArrayList<X509Certificate> cadenaClon = new ArrayList<X509Certificate> (cadenaCertificados);
			// Excluimos el primero
			cadenaClon.remove(0);
			certGenIter.next();

			int certRefLenght = digestValue.size();

			while (certGenIter.hasNext())
			{				
				X509Certificate certAValidar = certGenIter.next();

				for (int i=0; i < certRefLenght && esValido; i++)
				{
					X500Principal issuer = issuerName.get(i);
					BigInteger serial = new BigInteger(issuerSerial.get(i));
					String alg = digestAlg.get(i);
					byte[] value = Base64Coder.decode(digestValue.get(i));

					if (issuer.equals(certAValidar.getIssuerX500Principal()) && 
							(serial).equals(certAValidar.getSerialNumber())) {
						// Cálculo del digest del certificado de firma
						MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(alg);
						byte[] digestCert = null;
						try {
							digestCert = haseador.digest(certAValidar.getEncoded());
						} catch (CertificateEncodingException e) {
							esValido = false;
							// No se puede calcular la huella del certificado para la validación
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
							// Error al obtener la codificación: XXXX
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23) + 
									ConstantesXADES.DOS_PUNTOS_ESPACIO + e.getMessage(), e);

							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));

							return false;
						}
						if (Utilidades.isEqual(digestCert, value)) {
							// Coincidencia, se saca el certificado de la lista
							cadenaClon.remove(certAValidar);
							break;
						}
					}
				}
			}

			if (cadenaClon.size() > 0) {
				esValido = false;
				// No se puede validar un certificado de la cadena por falta de referencias
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR67));
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR67));

				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR67));

				return false;
			}

			// Se almacena la cadena de certificados firmante validada si la cadena contiene al certificado firmante
			for(int b = 0; b < cadenaCertificados.size(); ++b) {
				if (cadenaCertificados.get(b).equals(signingCert)) {
					datosFirma.setCadenaFirma(UtilidadCertificados.convertCertPath(cadenaCertificados));
					break;
				}
			}
			if (esValido)
			{

				boolean tieneError = false;

				int numCadenaCerts = cadenaCertificados.size();
				for (int i = 0; i < numCadenaCerts; i++ ) {
					X509Certificate certAValidar = (X509Certificate) cadenaCertificados.get(i);
					
					if(!certificadoYaValidadoOCSP.contains(certAValidar)){
	                    X509Certificate certIssuer = null;
    					if (i < (numCadenaCerts - 1))
    						certIssuer = (X509Certificate) cadenaCertificados.get(i+1);
    					else
    						certIssuer = certAValidar;
    
    					CertificateID certificadoId = null;
    					try {
    						certificadoId = new CertificateID(CertificateID.HASH_SHA1, certIssuer, certAValidar.getSerialNumber());
    					} catch (OCSPException ex) {
    						// No se pudo construir el identificador para un certificado: XXXX
    						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR158) + 
    								ConstantesXADES.DOS_PUNTOS_ESPACIO + ex.getMessage(), ex);
    						esValido = false;
    						// No se puede construir la cadena de certificados para la validación de XAdES-C
    						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR56));
    
    						if (i == 0) {
    							logv.abreTag(false);
    							logv.info("Certificate chain status:", 2);
    							tieneError = true;
    						}
    						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR158) + 
    								ConstantesXADES.DOS_PUNTOS_ESPACIO + ex.getMessage(), 2);
    
    						break;
    					}
    
    					// Por cada certificado se comprueba que exista al menos una respuestaOCSP good y ninguna revoked
    					// o que el certificado no exista en ninguna lista de revocación de su mismo issuer 
    					// o no exista RevocationRef asociada
    					int good = 0;
    					int revoked = 0;
    					DatosOCSP datosOCSP = null;  
    					DatosCRL datosCRL = null;  
    					BasicOCSPResp basicOcsp = null; 
    
    					if (respuestasOCSP != null) {		// Se comprueba que la lista de respuestasOCSP no sea nula
    						Iterator<OCSPResp> itRespOCSP = respuestasOCSP.iterator();
    						boolean hasNext = itRespOCSP.hasNext();
    						while (hasNext && esValido) {
    							OCSPResp respuestaOCSP = itRespOCSP.next();  
    							try {  
    								basicOcsp = (BasicOCSPResp)respuestaOCSP.getResponseObject();  
    							} catch (OCSPException e) {  
    								//No se puede reconstruir la respuesta básica a partir de la respuestaOCSP leída
    								LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR118), e);
    
    								if (i == 0) {
    									logv.abreTag(false);
    									logv.info("Certificate chain status:", 2);
    									tieneError = true;
    								}
    								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR118), 2);
    
    								break;  
    							}  
    
    							hasNext = itRespOCSP.hasNext();
    							SingleResp[] singleResps = basicOcsp.getResponses();
    							int numSingleResps = singleResps.length;
    							for (int j = 0; j < numSingleResps; ++j) {
    								if (certificadoId.equals(singleResps[j].getCertID())) {
                                        datosOCSP = new DatosOCSP();
                                        datosOCSP.setResponderId(basicOcsp.getResponderId().toASN1Object());
                                        datosOCSP.setCertConsultado(certAValidar.getSubjectX500Principal().toString());
                                        datosOCSP.setFechaConsulta(basicOcsp.getProducedAt());
                                        datosOCSP.setRespuestaOCSP(respuestaOCSP);
                                        
                                        RespuestaOCSP res = null;
                                        
                                        boolean isUnknown = false;

                                        Object obj = singleResps[j].getCertStatus();
    									if (obj == null) {
    										good++;
    
    										if (i == 0) {
    											logv.abreTag(true);
    											logv.info("Certificate chain status:", 2);
    										}
    
    										if (i < identifierOCSP.size())
    											logv.info("Certificate: " + certAValidar.getSubjectDN() + " is VALID (OCSP response: " + identifierOCSP.get(i).toString() + ")", 2);
    									}
    									else if (obj instanceof RevokedStatus) {
    										revoked++;
    
    										if (i == 0) {
    											logv.abreTag(false);
    											logv.info("Certificate chain status:", 2);
    											tieneError = true;
    										}
    										logv.error("Certificate: " + certificadoId + " is REVOKED (OCSP response: " + basicOcsp.getResponderId() + ")", 2);
    									} else if (obj instanceof UnknownStatus) { //else es UnknownStatus
    									    isUnknown = true;
                                            datosOCSP.setRevockedStatus(CERT_STATUS.unknown);                                             
                                            res = new RespuestaOCSP(ConstantesOCSP.UNKNOWN, ConstantesOCSP.CADENA_VACIA);
    									}

    									if(!isUnknown) {
                                            switch(respuestaOCSP.getStatus()) {
                                                case ConstantesOCSP.GOOD:
                                                    datosOCSP.setRevockedStatus(CERT_STATUS.valid);
                                                    res = new RespuestaOCSP(ConstantesOCSP.GOOD, ConstantesOCSP.CADENA_VACIA);
                                                    break;
                                                case ConstantesOCSP.REVOKED:
                                                    datosOCSP.setRevockedStatus(CERT_STATUS.revoked);                                             
                                                    res = new RespuestaOCSP(ConstantesOCSP.REVOKED, ConstantesOCSP.CADENA_VACIA);
                                                    break;
                                                default:
                                                    datosOCSP.setRevockedStatus(CERT_STATUS.unknown);                                             
                                                    res = new RespuestaOCSP(ConstantesOCSP.UNKNOWN, ConstantesOCSP.CADENA_VACIA);
                                            }
    									}
                                        datosOCSP.setStatus(new OCSPStatus(res, certAValidar));                                             
                                        try {
                                            CertPath ocspCertChain = UtilidadCertificados.orderCertPath(Arrays.asList(basicOcsp.getCerts(ConstantesXADES.SUN)));
                                            datosOCSP.setCertOCSPResponder(ocspCertChain.getCertificates().toArray(new X509Certificate[0]));
                                        } catch (NoSuchProviderException e) {
                                            LOGGER.error(e.getMessage(), e);
                                        } catch (OCSPException e) {
                                            LOGGER.error(e.getMessage(), e);
                                        }
                                        arrayDatosOCSP.add(datosOCSP);
    									break;
    								}
    							}
    							if (revoked > 0 || good > 0)
    								break;
    						}
    					}
    					if (crlList != null) {				// Se comprueba que la lista de CRL no sea nula
    						Iterator<X509CRL> itCRLList = crlList.iterator();
    						boolean hasNext = itCRLList.hasNext();
    						while (hasNext && esValido) {
    							X509CRL x509CRL = itCRLList.next();
    							hasNext = itCRLList.hasNext();
    							// Si el certificado tiene el mismo issuer que la CRL
    							if ((x509CRL.getIssuerX500Principal().getName()).equals(certIssuer.getSubjectX500Principal().getName()) &&
    									!(certAValidar.getSubjectDN().equals(certAValidar.getIssuerDN())) ) { // Y no es un certificado autofirmado (el raíz)
    								// se comprueba que el certificado no esté dentro de la lista
    								if (x509CRL.isRevoked(certAValidar)) {
    									revoked++;
    
    									if (i == 0) {
    										logv.abreTag(false);
    										logv.info("Certificate chain status:", 2);
    										tieneError = true;
    									}
    									logv.error("Certificate: " + certAValidar.getSubjectDN() + " is REVOKED (CRL response: " + x509CRL.getIssuerX500Principal().getName() + ")", 2);
    
    									break;
    								} else {
    									good++;
    
    									if (i == 0) {
    										logv.abreTag(true);
    										logv.info("Certificate chain status:", 2);
    									}
    
    									logv.info("Certificate: " + certAValidar.getSubjectDN() + " is VALID (CRL response: " + x509CRL.getIssuerX500Principal().getName() + ")", 2);
    
    									datosCRL = new DatosCRL();  
    									datosCRL.setIssuer(x509CRL.getIssuerX500Principal().getName());  
    									datosCRL.setFechaEmision(x509CRL.getThisUpdate());  
    									datosCRL.setFechaCaducidad(x509CRL.getNextUpdate());  
    									datosCRL.setX509CRL(x509CRL);  
    									arrayDatosCRL.add(datosCRL);  					
    								}
    							}
    						}
    						if (revoked > 0)
    							break;
    					}
    
    					if ((revoked == 0) && (good == 0)) {
    						if (!((certAValidar.getSubjectDN()).equals(certAValidar.getIssuerDN()))) {
    							// Un certificado de la cadena, distinto al raíz, no está validado. No se puede validar la cadena
    							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR67));
    
    							if (i == 0) {
    								logv.abreTag(false);
    								logv.info("Certificate chain status:", 2);
    								tieneError = true;
    							}
    							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR67), 2);
    
    							esValido = false;
    							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR67));
    							break;
    						}
    					} else {
    						if ((revoked > 0) || (good == 0)) {
    							// Un certificado de la cadena no es válido
    							LOGGER.error( I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR57));
    
    							if (i == 0) {
    								logv.abreTag(false);
    								logv.info("Certificate chain status:", 2);
    								tieneError = true;
    							}
    							logv.error( I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR57), 2);
    
    							esValido = false;
    							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR57));
    							break;
    						} 
    					}
    					certificadoYaValidadoOCSP.add(certAValidar);
					}
				}  
				logv.cierraTag(!tieneError);
			}
		}

		//TODO: si la firma es XL comprobar que el primer certificado en certificateValues es igual que el firmante

		return esValido;
	}
	
	/**
	 * Valida el sello de tiempo correspondiente al nivel XAdES-A
	 * 
	 * @param estructuraFirma Objeto con la estructura de la firma
	 * @return boolean.- true Si el sello de tiempo es válido, false en caso contrario
	 * @throws Exception
	 */
	private boolean validaXadesA(EstructuraFirma estructuraFirma) throws Exception {
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		// Se obtiene el nodo ArchiveTimeStamp
		Element archiveTimeStampNode = null;
		ArrayList<Element> nodesArchiveTimeStamp = new ArrayList<Element> ();
		try {
			nodesArchiveTimeStamp = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.ARCHIVE_TIME_STAMP));
		} catch (FirmaXMLError e) {
			LOGGER.error(e.getMessage(), e);
			return false;			
		}
		
		int numNodes = nodesArchiveTimeStamp.size();

		if (numNodes == 0) {
			esValido = false;
			// El sello de tiempo del nivel XAdES-A, no es válido
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR15));
			// El sello de tiempo xxx no es un sello válido
			LOGGER.error("El sello de tiempo del nivel XAdES-A, no es válido");
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR8)+ ConstantesXADES.ESPACIO +
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ConstantesXADES.ESPACIO + 
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR10));
			
			return esValido;
		}
		
		TSValidationResult tsv2 = null;
		DatosSelloTiempo datosSelloTiempo = null;
		byte[] byteData = null;

		// Se validan todos los nodos encontrados
		for (int i = 0; i < numNodes; ++i) {

			archiveTimeStampNode = nodesArchiveTimeStamp.get(i);

			datosSelloTiempo = new DatosSelloTiempo();
			
			 // Para los esquemas 1.1.1 y 1.2.2 se validan includes con los nodos tomados en el sello
    		if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaURI) ||
    				ConstantesXADES.SCHEMA_XADES_122.equals(esquemaURI)) {
    			// Se obtienen los identificadores que deben existir
    			ArrayList<String> inc = UtilidadXadesA.obtenerListadoIdsElementosXadesA(esquemaURI, estructuraFirma.xmlSig, archiveTimeStampNode);
    			
    			// Se obtienen los identificadores que aparecen en la firma
    			ArrayList<Element> incNodes = UtilidadTratarNodo.obtenerNodos(archiveTimeStampNode, 1, 
    					new NombreNodo(esquemaURI, ConstantesXADES.INCLUDE));
    			
    			// Se comparan ambos resultados, atendiendo también al orden
    			String uriIncludeObtenida = null;
    			Element incNode = null;
    			String uriIncludeLeida = null;
    			for (int j = 0; j < inc.size(); ++j) {
    				uriIncludeObtenida = inc.get(j);				
    				incNode = incNodes.get(j);
    				uriIncludeLeida = incNode.getAttribute(ConstantesXADES.URI_MAYUS);

    				if (!uriIncludeObtenida.equals(uriIncludeLeida)) {
    					esValido = false;
    					// El sello de tiempo del nivel XAdES-A, no es válido
    					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR15));
    					LOGGER.error("El sello de tiempo del nivel XAdES-A, no es válido. Los nodos Include no coinciden con los esperados");
    					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR15));

    					return esValido;
    				}
    			}
    		}

			// Se obtiene el listado de elementos de un sello de tiempo XAdES A
            try {
                byteData = UtilidadXadesA.obtenerListadoXadesA(esquemaURI, estructuraFirma.xmlSig, archiveTimeStampNode);
            } catch (BadFormedSignatureException e) {
                esValido = false;
                LOGGER.error("Firma mal formada: " + e.getMessage());
                resultado.setLog(e.getMessage());
                logv.error(e.getMessage());
                return esValido;
            }

			// Se obtiene el array de bytes del nodo EncapsulatedTimeStamp
			NodeList nodesEncapsulatedTimeStamp = archiveTimeStampNode.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_ENCTIMESTAMP);

			if (nodesEncapsulatedTimeStamp.getLength() != 1) {
				esValido = false;
				// El nodo EncapsulatedTimeStamp dentro del sello de tiempo no existe o no es único
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
						ConstantesXADES.LIBRERIAXADES_ENCTIMESTAMP + ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + 
						ConstantesXADES.ESPACIO + nodesEncapsulatedTimeStamp.getLength());

				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
						ConstantesXADES.LIBRERIAXADES_ENCTIMESTAMP + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + 
						ConstantesXADES.ESPACIO + nodesEncapsulatedTimeStamp.getLength());			

				// El sello de tiempo XAdES-A no es válido
				resultado.setLog("El sello de tiempo XAdES-A no es válido");
				return esValido;
			}

			Element encapsulatedTimeStampElement = (Element)nodesEncapsulatedTimeStamp.item(0);

			// Se recoge el encoding, si existe
			String enc = encapsulatedTimeStampElement.getAttribute(ConstantesXADES.XADES_TAG_ENCODING);
			EncodingEnum encoding = EncodingEnum.getEncoding(enc);
			if (encoding == null) {
				esValido = false;
				LOGGER.error("Encoding del sello de tiempo A desconocido: " + enc);
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR171));
				return esValido;
			}

			String encapsulatedTS = encapsulatedTimeStampElement.getFirstChild().getNodeValue();
			byte [] timeStampBytes = Base64.decode(encapsulatedTS);

			// Se comparan los resultados obtenidos
			try {
				tsv2 = tsValidator.validateTimeStamp(byteData, timeStampBytes);
			} catch (TimeStampException e) {
				esValido = false;
				// El sello de tiempo XAdES-A no es válido
				LOGGER.info("El sello de tiempo XAdES-A no es válido");

				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR15));

				resultado.setLog("El sello de tiempo XAdES-A no es válido");
				return esValido;
			}

			// Se guardan los resultados obtenidos
			Date fechaSello = tsv2.getDate();
			if (fechaSello != null) {
				long now = System.currentTimeMillis();
				if (tsv2.getTimeAccurracy() > 0)
					now += tsv2.getTimeAccurracy();
				if (fechaSello.after(new Date(now))) {
					// La fecha del sello de tiempo del nivel XAdES-A es posterior a la actual
					resultado.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_16, fechaSello, tsv2.getTimeAccurracy(), new Date(System.currentTimeMillis())));  
					LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_16, fechaSello, tsv2.getTimeAccurracy(), new Date(System.currentTimeMillis())));  
					resultado.setResultado(ResultadoEnum.UNKNOWN);
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR82));
				}
			}

			try {
				datosSelloTiempo.setFecha(fechaSello);
				datosSelloTiempo.setEmisor(tsv2.getTimeStampIssuer());
				datosSelloTiempo.setAlgoritmo(TSPAlgoritmos.getAlgName(tsv2.getStampAlg()));					
				datosSelloTiempo.setPrecision(tsv2.getTimeAccurracy());
				datosSelloTiempo.setTipoSello(TipoSellosTiempo.CLASE_A);
				datosSelloTiempo.setRawTimestamp(tsv2.getTimeStampRawToken());
				CertPath tsaCerts = tsv2.getCadena();
				if (tsaCerts != null) {
					if (truster != null && tsaCerts.getCertificates().size() == 1) {
						try {
							// Se intenta obtener la cadena completa
							tsaCerts = truster.getCertPath((X509Certificate) tsaCerts.getCertificates().get(0));
							// Se ordena la cadena obtenida
							datosSelloTiempo.setCadena(
									UtilidadCertificados.orderCertPath(
											(Iterable<X509Certificate>)tsaCerts.getCertificates()));
						} catch (Exception e) {
							LOGGER.debug("No se pudo ordenar la cadena de certificados del sello de tiempo");
							datosSelloTiempo.setCadena(tsaCerts);
						}
					} else {
						LOGGER.debug("No se pudo recuperar la cadena de certificación");
						datosSelloTiempo.setCadena(tsaCerts);
					}
				}

				if (esValido) {
					logv.abreTag(true);
					logv.info("XAdES-A TimeStamp validation: VALID", 2);
					logv.info("Date: " + fechaSello, 2);
					logv.info("Issuer: " + tsv2.getTimeStampIssuer(), 2);
					logv.cierraTag(true);
					resultado.setNivelValido(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_TEXTO8));
				} else {
					logv.abreTag(false);
					logv.info("XAdES-A TimeStamp validation: INVALID", 2);
					logv.info("Date: " + fechaSello, 2);
					logv.info("Issuer: " + tsv2.getTimeStampIssuer(), 2);
					logv.cierraTag(false);
				}


			} catch (Exception e) {
				// No se pudo generar los datos de la TSA
				esValido = false;
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR64), e);

				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR64));

				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR64));
				return esValido;
			}

			arrayDatosSello.add(datosSelloTiempo);
		}

		return true;
	}

	/**
	 * Busca en CertificateValues un certificado encapsulado con el mismo issuer y serial Number que el parametrizado
	 * 
	 * @param certIssuer Emisor del certificado a buscar
	 * @param serialNumber Número de serie del certificado a buscar
	 * @return Si se encontró coincidencia, se devuelve el elemento EncapsulatedX509Certificate. En caso contrario, un valor nulo
	 */
	private X509Certificate buscarCertificateValue(X500Principal certIssuer, BigInteger serialNumber, EstructuraFirma estructuraFirma) {
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		X509Certificate certificado = null;
		CertificateValues certificateValues = new CertificateValues(estructuraFirma.esquema);
		
		// Se busca el nodo CertificateValues para obtener sus nodos hijo
		ArrayList<Element> certificateValuesNodeList = new ArrayList<Element> ();
		try {
			certificateValuesNodeList = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.CERTIFICATE_VALUES));
		} catch (FirmaXMLError e) {
			LOGGER.debug(e.getMessage(), e);
			return null;
		}
		int certLength = certificateValuesNodeList.size();
		
		for (int i = 0; i < certLength; ++i) {
			try {
				certificateValues.load((Element) certificateValuesNodeList.get(i));
			} catch (InvalidInfoNodeException e) {
				LOGGER.debug(e.getMessage(), e);
				return null;
			}
			ArrayList<EncapsulatedX509Certificate> certificados = certificateValues.getCertificates();
			int certificadosLength = certificados.size();
			
			for (int j = 0; j < certificadosLength; ++j) {
				EncapsulatedX509Certificate certEncapsulated = certificados.get(j);
				try {
					certificado = certEncapsulated.getX509Certificate();
				} catch (CertificateException e) {
					LOGGER.debug(e.getMessage(), e);
					return null;
				}
				
				// Si coinciden los valores, se devuelve el X509Certificate encontrado
				if (certIssuer.equals(certificado.getIssuerX500Principal()) && 
						serialNumber.equals(certificado.getSerialNumber()))
					return certificado;
			}
		}
		
		return null;
	}

	/**
	 * Busca en RevocationValues una respuesta OCSP encapsulada que de el mismo valor de digest
	 * 
	 * @param digest .- Digest que debe resultar del nodo a buscar
	 * @param method .- Algoritmo a utilizar para el cálculo del digest
	 * @return Si se encontró coincidencia, se devuelve el elemento EncapsulatedOCSPValue. En caso contrario, un valor nulo
	 */
	private Element buscarRevocationValueOCSP(String digest, String method, EstructuraFirma estructuraFirma) {
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		// Se busca el nodo RevocationValues
		ArrayList<Element> revocationValuesNodeList = new ArrayList<Element>();
		try {
			revocationValuesNodeList = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.REVOCATION_VALUES));
		} catch (FirmaXMLError e) {
			LOGGER.debug(e.getMessage(), e);
			return null;
		}
		int revocationLength = revocationValuesNodeList.size();
		
		for (int i = 0; i < revocationLength; ++i) {
			// Se obtienen los hijos de OCSPValues para cada RevocationValue encontrado
			Element revocationValuesElement = (Element) revocationValuesNodeList.get(i);
			NodeList ocspValues = revocationValuesElement.getElementsByTagNameNS(esquemaURI, ConstantesXADES.OCSP_VALUES);
			if (ocspValues.getLength() != 1) {
				// El nodo OCSPValues no existe o no es único. Número de nodos presentes: X
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
						ConstantesXADES.OCSP_VALUES + ConstantesXADES.ESPACIO +
						I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + ConstantesXADES.ESPACIO + 
						ocspValues.getLength());
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
						ConstantesXADES.OCSP_VALUES + ConstantesXADES.ESPACIO +
						I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + ConstantesXADES.ESPACIO + 
						ocspValues.getLength());
				
				return null;				
			}
			ArrayList<Element> respuestasOCSP = UtilidadTratarNodo.getElementChildNodes((Element)ocspValues.item(0), false);
			if (respuestasOCSP == null) {
				esValido = false;
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.OCSP_VALUES));			
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.OCSP_VALUES));
				return null;
			}
			int respuestasOCSPLength = respuestasOCSP.size();
			
			for (int j = 0; j < respuestasOCSPLength; ++j) {
				// Se obtienen las respuestas OCSP encapsuladas y se calcula su Digest
				Element respuestaOCSPElement = (Element) respuestasOCSP.get(j);
				if (!(new NombreNodo(esquemaURI, ConstantesXADES.ENCAPSULATED_OCSP_VALUE).equals(
						new NombreNodo(respuestaOCSPElement.getNamespaceURI(), respuestaOCSPElement.getLocalName())))) { 
					// Al menos existe un nodo hijo de OCSPValues que no es del tipo EncapsulatedOCSPValue
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR119));
					
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR119));
					
					return null;
				}
				
				byte[] data = null;
				String encapsulatedValue = respuestaOCSPElement.getFirstChild().getNodeValue();
				if (encapsulatedValue != null) {
					try {
						 data = Base64Coder.decode(encapsulatedValue);
					} catch (IllegalArgumentException ex) {
						// Contenido base64 de EncapsulatedOCSPValue inválido
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR120), ex);
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR120));
						
						break;
					}			
				} else {
					// No se pudo recuperar el contenido de EncapsulatedOCSPValue
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR121));
					
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR121));
					
					return null;
				}
				// Se calcula el digest con el mismo algoritmo que el OCSP buscado
				MessageDigest resumenTemp = UtilidadFirmaElectronica.getMessageDigest(method);
				byte[] resumenMensajeByte = resumenTemp.digest(data);
				String digestLeido = new String(Base64Coder.encode(resumenMensajeByte));
				
				// Si coinciden los valores, se devuelve el nodo encontrado
				if (digest.equals(digestLeido))
					return respuestaOCSPElement;
			}
		}
		
		return null;
	}
	
	/**
	 * Busca en RevocationValues una CRL encapsulada con el mismo digest
	 * 
	 * @param digest .- Digest que debe resultar del nodo a buscar
	 * @param method .- Algoritmo a utilizar para el cálculo del digest
	 * @return Si se encontró coincidencia, se devuelve el elemento EncapsulatedCRLValue. En caso contrario, un valor nulo
	 */
	private Element buscarRevocationValueCRL(String digest, String method, EstructuraFirma estructuraFirma) {
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		
		// Se busca el nodo RevocationValues
		ArrayList<Element> revocationValuesNodeList = new ArrayList<Element> ();
		try {
			revocationValuesNodeList = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.REVOCATION_VALUES));
		} catch (FirmaXMLError e) {
			LOGGER.debug(e.getMessage(), e);
			return null;
		}
		int revocationLength = revocationValuesNodeList.size();
		
		for (int i = 0; i < revocationLength; ++i) {
			// Se obtienen los hijos de CRLValues para cada RevocationValue encontrado
			Element revocationValuesElement = (Element) revocationValuesNodeList.get(i);
			NodeList crlValues = revocationValuesElement.getElementsByTagNameNS(esquemaURI, ConstantesXADES.CRL_VALUES);
			if (crlValues.getLength() != 1) {
				// El nodo CRLValues no existe o no es único. Número de nodos presentes: X
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
						ConstantesXADES.CRL_VALUES + ConstantesXADES.ESPACIO +
						I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + ConstantesXADES.ESPACIO + 
						crlValues.getLength());
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + ConstantesXADES.ESPACIO + 
						ConstantesXADES.CRL_VALUES + ConstantesXADES.ESPACIO +
						I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + ConstantesXADES.ESPACIO + 
						crlValues.getLength());
				
				return null;				
			}
			ArrayList<Element> crls = UtilidadTratarNodo.getElementChildNodes((Element)crlValues.item(0), false);
			if (crls == null) {
				esValido = false;
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.CRL_VALUES));			
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
						ConstantesXADES.ESPACIO + ConstantesXADES.CRL_VALUES));
				return null;
			}
			int crlsLength = crls.size();
			
			for (int j = 0; j < crlsLength; ++j) {
				// Se obtienen las listas de revocación y se reconstruyen para calcular su Digest
				Element crlElement = (Element) crls.get(j);
				if (!(new NombreNodo(esquemaURI, ConstantesXADES.ENCAPSULATED_CRL_VALUE).equals(
						new NombreNodo(crlElement.getNamespaceURI(), crlElement.getLocalName())))) { 
					// Al menos existe un nodo hijo de CRLValues que no es del tipo EncapsulatedCRLValue
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR122));
					
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR122));
					
					return null;
				}
				
				// Se obtiene el valor de la CRL
				byte[] data = null;
				String encapsulatedValue = crlElement.getFirstChild().getNodeValue();
				if (encapsulatedValue != null) {
					try {
						 data = Base64Coder.decode(encapsulatedValue);
					} catch (IllegalArgumentException ex) {
						// Contenido base64 de EncapsulatedCRLValue inválido
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR123), ex);
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR123));
						
						break;
					}					
				} else {
					// No se pudo recuperar el contenido de EncapsulatedCRLValue
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR124));
					
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR124));
					
					return null;
				}
				// Se calcula el digest con el mismo algoritmo que la CRL buscada
				MessageDigest resumenTemp = UtilidadFirmaElectronica.getMessageDigest(method);
				byte[] resumenMensajeByte = resumenTemp.digest(data);
				String digestLeido = new String(Base64Coder.encode(resumenMensajeByte));
			
				// Si coinciden los valores, se devuelve el nodo encontrado
				if (digest.equals(digestLeido))
					return crlElement;
			}
		}
		
		return null;
	}
	
	/**
	 * Indica el tipo de firma que tiene el documento
	 * @return El nombre del tipo de firma
	 */
 	private DatosTipoFirma tipoFirma(EstructuraFirma estructuraFirma) throws BadFormedSignatureException
 	{

 		Element firma = estructuraFirma.firma;
 		String esquema = estructuraFirma.esquema.getSchemaUri();
 		
 		DatosTipoFirma datosTipoFirma = new DatosTipoFirma();
 		boolean esXAdES_C = false;
 		boolean esXAdES_X = false;

 		// Tomaremos que, por defecto, la fima es de tipo XAdES-BES (a continuación se valida que así sea)
 		datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_BES);

 	// Se comprueba que la firma sea XAdES-BES buscando el nodo QualifyingProperties

 		ArrayList<Element> nodosObject = UtilidadTratarNodo.obtenerNodos(firma, null, 
 				new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.OBJECT));
 		Iterator<Element> itObject = nodosObject.iterator();
 		int numQualifyingProperties = 0;
 		while (itObject.hasNext()) {
 	 		ArrayList<Element> nodosQualifyingProperties = UtilidadTratarNodo.obtenerNodos(itObject.next(), null, 
 	 				new NombreNodo(esquema, ConstantesXADES.LIBRERIAXADES_QUALIFYING_PROPERTIES));
 	 		numQualifyingProperties += nodosQualifyingProperties.size();
 		}

 		if (numQualifyingProperties != 1) {
 			// El nodo QuialifyingProperties no existe o no es único. Número de nodos presentes: X
 			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 					ConstantesXADES.ESPACIO + ConstantesXADES.LIBRERIAXADES_QUALIFYING_PROPERTIES + 
 					ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + 
 					ConstantesXADES.ESPACIO + numQualifyingProperties);
 			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 					ConstantesXADES.ESPACIO + ConstantesXADES.LIBRERIAXADES_QUALIFYING_PROPERTIES + 
 					ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + 
 					ConstantesXADES.ESPACIO + numQualifyingProperties);
			// Se comprueba que se trate de una firma de tipo XMLDSig
			ArrayList<Element> nodosSigValue = UtilidadTratarNodo.obtenerNodos(
					firma, null, new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.SIGNATURE_VALUE));
			Iterator<Element> itSigVal = nodosSigValue.iterator();
			if (itSigVal.hasNext()) {
				datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XMLSignature);
				return datosTipoFirma;
 			}
 			// Firma XAdES mal formada
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR125));
 		}

 	// Se comprueba que la firma sea XAdES-EPES buscando el nodo SignaturepolicyIdentifier
 		ArrayList<Element> nodosSignaturePolicyIdentifier = new ArrayList<Element> ();
 		try {
 			nodosSignaturePolicyIdentifier = UtilidadTratarNodo.obtenerNodos(firma, 5,
 				new NombreNodo(esquema, ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER));
 		} catch (FirmaXMLError e) {
 			LOGGER.error(e.getMessage(), e);
 			// Firma XAdES-EPES mal formada
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR126));
 		}
 		int numSignaturePolicyIdentifier = nodosSignaturePolicyIdentifier.size();

 		if (numSignaturePolicyIdentifier > 1) {
 			// El nodo SignaturePolicyIdentifier no es único. Número de nodos presentes: X
 			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) +
 					ConstantesXADES.ESPACIO + ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER + 
 					ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 					ConstantesXADES.ESPACIO + numSignaturePolicyIdentifier);

 			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) +
 					ConstantesXADES.ESPACIO + ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER + 
 					ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 					ConstantesXADES.ESPACIO + numSignaturePolicyIdentifier);
 			
 			
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR126));
 		} else if (ConstantesXADES.SCHEMA_XADES_111.equals(esquema) && numSignaturePolicyIdentifier < 1) {
 			// No se encuentra el nodo SignaturePolicyIdentifier
 			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_33) + 
 					ConstantesXADES.ESPACIO + ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER);
 			// Firma XAdES-EPES mal formada
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR126));
 		} else if (numSignaturePolicyIdentifier == 1) {
 			datosTipoFirma.setEsXAdES_EPES(true);
 		}

 	// Se comprueba que la firma sea XAdES-T buscando el nodo SignatureTimeStamp
 		ArrayList<Element> nodosSignatureTimeStamp = new ArrayList<Element>();
 		try {
 			nodosSignatureTimeStamp = UtilidadTratarNodo.obtenerNodos(firma, 5, 
 				new NombreNodo(esquema, ConstantesXADES.SIGNATURE_TIME_STAMP));
 		} catch (FirmaXMLError e) {
 			LOGGER.debug(e.getMessage(), e);
 		}
 			
 		int numSignatureTimeStamp = nodosSignatureTimeStamp.size();

 		if (numSignatureTimeStamp > 0) {
 			datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_T);
 		}
 	// Se comprueba que la firma sea XAdES-C buscando el nodo CompleteCertificateRefs y CompleteRevocationRefs
 		ArrayList<Element> nodosCompleteCertificateRefs = new ArrayList<Element> ();
 		ArrayList<Element> nodosCompleteRevocationRefs = new ArrayList<Element> ();
 		try {
 			nodosCompleteCertificateRefs = UtilidadTratarNodo.obtenerNodos(firma, 5, 
 				new NombreNodo(esquema, ConstantesXADES.COMPLETE_CERTIFICATE_REFS));
 			nodosCompleteRevocationRefs = UtilidadTratarNodo.obtenerNodos(firma, 5, 
 				new NombreNodo(esquema, ConstantesXADES.COMPLETE_REVOCATION_REFS));
 		} catch (FirmaXMLError e) {
 			LOGGER.error(e.getMessage(),e);
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR127));
 		}
 				
 		int numCompleteCertificateRefs = nodosCompleteCertificateRefs.size();
 		int numCompleteRevocationRefs = nodosCompleteRevocationRefs.size();

 		if (numCompleteCertificateRefs > 1 || numCompleteCertificateRefs != numCompleteRevocationRefs) {
 			if (numCompleteCertificateRefs > 1) {
 				// El nodo CompleteCertificateRefs no es único. Número de nodos presentes: X
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 						ConstantesXADES.ESPACIO + ConstantesXADES.COMPLETE_CERTIFICATE_REFS + 
 						ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 						ConstantesXADES.ESPACIO + numCompleteCertificateRefs);
 				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 						ConstantesXADES.ESPACIO + ConstantesXADES.COMPLETE_CERTIFICATE_REFS + 
 						ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 						ConstantesXADES.ESPACIO + numCompleteCertificateRefs);
 				
 			} else {
 				// El nodo CompleteRevocationRefs no es único. Número de nodos presentes: X
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 						ConstantesXADES.ESPACIO + ConstantesXADES.COMPLETE_REVOCATION_REFS + 
 						ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 						ConstantesXADES.ESPACIO + numCompleteRevocationRefs);
 				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 						ConstantesXADES.ESPACIO + ConstantesXADES.COMPLETE_REVOCATION_REFS + 
 						ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 						ConstantesXADES.ESPACIO + numCompleteRevocationRefs);
 			}
 			// Firma XAdES-C mal formada
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR127));
 		} else if (numCompleteCertificateRefs == 1 && numCompleteCertificateRefs == numCompleteRevocationRefs) {
 			if (ConstantesXADES.SCHEMA_XADES_111.equals(esquema) && !EnumFormatoFirma.XAdES_T.equals(datosTipoFirma.getTipoXAdES())) {
 				// La firma es una XAdES-C mal formada porque carece del nivel XAdES-T en el esquema 1.1.1
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR131));

 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR127));
 			} else {
 				esXAdES_C = true;
 				datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_C);
 			}
 		}

 	// Se comprueba que la firma sea XAdES-A buscando los nodos ArchiveTimeStamp, CertificateValues y RevocationValues
 		ArrayList<Element> nodosArchiveTimeStamp = new ArrayList<Element> ();
 		ArrayList<Element> nodosCertificateValues = new ArrayList<Element> ();
 		ArrayList<Element> nodosRevocationValues = new ArrayList<Element> ();
 		try {
 			nodosArchiveTimeStamp = UtilidadTratarNodo.obtenerNodos(firma, 5, 
 				new NombreNodo(esquema, ConstantesXADES.ARCHIVE_TIME_STAMP));
	 		nodosCertificateValues = UtilidadTratarNodo.obtenerNodos(firma, 5, 
	 			new NombreNodo(esquema, ConstantesXADES.CERTIFICATE_VALUES));
	 		nodosRevocationValues = UtilidadTratarNodo.obtenerNodos(firma, 5, 
	 			new NombreNodo(esquema, ConstantesXADES.REVOCATION_VALUES));
 		} catch (FirmaXMLError e) {
 			LOGGER.error(e.getMessage(), e);			
 		}
 		int numArchiveTimeStamp = nodosArchiveTimeStamp.size();
 		int numCertificateValues = nodosCertificateValues.size();
 		int numRevocationValues = nodosRevocationValues.size();
 		
 		if (numArchiveTimeStamp > 0) {
 			if (numCertificateValues < 1 || numRevocationValues < 1) {
 				// La firma es una XAdES-A mal formada porque carece de los nodos Certificatevalues y/o RevocationValues 
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR132));
 				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR132));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR128));
 			} else if (numCertificateValues > 1 || numRevocationValues > 1) {
 				// La firma es una XAdES-A mal formada porque los nodos Certificatevalues y/o RevocationValues no son únicos 
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR133)); 
 				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR133));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR128));
 			} else if (ConstantesXADES.SCHEMA_XADES_111.equals(esquema) && !esXAdES_C) {
 				// La firma es una XAdES-A mal formada porque carece del nivel XAdES-C en el esquema 1.1.1
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR134));
 				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR134));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR128));
 			} else
 				datosTipoFirma.setEsXAdES_A(true);
 		}

 	// Se comprueba que la firma sea XAdES-X buscando los nodos SigAndRefsTimeStamp y/o RefsOnlyTimeStamp
 		ArrayList<Element> nodosSigAndRefTimeStamp = new ArrayList<Element> ();
 		ArrayList<Element> nodosRefsOnlyTimeStamp = new ArrayList<Element> ();
 		try {
 			nodosSigAndRefTimeStamp = UtilidadTratarNodo.obtenerNodos(firma, 5, 
 				new NombreNodo(esquema, ConstantesXADES.SIG_AND_REFS_TIME_STAMP));
 			nodosRefsOnlyTimeStamp = UtilidadTratarNodo.obtenerNodos(firma, 5, 
 				new NombreNodo(esquema, ConstantesXADES.REFS_ONLY_TIME_STAMP));
 		} catch (FirmaXMLError e) {
 			LOGGER.error(e.getMessage(), e);
 		}
 		int numSigAndRefsTimeStamp = nodosSigAndRefTimeStamp.size();
 		int numRefsOnlyTimeStamp = nodosRefsOnlyTimeStamp.size();

 		if (numSigAndRefsTimeStamp > 0 || numRefsOnlyTimeStamp > 0) {
 			if (!esXAdES_C) {
 				// La firma es una XAdES-X mal formada porque carece del nivel XAdES-C
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR135));
 				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR135));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR129));
 			} else {
 				esXAdES_X = true;
 				datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_X);
 			}
 		}

 	// Se comprueba que la firma sea XAdES-XL buscando los nodos CertificateValues y RevocationValues (ya buscados al validar XAdES-A)

 		if (numCertificateValues > 1 || numRevocationValues > 1) {
 			// La firma es una XAdES-A mal formada porque los nodos Certificatevalues y/o RevocationValues no son únicos 
 			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR133)); 
 			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR133));
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR128));
 		} else if (numCertificateValues == 1 && numRevocationValues == 1) {
 			// Si es XAdES-X y tiene los Values --> es XAdES-XL
 			// Si no es XAdES-X, tiene los Values y es XAdES-A --> No es XL pero no salta excepción (es XAdES-A)
 			// Si no es XAdES-X ni XAdES-A pero sí tiene los Values --> Excepción! es una XL mal formada 
 			if (esXAdES_X) {
 				datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_XL);
 			} else if (!datosTipoFirma.esXAdES_A()) {
 				// La firma es una XAdES-XL mal formada porque carece del nivel XAdES-X y no es XAdES-A
 				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR137));
 				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR137));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR130));
 			}
 		} 

 		LOGGER.debug(datosTipoFirma.getTipoXAdES());
 		return datosTipoFirma;
	}
	
	/**
	 * Saca del nodo SigningTime los datos de la fecha de firma.
	 * Si falla el parseo de la firma porque no tiene un formato correcto devuelve un nulo
	 * @return Date fechaFirma
	 */
	
	private Date obtenerFechaFirma(EstructuraFirma estructuraFirma) {
		// Buscamos la fecha de la firma

        ArrayList<Element> nodesSignTimeValue = new ArrayList<Element> ();
        Date fechaFirma = null; 
        
        SigningTime momentoFirma = new SigningTime(estructuraFirma.esquema);

        try {
        	nodesSignTimeValue = UtilidadTratarNodo.obtenerNodos(estructuraFirma.firma, 5, 
        		new NombreNodo(estructuraFirma.esquema.getSchemaUri(), ConstantesXADES.SIGNING_TIME));
        } catch (FirmaXMLError e) {
        	LOGGER.error(e.getMessage(), e);
        }
  	                          
        if(nodesSignTimeValue.size() != 0) {
        	try {
				momentoFirma.load((Element)nodesSignTimeValue.get(0));
			} catch (InvalidInfoNodeException e) {
				LOGGER.warn(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
				
				return null;
			}
        	fechaFirma =  momentoFirma.getValue();
        }
        
        if (fechaFirma == null) {
        	if(nodesSignTimeValue.size() != 0) {
        		// No se puede parsear la fecha. El formato no es correcto
        		LOGGER.warn(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
        		logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR63));
        	} else {
        		// No se puede parsear la fecha. No existe el nodo SigningCertificate
        		LOGGER.warn(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR163));
    			logv.info(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR163));
        	}
			
		}
        return fechaFirma;
    }
	
	/**
	 * Obtiene los roles del nodo ClaimedRoles
	 * @return ArrayList<String> roles
	 */
	private ArrayList<String> obtenerRoles (EstructuraFirma estructuraFirma) {
		
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();
		// Buscamos el valor de los roles
		ArrayList<String> roles = new ArrayList<String>();
		
		ArrayList<Element> lst = UtilidadTratarNodo.obtenerNodos(estructuraFirma.signedSignatureProperties, 
				null, new NombreNodo(esquemaURI, ConstantesXADES.SIGNER_ROLE));
		Iterator<Element> it = lst.iterator();
		while (it.hasNext()) {
			NodeList nodesClaimedRoles = it.next().getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_CLAIMEDROLE);

			int nodesClaimedRolesLength = nodesClaimedRoles.getLength();
			for (int i=0; i<nodesClaimedRolesLength; i++)
			{
				Element stElement = (Element)nodesClaimedRoles.item(i);
				roles.add(stElement.getTextContent());
			}
		}

		return (roles.size() > 0) ? roles : null;
	}
	
	/**
	 * Saca del nodo QualifyingProperties el esquema. 
	 * Devuelve nulo si no esta en la lista de esquemas que se pueden validar.
	 * @return String esquema
	 */
	private EstructuraFirma obtenerEsquema(Element firma)
	{
		String esquema = null;
		for (Iterator<String> it = esquemasParaValidar.iterator(); it.hasNext( ); )
		{
			esquema = (it.next()).trim();
			// identifica el nodo QualifyingProperties
	 		Element qualifyingElement = null;
	 		ArrayList<Element> nodosObject = UtilidadTratarNodo.obtenerNodos(firma, null, new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.OBJECT));
	 		Iterator<Element> itObject = nodosObject.iterator();
	 		while (itObject.hasNext()) {
	 	 		ArrayList<Element> nodosQualifyingProperties = UtilidadTratarNodo.obtenerNodos(itObject.next(), null, new NombreNodo(esquema, ConstantesXADES.LIBRERIAXADES_QUALIFYING_PROPERTIES));
	 	 		if (nodosQualifyingProperties.size() > 0) {
	 	 			qualifyingElement = nodosQualifyingProperties.get(0);
	 	 			break;
	 	 		}
	 		}

			if (qualifyingElement != null) {
				EstructuraFirma ef = new EstructuraFirma();
				ef.firma = firma;
				ArrayList<Element> signedProperties = UtilidadTratarNodo.obtenerNodos(qualifyingElement, null, new NombreNodo(esquema, ConstantesXADES.SIGNED_PROPERTIES));
				if (signedProperties.size() != 1)
					return null;
				ArrayList<Element> signedSignatureProperties = UtilidadTratarNodo.obtenerNodos(signedProperties.get(0), null, new NombreNodo(esquema, ConstantesXADES.SIGNED_SIGNATURE_PROPERTIES));
				if (signedSignatureProperties.size() != 1)
					return null;
				ef.signedSignatureProperties = signedSignatureProperties.get(0);
				ArrayList<Element> unsignedProperties = UtilidadTratarNodo.obtenerNodos(qualifyingElement, null, new NombreNodo(esquema, ConstantesXADES.UNSIGNED_PROPERTIES));
				if (unsignedProperties.size() != 1)
					ef.unsignedSignatureProperties = null;
				else {
					ArrayList<Element> unsignedSignatureProperties = UtilidadTratarNodo.obtenerNodos(unsignedProperties.get(0), null, new NombreNodo(esquema, ConstantesXADES.UNSIGNED_SIGNATURE_PROPERTIES));
					if (unsignedSignatureProperties.size() != 1)
						ef.unsignedSignatureProperties = null;
					else
						ef.unsignedSignatureProperties = unsignedSignatureProperties.get(0);
				} 
				ef.esquema = XAdESSchemas.getXAdESSchema(esquema);
				return ef;
			} else if (esquema.equals(ConstantesXADES.SCHEMA_DSIG)) {
				// Buscar XMLDSig
				Element sigValElement = null;
				ArrayList<Element> nodosSigValue = UtilidadTratarNodo.obtenerNodos(
						firma, null, new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.SIGNATURE_VALUE));
				Iterator<Element> itSigVal = nodosSigValue.iterator();
				while (itSigVal.hasNext()) {
					sigValElement = itSigVal.next();
					if (esquema.equals(sigValElement.getNamespaceURI())) {
						EstructuraFirma ef = new EstructuraFirma();
						ef.firma = firma;
						ef.esquema = XAdESSchemas.getXAdESSchema(esquema);
						return ef;
					} else {
						break;
					}
				}
			}
		}
		
		// No se han encontrado esquemas
		EstructuraFirma ef = new EstructuraFirma();
		ef.firma = firma;

		return ef;
	}
	
	/**
	 * Obtiene la cadena de certificados buscando en los nodos KeyInfo, CertificateValues y CompleteCertificateRefs
	 * 
	 * @param Element firma.- Firma a validar
	 * @return boolean.- En caso de error se devuelve un false
	 */
	private boolean obtenerCadenaCertificados(EstructuraFirma estructuraFirma) {
		
		Element firma = estructuraFirma.firma;
		String esquemaURI = estructuraFirma.esquema.getSchemaUri();

		if (firma == null) {
			esValido = false;
			// No se encuentra la firma a validar
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR76));
			LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR76));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR76));
			
			return false;
		}

		DatosX509 certificadoFirma = null;
		// Se obtiene la cadena de certificados de KeyInfo, si existe
		ArrayList<X509Certificate> certificadosKeyInfo = new ArrayList<X509Certificate> ();
		ArrayList<Element> nodosKeyInfo = new ArrayList<Element> ();
		try {
			nodosKeyInfo = UtilidadTratarNodo.obtenerNodos(firma, 2, 
				new NombreNodo(uriXmlNS, ConstantesXADES.LIBRERIAXADES_KEY_INFO));
		} catch (FirmaXMLError e) {
			LOGGER.error(e.getMessage(), e);
		}
		if (nodosKeyInfo.size() > 0) {
			Element nodoKeyInfo = (Element)nodosKeyInfo.get(0);
			// Obtenemos los nodos X509Data
			NodeList nodosX509Data = nodoKeyInfo.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_X509_DATA);
			int nodosX509DataLenght = nodosX509Data.getLength();
			for(int i = 0; i < nodosX509DataLenght; ++i) {
				Element nodoX509Data = (Element)nodosX509Data.item(i);
				// Obtenemos sus nodos X509Certificate
				NodeList x509Cert = nodoX509Data.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_X509_CERTIFICATE);
				int x509CertLenght = x509Cert.getLength();
				for(int x = 0; x < x509CertLenght; ++x) {
					Node nodoX509Certificate = x509Cert.item(x);
					try
					{
						ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(nodoX509Certificate.getFirstChild().getNodeValue()));
						CertificateFactory cf = CertificateFactory.getInstance(ConstantesXADES.X_509);
						certificadosKeyInfo.add((X509Certificate)cf.generateCertificate(bais));
					} catch (CertificateException e1) {
						esValido = false;
						// Firma inválida. No se pudo obtener el certificado firmante
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						// Error al instanciar la factoría de certificados
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), e1);
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						
						return false;
					} 
				}
			}
		} else {
			// Se obtienen los datos del certificado contenido en SigningCertificate, si existe
			certificadoFirma = new DatosX509();
			ArrayList<Element> nodosSigningCertificate = new ArrayList<Element> ();
			try {
				nodosSigningCertificate = UtilidadTratarNodo.obtenerNodos(firma, 5, 
					new NombreNodo(esquemaURI, ConstantesXADES.LIBRERIAXADES_SIGNINGCERTIFICATE));
			} catch (FirmaXMLError e) {
				LOGGER.error(e.getMessage(), e);
			}
			if (nodosSigningCertificate.size() == 1) {
				Node nodoSigningCertificate = nodosSigningCertificate.get(0);
				ArrayList<Element> nodosCert = UtilidadTratarNodo.getElementChildNodes((Element)nodoSigningCertificate, false);
				if (nodosCert == null) {
					esValido = false;
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
							ConstantesXADES.ESPACIO + ConstantesXADES.CERT));			
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
							ConstantesXADES.ESPACIO + ConstantesXADES.CERT));
					return false;
				}
				String algoritmo = null;
				String digest = null;
				Element nodoCert = (Element) nodosCert.get(0); // Solo tomamos el primero
				Element certDigest = (Element)nodoCert.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_CERTDIGEST).item(0);
				if (certDigest != null) {
					NodeList digAlgs = certDigest.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD);
					if (digAlgs != null) {
						Element certDigestAlgElement = (Element)digAlgs.item(0);
						algoritmo = certDigestAlgElement.getAttributes().getNamedItem(ConstantesXADES.ALGORITHM).getNodeValue();					}
					NodeList digValues = certDigest.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE);
					if (digValues != null) {
						Element certDigestValElement = (Element)digValues.item(0);
						digest = certDigestValElement.getFirstChild().getNodeValue();
					}
					certificadoFirma.setAlgMethod(algoritmo);
					certificadoFirma.setDigestValue(digest);
				}
			} else {
				// No se puede recuperar el certificado firmante porque no existe el nodo KeyInfo ni el nodo SigningCertificate
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR138));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR138));
				
				esValido = false;
				// Firma inválida. No se pudo obtener el certificado firmante
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
				return false;
			}
		}

		// Se obtiene la cadena de certificados de CertificateValues o en su lugar, de CompleteCertificateRefs
		ArrayList<X509Certificate> certificadosRef = new ArrayList<X509Certificate> ();
		ArrayList<Element> nodosCertValue = new ArrayList<Element> ();
		try {
			nodosCertValue = UtilidadTratarNodo.obtenerNodos(firma, 5, 
				new NombreNodo(esquemaURI, ConstantesXADES.CERTIFICATE_VALUES));
		} catch (FirmaXMLError e) {
			LOGGER.error(e.getMessage(), e);
		}
		if (nodosCertValue.size() > 0) {
			Element nodoCertValue = (Element)nodosCertValue.get(0);
			// Obtenemos los nodos EncapsulatedX509Certificate
			NodeList nodosX509Cert = nodoCertValue.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_X509VALUE);
			int nodosX509DataLenght = nodosX509Cert.getLength();
			for(int i = 0; i < nodosX509DataLenght; ++i) {
				Element nodoX509Cert = (Element)nodosX509Cert.item(i);			
				try
				{
					ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(nodoX509Cert.getFirstChild().getNodeValue()));
					CertificateFactory cf = CertificateFactory.getInstance(ConstantesXADES.X_509);
					certificadosRef.add((X509Certificate)cf.generateCertificate(bais));
				} catch (CertificateException e1) {
					esValido = false;
					// Firma inválida. No se pudo obtener el certificado firmante
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
					// Error al instanciar la factoría de certificados
					LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR23), e1);
					
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
					
					return false;
				} 		
			}
		} else 
		{
			// Se obtienen los nodos CompleteCertificateRefs
			ArrayList<Element> nodosCompCertRef = new ArrayList<Element> ();
			try {
				nodosCompCertRef = UtilidadTratarNodo.obtenerNodos(firma, 5, 
					new NombreNodo(esquemaURI, ConstantesXADES.COMPLETE_CERTIFICATE_REFS));
			} catch (FirmaXMLError e) {
				LOGGER.error(e.getMessage(), e);
			}
			if (nodosCompCertRef.size() > 0) {
				// Obtenemos el nodo CertRefs, que contiene los nodos Cert
				Node nodoCertRefs = UtilidadTratarNodo.getFirstElementChild((Element)nodosCompCertRef.get(0), false);
				if (nodoCertRefs == null) {
					esValido = false;
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
							ConstantesXADES.ESPACIO + ConstantesXADES.CERT_REFS));			
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
							ConstantesXADES.ESPACIO + ConstantesXADES.CERT_REFS));
					return false;
				}
				ArrayList<Element> nodosCert = UtilidadTratarNodo.getElementChildNodes((Element)nodoCertRefs, false);
				if (nodosCert == null) {
					esValido = false;
					resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
							ConstantesXADES.ESPACIO + ConstantesXADES.CERT));			
					logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR95 +
							ConstantesXADES.ESPACIO + ConstantesXADES.CERT));
					return false;
				}
				int nodosCertSize = nodosCert.size();
				for(int i = 0; i < nodosCertSize; ++i) {
					Node nodoCert = nodosCert.get(i);
					String uri = null;
					try {
						uri = URLDecoder.decode(nodoCert.getAttributes().getNamedItem(tipoUri).getNodeValue(), ConstantesXADES.UTF8);
					} catch (UnsupportedEncodingException e) {
						// No se puede decodificar la URI a UTF-8
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR30), e);
						esValido = false;
						// Firma inválida. No se pudo obtener el certificado firmante
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						
					} catch (Exception e) {
						// No se pudo recuperar la URI del nodo CertDigest
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR65), e);
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR65));
						
						esValido = false;
						// Firma inválida. No se pudo obtener el certificado firmante
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
					}
					// La uri puede apuntar a un nodo dentro de CertificateValues o a un fichero externo.
					// Dado que el flujo impone que no existe dicho nodo, se va a buscar el fichero externo 
					if ((uri != null) && (!uri.startsWith(ConstantesXADES.ALMOHADILLA))) {
						X509Certificate certFile = null;
						if (recoverManager != null) {
							Map<String, Object> props = new HashMap<String, Object>();
							props.put(IRecoverElements.PROP_URI, uri);

							try {
								certFile = recoverManager.getElement(props, X509Certificate.class);
							} catch (ElementNotFoundException ex) {
								LOGGER.warn(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_2));
								if (LOGGER.isTraceEnabled()) {
									LOGGER.trace(props);
								}
							} catch (UnknownElementClassException ex) {
								LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_3, "X509Certificate"), ex);
							}
						}
						if (certFile == null) {
							LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_1, uri));
							esValido = false;
							// Firma inválida. No se pudo obtener el certificado firmante
							// TODO: marcar esta firma como desconocida por no poderse recuperar información necesaria para su validación
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
							
							logv.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_1, uri));
							
							return false;
						}

						// Se toman las variables de la firma para validar que sean correctas

						Element certElement = (Element)nodoCert;		
						Element certDigest = (Element)certElement.getElementsByTagNameNS(esquemaURI, ConstantesXADES.LIBRERIAXADES_CERTDIGEST).item(0);	// Sacamos CertDigest

						String alg = null;     			
						String digest = null;
						String resumenCertificado = ConstantesXADES.CADENA_VACIA;
						if (certDigest != null) {
							Node algorithm = certDigest.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD).item(0);				// Sacamos DigestAlgorithm
							Node value = certDigest.getElementsByTagNameNS(uriXmlNS, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE).item(0);					// Sacamos DigestValue

							alg = algorithm.getAttributes().getNamedItem(ConstantesXADES.ALGORITHM).getNodeValue(); 	// Guardamos el valor del algoritmo        			
							digest = value.getFirstChild().getNodeValue(); 								// Guardamos valor del digest

							// Se comprueba que el valor digest del nodo coincida con el digest de la uri
							try
							{
								MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(alg);
								if (haseador == null) {
									esValido = false;
									// No se puede calcular la huella del certificado para la validación
									resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
									// No se encontró el algoritmo para calcular el valor del digest del certificado
									LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_16));
									
									logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_16));
									
									return false;
								}
								byte[] resumenMensajeByte = haseador.digest(certFile.getEncoded());
								resumenCertificado = new String(Base64Coder.encode(resumenMensajeByte));
							} catch (CertificateEncodingException e) {
								// Error al obtener la codificación XXXX
								LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_23) + 
										ConstantesXADES.ESPACIO + e.getMessage(), e);				
								esValido = false;
								// No se puede calcular la huella del certificado para la validación
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52));
								
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR52) + "\n" +
										I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_23) + 
										ConstantesXADES.ESPACIO + e.getMessage());
								
								return false;
							}

							if (digest.equals(resumenCertificado)) {
								certificadosRef.add(certFile);
							} else {
								esValido = false;
								// No coincide el certificado obtenido con el almacenado
								resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR53));
								LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR53));
								
								logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR53));
								
								return false;
							}

						} else {
							// No se puede validar el fichero de certificado referenciado en CompleteCertificateRefs
							LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66));
							
							logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR66));
							
							// Firma inválida. No se pudo obtener el certificado firmante
							resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
							esValido = false;
							return false;
						}

					} else {
						// No se puede continuar la validación dado que hay CertificateRefs sin URI, ni certificateValues
						LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR83));				
						
						logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR83));
						
						esValido = false;
						// Firma inválida. No se pudo obtener el certificado firmante
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						return false;
					}
				}
			} 
		}

		// Con ambos resultados (certificadosKeyInfo y certificadosRef) se construye la cadena
		certificadosRef.addAll(certificadosKeyInfo);
		ArrayList<ArrayList<X509Certificate>> certChains = UtilidadCertificados.filterCertPathsArrays(UtilidadCertificados.getCertPathsArray(certificadosRef), UtilidadCertificados.Filter.SIGN_SIGNER);
		int certChainsSize = certChains.size();
		if (certChainsSize > 1) { // Hay varias cadenas, se busca la que contenga al certificado de firma
			boolean encontrado = false;
			// Se compara el primer certificado de cada cadena con el certificados de firma
			// El certificado de firma puede provenir de KeyInfo, o en su lugar, de SigningCertificate
			if (certificadosKeyInfo.size() != 0) { // Se busca por KeyInfo (solo se compara con el primero)
				for (int i = 0; i < certChainsSize; ++i) {
					ArrayList<X509Certificate> cadena = certChains.get(i);
					X509Certificate cert = cadena.get(0);
					if (cert.equals(certificadosKeyInfo.get(0))) {
						cadenaCertificados = cadena;
						datosFirma.setCadenaFirma(UtilidadCertificados.convertCertPath(cadenaCertificados));
						encontrado = true;
					}
				}
			} else if (certificadoFirma != null){ // Se busca por SigningCertificate (solo se recuperó el digest)
				MessageDigest haseador = null;
				haseador = UtilidadFirmaElectronica.getMessageDigest(certificadoFirma.getAlgMethod());
				for (int i = 0; i < certChainsSize && haseador != null; ++i) {
					ArrayList<X509Certificate> cadena = certChains.get(i);
					X509Certificate cert = cadena.get(0);
					// Calculamos el digest
					String digest = null; 
	    	        try {
	    	            byte[] resumenMensajeByte = haseador.digest(cert.getEncoded());
	    	            digest = new String(Base64Coder.encode(resumenMensajeByte));
	    	        } catch (CertificateEncodingException e) {
	    	        	LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_23), e);		
	    	        	
	    	        	logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_23) + " " + e.getMessage());
	    	        	
	    	        }    	        
					if ((certificadoFirma.getDigestValue()).equals(digest)) {
						cadenaCertificados = cadena;
						datosFirma.setCadenaFirma(UtilidadCertificados.convertCertPath(cadenaCertificados));
						encontrado = true;
					}
				}
			}		
			if (!encontrado) {
				// No se pueden validar dos o más cadenas de certificados
				esValido = false;
				resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR84));
				LOGGER.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR84));
				
				logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR84));
				
				return false;
			}
		} else if (certChainsSize == 0) {
			// No hay ni una cadena de certificación disponible en la firma
			esValido = false;
			resultado.setLog(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_10));
			LOGGER.error(i18n.getLocalMessage(ConstantsXAdES.I18N_VALIDATE_10));
			
			logv.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR84));
			
			return false;
		} else {
			cadenaCertificados = certChains.get(0);
			// Almacenamos la cadena construida  
			datosFirma.setCadenaFirma(UtilidadCertificados.convertCertPath(cadenaCertificados));  
		}

		return true;
	}
	
	/**
	 * Método para setear las constantes que varían según el esquema
	 */
	private void getConstantesEsquema(XAdESSchemas esquema) {
		if (esquema != null && ConstantesXADES.SCHEMA_XADES_111.equals(esquema.getSchemaUri())) {
			nombreNodoUri = ConstantesXADES.HASH_DATA_INFO;
			tipoUri = ConstantesXADES.URI_MINUS;
		} else {
			nombreNodoUri = ConstantesXADES.INCLUDE;
			tipoUri = ConstantesXADES.URI_MAYUS;
		}
	}
}