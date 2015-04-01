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
package es.mityc.firmaJava.ocsp;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

import es.mityc.crypto.Utils;
import es.mityc.firmaJava.ocsp.config.ConfigProveedores;
import es.mityc.firmaJava.ocsp.config.ServidorOcsp;
import es.mityc.firmaJava.ocsp.exception.OCSPClienteException;
import es.mityc.firmaJava.ocsp.exception.OCSPProxyException;
import es.mityc.javasign.certificate.ocsp.OwnSSLProtocolSocketFactory;
import es.mityc.javasign.ssl.ISSLManager;
import es.mityc.javasign.utils.Base64Coder;
import es.mityc.javasign.utils.ProxyUtil;
import es.mityc.javasign.utils.SimpleAuthenticator;

/**
 * @deprecated Usar la clase OCSPLiveConsultant en su lugar
 */
public class OCSPCliente {

	/** 5000 */
    private static final Integer INT_20000 = new Integer(20000);
    
    private Integer timeOut = INT_20000;
	
	private String 	servidorURL;

    static Log log = LogFactory.getLog(OCSPCliente.class);

    private PostMethod method = null;
    private HttpClient client = null;

    /**
     * Constructor de la clase OCSPCliente
     * @param servidorURL Servidor URL
     */
    public OCSPCliente(String servidorURL) {
        this.servidorURL = servidorURL;
    }


    /**
     * Este método valida el Certificado contra un servidor OCSP
     * @param certificadoUsuario Certificado
     * @param certificadoEmisor Certificado del emisor. En el caso de un certificado autofirmado el certificado del emisor será el mismo que el del usuario
     * @return respuestaOCSP tipo número de respuesta y mensaje correspondiente
     * @throws OCSPClienteException Errores del cliente OCSP
     */
    public RespuestaOCSP validateCert(X509Certificate certificadoUsuario, X509Certificate certificadoEmisor) throws OCSPClienteException, OCSPProxyException
    {
    	RespuestaOCSP respuesta = new RespuestaOCSP();
    	
    	// Añadimos el proveedor BouncyCastle
    	es.mityc.javasign.utils.Utils.addBCProvider();
        OCSPReqGenerator generadorPeticion = new OCSPReqGenerator();
        OCSPReq peticionOCSP = null;
        OCSPResp respuestaOCSP = null;
        CertificateID certificadoId = null;
                
        try {
            certificadoId = new CertificateID(CertificateID.HASH_SHA1, certificadoEmisor, certificadoUsuario.getSerialNumber());
            log.info(ConstantesOCSP.MENSAJE_CREADO_INDENTIFICADO);
        } catch (OCSPException e) {
            log.info( ConstantesOCSP.MENSAJE_ERROR_GENERAR_IDENTIFICADOR + e.getMessage());
            throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_2) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        generadorPeticion.addRequest(certificadoId);

        try {
            peticionOCSP = generadorPeticion.generate();
            log.info(ConstantesOCSP.MENSAJE_PETICION_OCSP_GENERADA);
        }
        catch (OCSPException e) {
            log.error( ConstantesOCSP.ERROR_MENSAJE_GENERAR_PETICION_OCSP + e.getMessage());
            throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_3) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        
        client = new HttpClient();
        
        // Comprueba si hay configurado un proxy 
        if (System.getProperty("http.proxySet") != null 
        		&& Boolean.parseBoolean(System.getProperty("http.proxySet")) &&
        		!ProxyUtil.isInNonHosts(servidorURL)) {
			if (System.getProperty("http.proxyUser") != null && !"".equals(System.getProperty("http.proxyUser"))) {
				Authenticator.setDefault(new SimpleAuthenticator(System.getProperty("http.proxyUser"), System.getProperty("http.proxyPassword")));
				
				String encoded = new String(System.getProperty("http.proxyUser") + 
						":" + System.getProperty("http.proxyPassword"));
				Credentials defaultcreds = new org.apache.commons.httpclient.UsernamePasswordCredentials(encoded);
	    		client.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
			} else {
	    		Authenticator.setDefault(null);
	    		
	    		Credentials defaultcreds = new AuthenticatorProxyCredentials(System.getProperty("http.proxyHost"), ConstantesOCSP.CADENA_VACIA);
	    		client.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
	    	}			
			client.getHostConfiguration().setProxy(System.getProperty("http.proxyHost"), Integer.parseInt(System.getProperty("http.proxyPort")));		
			
			String encoded = new String(System.getProperty("http.proxyUser") + 
					":" + System.getProperty("http.proxyPassword"));
			Credentials defaultcreds = new org.apache.commons.httpclient.UsernamePasswordCredentials(encoded);
    		client.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
		}
        
        client.getParams().setParameter(HttpClientParams.SO_TIMEOUT, timeOut);
        client.getParams().setParameter(HttpClientParams.RETRY_HANDLER,
        		new DefaultHttpMethodRetryHandler(0, false));
        
        if (((servidorURL == null) || ("".equals(servidorURL.trim())))
        		|| servidorURL.trim().equalsIgnoreCase(ConstantesOCSP.USAR_OCSP_MULTIPLE)) {

        	ServidorOcsp servidor = ConfigProveedores.getServidor(certificadoUsuario);

        	if (null != servidor) {
        		servidorURL = servidor.getUrl().toString();
        		log.debug(ConstantesOCSP.DEBUG_SERVIDOR_OCSP_ENCONTRADO + servidorURL);
        	} else {
        		log.error(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_12));
        		servidorURL = ConstantesOCSP.CADENA_VACIA;
        		throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_12));
        	}
        }

        method = new PostMethod(servidorURL);

        method.addRequestHeader(ConstantesOCSP.CONTENT_TYPE, ConstantesOCSP.APPLICATION_OCSP_REQUEST);
        ByteArrayInputStream datos = null;

        try {
        	datos = new ByteArrayInputStream(peticionOCSP.getEncoded());
        } catch (IOException e) {
        	log.error( ConstantesOCSP.MENSAJE_ERROR_LEER_PETICION + e.getMessage());
        	throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_4) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        InputStreamRequestEntity rq = new InputStreamRequestEntity (datos);
        method.setRequestEntity(rq);

        method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER,
        		new DefaultHttpMethodRetryHandler(0, false));
        method.getParams().setParameter(HttpMethodParams.SO_TIMEOUT, timeOut);

        MethodThread ocspThread =  new MethodThread();
        ocspThread.start();

        try {
        	try {
        		ocspThread.join(timeOut);
        	} catch (InterruptedException e) {
        		method.abort();
            	log.error( ConstantesOCSP.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + "Demanda de interrupción");
        		retryPost(0, peticionOCSP, ocspThread, datos.available());
        	}

        	int estadoCodigo = ocspThread.getResult();//cliente.executeMethod(metodo);
        	log.info(ConstantesOCSP.MENSAJE_PETICION_ENVIADA);           

        	if (estadoCodigo != HttpStatus.SC_OK) {
        		if (log.isDebugEnabled()) {
        			log.debug("Respuesta de error: " + estadoCodigo);
        		}
        		retryPost(estadoCodigo, peticionOCSP, ocspThread, datos.available());
            }

            byte[] cuerpoRespuesta = ocspThread.getResponse();//metodo.getResponseBody();
            if (cuerpoRespuesta == null) {
            	String mensajeError = I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_10) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + servidorURL;
            	log.error( ConstantesOCSP.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + "Respuesta vacía");
            	throw new OCSPClienteException(mensajeError);
            }
            log.info(ConstantesOCSP.MENSAJE_RESPUESTA_OBTENIDA);     

            try {
            	respuestaOCSP = new OCSPResp(cuerpoRespuesta);
            } catch (IOException e) {
            	log.error( ConstantesOCSP.MENSAJE_ERROR_SECUENCIA_BYTES_RESPUESTA + e.getMessage());
                throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_5) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
            }

            /*
              Estados de la respuesta OCSP
                successful            (0) La respuesta tiene una confirmación válida
                malformedRequest      (1) La petición no se realizó de forma correcta
                internalError         (2) Error interno
                tryLater              (3) Vuelva a intentarlo
                    -				  (4) no se utiliza
                sigRequired           (5) La petición debe estar firmada
                unauthorized          (6) No se ha podido autorizar la petición

            */
            
            processResponse(respuestaOCSP, respuesta, certificadoId);
        } catch (HttpException e) {
        	log.error( ConstantesOCSP.MENSAJE_VIOLACION_HTTP + e.getMessage());
        	throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_7) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
        } catch (IOException e)  {
        	String mensajeError = I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_10) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + servidorURL;
        	log.error( ConstantesOCSP.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + e.getMessage());
        	throw new OCSPClienteException(mensajeError);
        } finally {
            Security.removeProvider(ConstantesOCSP.BC);
            method.releaseConnection();
        }
        
        return respuesta ;
    }
    
    public static void processResponse(OCSPResp inResp, RespuestaOCSP outResp, CertificateID certID) throws OCSPClienteException, IOException {
    	outResp.setRespuesta(inResp);
        if (inResp.getStatus() != 0)
        {
        	log.info(ConstantesOCSP.MENSAJE_OCSP_NOT_SUCCESSFUL);
        	switch (inResp.getStatus())
        	{
	            case 1:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_MALFORMED_REQUEST);
	            			outResp.setNroRespuesta(ConstantesOCSP.MALFORMEDREQUEST);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_1));
	            			
	            			break;
	            case 2:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_INTERNAL_ERROR);
	            			outResp.setNroRespuesta(ConstantesOCSP.INTERNALERROR);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_2));
	            			break;
	            case 3:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_TRY_LATER);
	            			outResp.setNroRespuesta(ConstantesOCSP.TRYLATER);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_3));
	            			break;
	            case 5:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_SIG_REQUIRED);
	            			outResp.setNroRespuesta(ConstantesOCSP.SIGREQUIRED);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_4));
	            			break;
	            case 6:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_UNAUTHORIZED);
	            			outResp.setNroRespuesta(ConstantesOCSP.UNAUTHORIZED);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_5));
	            			break;
        	}
        }
        else
        {
            try
            {
            	log.info(ConstantesOCSP.MENSAJE_OCSP_SUCCESSFUL);
                BasicOCSPResp respuestaBasica = (BasicOCSPResp)inResp.getResponseObject();
				
                try {
                	X509Certificate certs[] = respuestaBasica.getCerts(ConstantesOCSP.SUN);
                	if ((certs != null) && (certs.length > 0)) {
                		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>(certs.length);
                		for (int i = 0; i < certs.length; i++)
                			list.add(certs[i]);
                		outResp.setOCSPSigner(list);
                	}
				} catch (NoSuchProviderException e) {
					log.info(e.getMessage(), e);
				} catch (OCSPException e) {
					log.info(e.getMessage(), e);
				}
                
                SingleResp[] arrayRespuestaBasica = respuestaBasica.getResponses();
                outResp.setTiempoRespuesta(respuestaBasica.getProducedAt());
                ResponderID respID = respuestaBasica.getResponderId().toASN1Object();
                outResp.setResponder(respID);
                StringBuffer mensaje = new StringBuffer(ConstantesOCSP.MENSAJE_RECIBIDO_ESTADO_NO_DEFINIDO);

                boolean finded = false;
                for (int i = 0; i<arrayRespuestaBasica.length;i++)
                {
                	// Comprueba si es la respuesta esperada
                	SingleResp sr = arrayRespuestaBasica[i];
                	if (!certID.equals(sr.getCertID()))
            			continue;
                	
                	finded = true;
                	Object certStatus = arrayRespuestaBasica[i].getCertStatus();
                	if (certStatus == null)
                    {
                    	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_GOOD);
                    	outResp.setNroRespuesta(ConstantesOCSP.GOOD);
                    	outResp.setMensajeRespuesta(new String(Base64Coder.encode(inResp.getEncoded())));
                    }
                	else if (certStatus instanceof RevokedStatus)
                    {
                    	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_REVOKED);
                    	outResp.setFechaRevocacion(((RevokedStatus)certStatus).getRevocationTime());
                    	outResp.setNroRespuesta(ConstantesOCSP.REVOKED);

                        /*
                        Razones de revocación
                        	unused 					(0) Sin uso
                        	keyCompromise 			(1) Se sospecha que la clave del certificado ha quedado comprometida
                        	cACompromise			(2) Se sospecha que la clave que firmó el certificado ha quedado comprometida
                        	affiliationChanged		(3) Se han cambiado los datos particulares del certificado
                        	superseded	      		(4) El certificado ha sido reemplazado por otro
                        	cessationOfOperation	(5) El certificado ha dejado de operar
                        	certificateHold 		(6) El certificado momentáneamente ha dejado de operar
						*/

                        RevokedStatus revoked = (RevokedStatus)certStatus;
                        if (revoked.hasRevocationReason())
                        {
	                        switch (revoked.getRevocationReason())
	                        {
	                        
	                        	case 1:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_1));
                        			break;
	                        	case 2:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_2));
                    				break;
	                        	case 3:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_3));
                    				break;
	                        	case 4:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_4));
                    				break;
	                        	case 5:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_5));
                    				break;
	                        	case 6:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_6));
                    				break;
	                        	default:
	                        		outResp.setMensajeRespuesta(ConstantesOCSP.CADENA_VACIA);
	                        }
                        }
                        else
                        	outResp.setMensajeRespuesta(ConstantesOCSP.CADENA_VACIA);
                    }
                    else if (certStatus instanceof UnknownStatus)
                    {
                    	
                    	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_UNKNOWN);
                    	outResp.setNroRespuesta(ConstantesOCSP.UNKNOWN) ;
                    	outResp.setMensajeRespuesta(ConstantesOCSP.MENSAJE_RESPUESTA_SERVIDOR_ESTADO_DESCONOCIDO);
                    }
                    else
                    {
                    	mensaje.append(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
                    	log.info( mensaje.toString());
                    	outResp.setNroRespuesta(ConstantesOCSP.ERROR) ;
                    	outResp.setMensajeRespuesta(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
                    }
                }
                
                if (!finded) {
                	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_UNKNOWN);
                	outResp.setNroRespuesta(ConstantesOCSP.UNKNOWN) ;
                	outResp.setMensajeRespuesta(ConstantesOCSP.MENSAJE_RESPUESTA_SERVIDOR_ESTADO_DESCONOCIDO);
                }
            }
            catch (OCSPException e)
            {
            	log.error( ConstantesOCSP.MENSAJE_ERROR_RESPUESTA_OCPS_BASICA + e.getMessage());
            	throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_6) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
            }
        }
    }
    
	/**
	 * <p>Establece un gestionador de las conexiones SSL para el cliente.</p>
	 * @param sslmanager Gestionador de las conexiones SSL
	 */
	public static void setSSLManager(ISSLManager sslmanager) {
		Protocol authhttps = new Protocol("https", (ProtocolSocketFactory) new OwnSSLProtocolSocketFactory(sslmanager), 443); 
		Protocol.registerProtocol("https", authhttps);
	}
	
	/**
     * <p>Establece el tiempo máximo de espera para solicitar una respuesta OCSP.</p>
     * @param timeMilis Tiempo máximo de espera en milisegundos
     */
    public void setTimeOut(Integer timeMilis) {
    	if (timeMilis != null && timeMilis > 0) {
    		log.debug("Se establece el tiempo máximo de espera a " + timeMilis);
    		timeOut = timeMilis;
    	} else {
    		log.error("No se pudo establecer el valor de TimeOut a " + timeMilis + ". Se toma el valor por defecto.");
    		timeOut = INT_20000;
    	}
    }
    
    public synchronized void abort() {
    	if (method != null)
    		method.abort();
    }
    
    class MethodThread extends Thread {
    	private int result = 0;
    	private byte[] response = null;

    	public MethodThread() {	}

    	public void run() {
    		try {
    			result = client.executeMethod(method);
    			response = method.getResponseBody();
    		} catch(Exception e) {
    			log.error(e);
    		} finally {
    			method.releaseConnection();
    		}
    	}

		public int getResult() {
			return result;
		}
		public byte[] getResponse() {
			return response;
		}
		public void setResponse(byte[] res) {
			response = res;
		}
    }
    
    private void retryPost(int estadoCodigo, OCSPReq peticionOCSP, MethodThread ocspThread, int dataLenght) throws OCSPClienteException, OCSPProxyException {
    	if (method == null || method.isAborted()) {
    		log.debug("Cancelado por el usuario");
    		return;
    	}
    	log.info("OCSP Satus: Reintentando vía HttpPOST");
		HttpURLConnection conn = null;
		InputStream in = null;
		try {
			conn = ProxyUtil.getConnection(servidorURL);
			conn.setConnectTimeout(7000);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Content-Type", "application/ocsp-request");
			conn.setRequestProperty("Accept", "application/ocsp-response");
			conn.setRequestProperty("Content-Length", String.valueOf(dataLenght));
			conn.setUseCaches (false);
			conn.setDoOutput(true);        			

			DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
			wr.write(peticionOCSP.getEncoded());
			wr.flush ();
			wr.close ();	

			if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
				if (log.isDebugEnabled()) {
					log.debug("Utilizando proxy: " + conn.usingProxy());
				}
				
				in = (InputStream) conn.getContent();
				OCSPResp ocspResponse = new OCSPResp(in); 
				int status = ocspResponse.getStatus();
				
				if (ocspResponse != null && ocspResponse.getEncoded().length > 0) {
					if (log.isDebugEnabled()) {
						log.debug("Conexión satisfactoria vía HttpURLConnection");
					}
					estadoCodigo = HttpURLConnection.HTTP_OK;
					ocspThread.setResponse(ocspResponse.getEncoded());
				} else {
					if (log.isDebugEnabled()) {
						log.debug("Se obtuvo una respuesta inesperada: " + status);
					}
					throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_9) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + method.getStatusLine());
				}
			} else {
				if (log.isDebugEnabled()) {
					log.debug("Se obtuvo una respuesta de error:" + conn.getResponseCode() + " - " + conn.getResponseMessage());
				}
			}
		} catch (Exception e1) {
			if (log.isDebugEnabled()) {
				log.debug("Conexión fallida vía HttpURLConnection", e1);
			}
			throw new OCSPProxyException(e1);
		} finally {
			if (conn != null) {
				conn.disconnect();
			}
			if (in != null) {
				try { in.close(); } catch (IOException e1) {
					if (log.isDebugEnabled()) {
						log.debug("No se pudo cerrar el canal de escritura", e1);
					}
				}
			}
		}          	

    	if (estadoCodigo == HttpStatus.SC_PROXY_AUTHENTICATION_REQUIRED)
        	throw new OCSPProxyException(ConstantesOCSP.MENSAJE_PROXY_AUTENTICADO);
        else if (estadoCodigo == HttpStatus.SC_USE_PROXY)
        	throw new OCSPProxyException(ConstantesOCSP.MENSAJE_PROXY_POR_CONFIGURAR);
        else if (estadoCodigo != HttpURLConnection.HTTP_OK) {
        	log.error( ConstantesOCSP.MENSAJE_FALLO_EJECUCION_METODO + method.getStatusLine());
        	throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_9) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + method.getStatusLine());
        }
    }
}
