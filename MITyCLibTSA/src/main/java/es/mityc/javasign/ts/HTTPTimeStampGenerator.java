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
package es.mityc.javasign.ts;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.security.MessageDigest;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnection;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.util.EncodingUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.ssl.ISSLManager;
import es.mityc.javasign.tsa.ITimeStampGenerator;
import es.mityc.javasign.tsa.TimeStampException;
import es.mityc.javasign.utils.ProxyUtil;

/**
 * <p>Clase encargada de generar sellos de tiempo. Se corresponde con una
 * implementación de la interfaz ITimeStampGenerator mediante protocolo
 * HTTP(S) y de acuerdo con la RFC 3161</p>
 * 
 */
public class HTTPTimeStampGenerator implements ITimeStampGenerator {
    
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsTSA.LIB_NAME);
	/** Servidor que da el servicio de sellado de tiempo. */
	private String servidorTSA = null;
	/** Algoritmo hash del sello de tiempo. */
	private String algoritmoHash = null;
	/** Valor 5000 para timeouts. */
	private static final Integer INT10000 = new Integer(10000);
	
	private Integer timeOut = INT10000;
	/** Looger. */
	static Log log = LogFactory.getLog(HTTPTimeStampGenerator.class.getName());
    
    /**
     * <p>Crea una nueva instancia de TSCliente.</p>
     * @param nombreServidor Nombre del servidor
     * @param algoritmoHash Algoritmo del hash del Sello de Tiempo
     */
	public HTTPTimeStampGenerator(final String nombreServidor, final String algoritmoHash) {
		super();
		this.servidorTSA = nombreServidor;        

		// Algoritmo para digest aceptado por defecto
		this.algoritmoHash = TSPAlgoritmos.SHA1;

		// Comprueba que el algoritmo configurado en propiedades es aceptado. Si no lo es deja el algoritmo por defecto.
		// Los algoritmos aceptados se pueden ver en la clase TSPAlgorithms (excepto MD5)
		if (algoritmoHash != null) {
			String temp = algoritmoHash.trim().toUpperCase();
			if (TSPAlgoritmos.getPermitidos().contains(algoritmoHash)) {
				this.algoritmoHash = temp;
			} else {
				log.warn(ConstantsTSA.MENSAJE_NO_ALGORITMO_HASH);
			}
		}
	}
	
	/**
	 * <p>Establece un gestionador de las conexiones SSL para el cliente.</p>
	 * @param sslmanager Gestionador de las conexiones SSL
	 */
	public static void setSSLManager(ISSLManager sslmanager) {

	    OwnSSLProtocolSocketFactory ospsf = new OwnSSLProtocolSocketFactory(sslmanager);
		Protocol authhttps = new Protocol("https", ospsf, 443); 
		Protocol.registerProtocol("https", authhttps);
		try {
            HttpsURLConnection.setDefaultSSLSocketFactory( ospsf.getSSLContext().getSocketFactory());
        } catch (IOException e) {
            log.error("Error estableciendo socket factory: " + e.getMessage(), e);
        }
	}
    
    /**
     * <p>Este método genera el Sello de Tiempo.</p>
     * @param dataToSeal Datos a sellar
     * @return TimeStampToken en formato binario
     * @throws TSClienteError En caso de error
     */
    public byte[] generateTimeStamp(final byte[] dataToSeal) throws TimeStampException {
    	return generateTimeStamp(dataToSeal, null);
    }
    /**
     * <p>Este método genera el Sello de Tiempo.</p>
     * @param dataToSeal Datos a sellar
     * @param idApplication Identificador de aplicacion para @firma
     * @return TimeStampToken en formato binario
     * @throws TSClienteError En caso de error
     */
    public byte[] generateTimeStamp(final byte[] dataToSeal, String idApplication) throws TimeStampException {
        if (dataToSeal == null) {
        	log.error(ConstantsTSA.MENSAJE_NO_DATOS_SELLO_TIEMPO);
            throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_1));
        } else {
            log.info(ConstantsTSA.MENSAJE_GENERANDO_SELLO_TIEMPO);
        	/** Cliente Http para las comunicaciones. */    
        	HttpClient CLIENTE = new HttpClient();
            TimeStampRequestGenerator generadorPeticion = new TimeStampRequestGenerator();
            generadorPeticion.setCertReq(true);
            if(idApplication!=null && idApplication.length() > 0) {
            	generadorPeticion.addExtension(ConstantsTSA.AFIRMA_ID_APLICACION_OID, false, idApplication.getBytes());
            }
            TimeStampRequest peticion = null;
            TimeStampResponse respuesta = null;
            
            CLIENTE.getHttpConnectionManager().closeIdleConnections(100);
            
            try {
                MessageDigest resumen = MessageDigest.getInstance(algoritmoHash);
                resumen.update(dataToSeal);
                peticion = generadorPeticion.generate(TSPAlgoritmos.getOID(algoritmoHash), resumen.digest());
                log.info(ConstantsTSA.MENSAJE_PETICION_TSA_GENERADA);
            } catch (final Exception e) {
                log.error(ConstantsTSA.MENSAJE_ERROR_PETICION_TSA,e);
                throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_10, e.getMessage()));                
            }
            
            CLIENTE.getParams().setParameter(HttpClientParams.SO_TIMEOUT, timeOut);
            
            String servidorProxy = System.getProperty("http.proxyHost");
            if (servidorProxy != null) {
            	int puertoProxy = 80;
            	try {
            		puertoProxy = Integer.parseInt(System.getProperty("http.proxyPort"));
            	} catch (NumberFormatException ex) { }
            	CLIENTE.getHostConfiguration().setProxy(servidorProxy, puertoProxy);
            	
        		Credentials defaultcreds = new AuthenticatorProxyCredentials(servidorProxy, ConstantsTSA.CADENA_VACIA);
        		CLIENTE.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
            }

            PostMethod metodo = new PostMethod(servidorTSA);
            metodo.addRequestHeader(ConstantsTSA.CONTENT_TYPE, ConstantsTSA.APPLICATION_TIMESTAMP_QUERY);
            ByteArrayInputStream datos = null;
            try {
                datos = new ByteArrayInputStream(peticion.getEncoded());
            } catch (IOException e) {
                log.error(ConstantsTSA.MENSAJE_ERROR_PETICION + e.getMessage(),e);
                throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_11, e.getMessage()));
            }
            
            InputStreamRequestEntity rq = new InputStreamRequestEntity(datos);
            metodo.setRequestEntity(rq);
            
            metodo.getParams().setParameter(HttpMethodParams.RETRY_HANDLER,
                    new DefaultHttpMethodRetryHandler(3, false));
                       
            byte[] cuerpoRespuesta = null;
            try {
            	int estadoCodigo = 0;
                try {
                	estadoCodigo = CLIENTE.executeMethod(metodo);
                	log.info(ConstantsTSA.MENSAJE_PETICION_TSA_ENVIADA);
                } catch (IOException e) {
                	log.error(ConstantsTSA.MENSAJE_ERROR_CONEXION_SERVIDOR_TSA + e.getMessage());
                	estadoCodigo = HttpStatus.SC_REQUEST_TIMEOUT;
                }
                
                if (estadoCodigo != HttpStatus.SC_OK) {              	
                	log.info("Fallo en consulta TimeStamp: Reintentando vía HttpPOST");
                	HttpURLConnection conn = null;
                	BufferedReader brr = null;
                	try {        				
                		conn = ProxyUtil.getConnection(servidorTSA);

                		conn.setConnectTimeout(5000);
                		conn.setRequestMethod("POST");
                		conn.setRequestProperty("Content-Type", "application/timestamp-query");
            			conn.setRequestProperty("Accept", "application/timestamp-reply");
                		conn.setRequestProperty("Content-Length", String.valueOf(peticion.getEncoded().length));
                		conn.setUseCaches (false);
                		conn.setDoOutput(true);

                		DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
                		wr.write(peticion.getEncoded());
                		wr.flush ();
                		wr.close ();	

                		if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                			if (log.isDebugEnabled()) {
                				log.debug("Utilizando proxy: " + conn.usingProxy());
                			}
                			Object response = conn.getContent();
                			if (response != null) {
                				if (response instanceof InputStream) {
                					InputStream in = (InputStream) response;
                					if (in != null && in.available() > 0) {
                						int b = 0;
                						cuerpoRespuesta = new byte[in.available()];
                						for (int i = 0; (b >= 0) && i < cuerpoRespuesta.length; ++i) {
                							b = in.read();
                							cuerpoRespuesta[i] = (byte) b;
                						}
                					}
                				} else {
                    				throw new Exception("Tipo de respuesta inesperada: " + conn.getContentType());
                    			}
                				if (log.isDebugEnabled()) {
                					log.debug("Conexión satisfactoria vía HttpURLConnection");
                				}
                				log.info(ConstantsTSA.MENSAJE_RESPUESTA_TSA_OBTENIDA);
                			} else {
                				throw new Exception("No se obtubo respuesta o se obtuvo una respuesta inesperada: " + conn.getResponseCode());
                			}
                		} else {
                			throw new Exception("Respuesta de error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
                		}
                	} catch (Exception e1) {
                		if (log.isDebugEnabled()) {
                			log.debug("Conexión fallida vía HttpURLConnection", e1);
                		}
                		log.error(ConstantsTSA.MENSAJE_FALLO_EJECUCION_METODO + metodo.getStatusLine());
                		if (metodo.getStatusLine() != null) {
                			String m = metodo.getStatusLine().getReasonPhrase();
                			if (m.contains("��")) {
                				m = m.replaceAll("��", "ó");
                			}
                			throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_12,  EncodingUtil.getString(m.getBytes("UTF8"), "UTF8")));
                		} else {
                			throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_12,  metodo.getStatusCode()));
                		}
                	} finally {
                		if (conn != null) {
                			conn.disconnect();
                		}
                		if (brr != null) {
                			try { brr.close(); } catch (IOException e1) {
                				if (log.isDebugEnabled()) {
                					log.debug("No se pudo cerrar el canal de escritura", e1);
                				}
                			}
                		}
                	}
                } else {
                	cuerpoRespuesta = metodo.getResponseBody();
                	new String(cuerpoRespuesta);
                	log.info(ConstantsTSA.MENSAJE_RESPUESTA_TSA_OBTENIDA);
                }
                
                try {
                    respuesta = new TimeStampResponse(cuerpoRespuesta);
                    try {
                        
                    	// Se valida que la respuesta sea la petición enviada
                    	respuesta.validate(peticion);
                    	
                        log.info(ConstantsTSA.MENSAJE_RESPUESTA_TSA_VALIDADA_OK);
                        // Para solucionar bug en libreria bouncycastle
                        //return respuesta.getTimeStampToken().getEncoded();
                        //AppPerfect: Falso positivo
                        ASN1InputStream is = new ASN1InputStream(cuerpoRespuesta);
                        ASN1Sequence seq = ASN1Sequence.getInstance(is.readObject());
                        DEREncodable enc = null;
                        if (seq.size() > 1)
                        	enc = seq.getObjectAt(1);
                        if (enc == null) {
                        	return null;
                        }
                        return enc.getDERObject().getEncoded();
                        //Fin Para solucionar bug en libreria bouncycastle
                    } catch (TSPException e) {
                    	log.error(ConstantsTSA.MENSAJE_RESPUESTA_NO_VALIDA + e.getMessage(),e);
                        throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_9, e.getMessage()));
                    }
                } catch (TSPException e) { 
                    log.error(ConstantsTSA.MENSAJE_RESPUESTA_MAL_FORMADA + e.getMessage(),e);
                	throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_8, e.getMessage()));
                } catch (IOException e) {
                	log.error(ConstantsTSA.MENSAJE_SECUENCIA_BYTES_MAL_CODIFICADA + e.getMessage(),e);
                	throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_7, e.getMessage()));
                }               
            } 
            catch (HttpException e) {
                log.error(ConstantsTSA.MENSAJE_VIOLACION_PROTOCOLO_HTTP + e.getMessage(),e);
            	throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_6, e.getMessage()));
            } catch (IOException e) {
            	String mensajeError = I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_4, servidorTSA,e);
            	log.error(ConstantsTSA.MENSAJE_ERROR_CONEXION_SERVIDOR_TSA + e.getMessage());
            	 
            	throw new TimeStampException(mensajeError);
            } finally {
                // Termina la conexión
            	HostConfiguration hostConf = new HostConfiguration(); 
            	hostConf.setHost(servidorTSA);
            	HttpConnection conn = CLIENTE.getHttpConnectionManager().getConnection(hostConf);
            	if (conn != null) {
            		CLIENTE.getHttpConnectionManager().releaseConnection(conn);
            		conn.close();
            		conn.releaseConnection();
            	}
                metodo.releaseConnection();
            }
        }
    }  
    
    /**
     * <p>Establece el tiempo máximo de espera para solicitar un sello de tiempo.</p>
     * @param timeMilis Tiempo máximo de espera en milisegundos
     */
    public void setTimeOut(Integer timeMilis) {
    	if (timeMilis != null && timeMilis > 0) {
    		log.debug("Se establece el tiempo máximo de espera a " + timeMilis);
    		timeOut = timeMilis;
    	} else {
    		log.error("No se pudo establecer el valor de TimeOut a " + timeMilis + ". Se toma el valor por defecto.");
    		timeOut = INT10000;
    	}
    }
    
}

