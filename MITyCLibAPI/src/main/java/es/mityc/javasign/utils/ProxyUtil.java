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
package es.mityc.javasign.utils;

import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.StringTokenizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

/**
 * <p>Permite manejar datos para acceso a internet vía Proxy.</p>
 */
public class ProxyUtil {
	
	static Log log = LogFactory.getLog(ProxyUtil.class);
	
	/**
	 * <p>Realiza la conexión a la dirección indicada gestionando 
	 * la configuración de acceso a red del sistema.</p>
	 * @param URL La dirección a conectar
	 * @return La conexión ya creada
	 * @throws MalformedURLException
	 * @throws IOException
	 */
	public static HttpURLConnection getConnection(String URL) throws MalformedURLException, IOException {
		HttpURLConnection conn = null;
		if (System.getProperty("http.proxySet") != null 
				&& Boolean.parseBoolean(System.getProperty("http.proxySet"))
				&& !isInNonHosts(URL)) {
			if (log.isDebugEnabled()) {
				log.debug("Conexión a través de Proxy a " + URL);
			}
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(System.getProperty("http.proxyHost"), Integer.parseInt(System.getProperty("http.proxyPort"))));					
			conn = (HttpURLConnection) new URL(URL).openConnection(proxy);

			if (System.getProperty("http.proxyUser") != null && !"".equals(System.getProperty("http.proxyUser"))) {
				if (log.isDebugEnabled()) {
					log.debug("Proxy - Autenticando con " + System.getProperty("http.proxyUser"));
				}
				Authenticator.setDefault(new SimpleAuthenticator(System.getProperty("http.proxyUser"), System.getProperty("http.proxyPassword")));
				String encoded = new String(Base64.encode(new String(System.getProperty("http.proxyUser") + 
						":" + System.getProperty("http.proxyPassword")).getBytes()));
				conn.setRequestProperty("Proxy-Authorization", "NTLM " + encoded);
			}			
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Conexión directa a " + URL);
			}
			conn = (HttpURLConnection) new URL(URL).openConnection();
		}
		return conn;
	}
	
	/**
	 * <p> Comprueba si la URL esta dentro de System.getProperty("http.nonProxyHosts")</p>
	 * @param URL La dirección a comprobar
	 * @return <code>true</code> si el parámetro se encuentra en la lista
	 */
	public static boolean isInNonHosts(String URL) {
		try {
			String nonHostsList = System.getProperty("http.nonProxyHosts");
			if (nonHostsList != null && nonHostsList.trim().length() > 0) {
				StringTokenizer st = new StringTokenizer(nonHostsList, "|");
				while(st.hasMoreTokens()) {
					String host = st.nextToken();
					URL url = new URL(URL);
					
					try {
						// Se compara por la IP
						InetAddress inet = InetAddress.getByName(host);
						InetAddress inetDestino = InetAddress.getByName(url.getHost());
						String ip = inet.getHostAddress();
						String ipDestino = inetDestino.getHostAddress();
						for (int j = 0; j < ip.length(); ++j) {
							if (ipDestino.charAt(j) != ip.charAt(j)) {
								break;
							}
							if (j > 0 && host.charAt(j) == '.') {
								return true;
							}
						}
					} catch (Exception e) {
						log.debug("Error al comprobar la lista NonHosts por IP", e);
						break;
					}
					
					// Se comprueba el nombre de dominio
					int i = 0;
					int lenght = host.length();
					while((host.startsWith("*") || host.startsWith(".")) && i < lenght) {
						++i;
						host = host.substring(1);
					}
					if (url.getHost().contains(host)) {
						if (log.isDebugEnabled()) {
							log.debug("URL filtrada para el proxy");
						}
						return true;
					} 
				}
			}
		} catch (IOException e) {
			log.error("Error al comprobar la lista NonHosts", e);
			return false;
		}

		return false;
	}
}
