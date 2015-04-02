/*
* ====================================================================
*
*  Licensed to the Apache Software Foundation (ASF) under one or more
*  contributor license agreements.  See the NOTICE file distributed with
*  this work for additional information regarding copyright ownership.
*  The ASF licenses this file to You under the Apache License, Version 2.0
*  (the "License"); you may not use this file except in compliance with
*  the License.  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
* ====================================================================
*
* This software consists of voluntary contributions made by many
* individuals on behalf of the Apache Software Foundation.  For more
* information on the Apache Software Foundation, please see
* <http://www.apache.org/>.
*
* [Additional notices, if required by prior licensing conditions]
*
* Alternatively, the contents of this file may be used under the
* terms of the GNU Lesser General Public License Version 2 or later
* (the "LGPL"), in which case the provisions of the LGPL are 
* applicable instead of those above.  See terms of LGPL at
* <http://www.gnu.org/copyleft/lesser.txt>.
* If you wish to allow use of your version of this file only under 
* the terms of the LGPL and not to allow others to use your version
* of this file under the Apache Software License, indicate your 
* decision by deleting the provisions above and replace them with 
* the notice and other provisions required by the LGPL.  If you do 
* not delete the provisions above, a recipient may use your version 
* of this file under either the Apache Software License or the LGPL.
*/
package es.mityc.javasign.ts;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Vector;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.X509Certificate;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.X509Name;

import es.mityc.javasign.ssl.ISSLErrorManager;
import es.mityc.javasign.ssl.ISSLManager;

/**
 * A <code>SecureProtocolSocketFactory</code> that uses JSSE to create
 * SSL sockets.  It will also support host name verification to help preventing
 * man-in-the-middle attacks.  Host name verification is turned <b>on</b> by
 * default but one will be able to turn it off, which might be a useful feature
 * during development.  Host name verification will make sure the SSL sessions
 * server host name matches with the the host name returned in the 
 * server certificates "Common Name" field of the "SubjectDN" entry.
 *
 * @author <a href="mailto:hauer@psicode.com">Sebastian Hauer</a>
 * <p>
 * DISCLAIMER: HttpClient developers DO NOT actively support this component.
 * The component is provided as a reference material, which may be inappropriate
 * for use without additional customization.
 * </p>
 * <p>This class has been adapted to works in MITyCLibTSA.</p>
 */
public class OwnSSLProtocolSocketFactory implements SecureProtocolSocketFactory {

    /** Log object for this class. */
    private static final Log LOG = LogFactory.getLog(OwnSSLProtocolSocketFactory.class);
    
    /** Timeout for SSL connection. */
    private static final int SSL_TIME_OUT = 30;

    private ISSLManager sslManager = null;
    private SSLContext sslcontext = null;


    /**
     * Constructor for OwnSSLProtocolSocketFactory.
     * @param ssl Gestionador de la autenticación y confianza de la comunicación SSL
     * 
     * Code sample:
     *  
     *     <blockquote>
     *     Protocol stricthttps = new Protocol( 
     *         "https", new OwnSSLProtocolSocketFactory(true), 443);
     *
     *     HttpClient client = new HttpClient();
     *     client.getHostConfiguration().setHost("localhost", 443, stricthttps);
     *     </blockquote>
     *
     */
    public OwnSSLProtocolSocketFactory(ISSLManager ssl) {
        super();
        this.sslManager = ssl;
    }

    /**
     * Constructor for OwnSSLProtocolSocketFactory.
     */
    public OwnSSLProtocolSocketFactory() {
        super();
    }

    private SSLContext createSSLContext() throws IOException {
        try {
            KeyManager[] keymanagers = null;
            TrustManager[] trustmanagers = null;
            if (sslManager != null) {
            	KeyManager km = sslManager.getKeyManager();
            	if (km != null) {
            		keymanagers = new KeyManager[] { km };
            	}
            	TrustManager tm = sslManager.getTrustManager();
            	if (tm != null) {
            		trustmanagers = new TrustManager[] { tm };
            	}
            }
            SSLContext sslcontext = SSLContext.getInstance("SSL");
            sslcontext.init(keymanagers, trustmanagers, null);
            sslcontext.getClientSessionContext().setSessionTimeout(SSL_TIME_OUT);
            return sslcontext;
        } catch (NoSuchAlgorithmException ex) {
        	LOG.error(ex.getMessage(), ex);
        	throw new IOException(ex.getMessage());
        } catch (KeyManagementException ex) {
        	LOG.error(ex.getMessage(), ex); 
        	throw new IOException(ex.getMessage());
		}
    }
    
    public SSLContext getSSLContext() throws IOException {
        if (this.sslcontext == null) {
            this.sslcontext = createSSLContext();
        }
        return this.sslcontext;
    }

    
    /**
     * Attempts to get a new socket connection to the given host within the given time limit.
     * <p>
     * To circumvent the limitations of older JREs that do not support connect timeout a 
     * controller thread is executed. The controller thread attempts to create a new socket 
     * within the given limit of time. If socket constructor does not return until the 
     * timeout expires, the controller terminates and throws an {@link ConnectTimeoutException}
     * </p>
     *  
     * @param host the host name/IP
     * @param port the port on the host
     * @param localAddress the local host name/IP to bind the socket to
     * @param localPort the port on the local machine
     * @param params {@link HttpConnectionParams Http connection parameters}
     * 
     * @return Socket a new socket
     * 
     * @throws IOException if an I/O error occurs while creating the socket
     * @throws UnknownHostException if the IP address of the host cannot be
     * determined
     */
    public Socket createSocket(
        final String host,
        final int port,
        final InetAddress localAddress,
        final int localPort,
        final HttpConnectionParams params
    ) throws IOException, UnknownHostException, ConnectTimeoutException {
        if (params == null) {
            throw new IllegalArgumentException("Parameters may not be null");
        }
        int timeout = params.getConnectionTimeout();
        Socket socket = null;

        SocketFactory socketfactory = getSSLContext().getSocketFactory();
        if (timeout == 0) {
        	socket = socketfactory.createSocket(host, port, localAddress, localPort);
        } else {
            socket = socketfactory.createSocket();
            SocketAddress localaddr = new InetSocketAddress(localAddress, localPort);
            SocketAddress remoteaddr = new InetSocketAddress(host, port);
            socket.bind(localaddr);
            socket.connect(remoteaddr, timeout);
        }
        verifyHostname((SSLSocket)socket);
        return socket;
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int,java.net.InetAddress,int)
     */
    public Socket createSocket(
        String host,
        int port,
        InetAddress clientHost,
        int clientPort)
        throws IOException, UnknownHostException
   {
        SSLSocketFactory sf = getSSLContext().getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sf.createSocket(host, port, 
                                                          clientHost, 
                                                          clientPort);
        verifyHostname(sslSocket);

        return sslSocket;
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int)
     */
    public Socket createSocket(String host, int port)
        throws IOException, UnknownHostException
    {
        SSLSocketFactory sf = getSSLContext().getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sf.createSocket(host, port);
        verifyHostname(sslSocket);

        return sslSocket;
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.net.Socket,java.lang.String,int,boolean)
     */
    public Socket createSocket(
        Socket socket,
        String host,
        int port,
        boolean autoClose)
        throws IOException, UnknownHostException
    {
        SSLSocketFactory sf = getSSLContext().getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sf.createSocket(socket, host, 
                                                          port, autoClose);
        verifyHostname(sslSocket);

        return sslSocket;
    }
    
    /**
     * Describe <code>verifyHostname</code> method here.
     *
     * @param socket a <code>SSLSocket</code> value
     * @exception SSLPeerUnverifiedException  If there are problems obtaining
     * the server certificates from the SSL session, or the server host name 
     * does not match with the "Common Name" in the server certificates 
     * SubjectDN.
     * @exception UnknownHostException  If we are not able to resolve
     * the SSL sessions returned server host name. 
     */
    private void verifyHostname(SSLSocket socket) 
        throws SSLPeerUnverifiedException, UnknownHostException {
    	if (sslManager == null) {
    		return;
    	}
    	ISSLErrorManager errorMng = sslManager.getSSLErrorManager();
    	if (errorMng == null) {
    		return;
    	}

        SSLSession session = socket.getSession();
        String hostname = session.getPeerHost();
        try {
            InetAddress.getByName(hostname);
        } catch (UnknownHostException uhe) {
            throw new UnknownHostException("Could not resolve SSL sessions "
                                           + "server hostname: " + hostname);
        }
        
        X509Certificate[] certs = session.getPeerCertificateChain();
        if (certs == null || certs.length == 0) 
            throw new SSLPeerUnverifiedException("No server certificates found!");
        
        //get the servers DN in its string representation
        String dn = certs[0].getSubjectDN().getName();

        //might be useful to print out all certificates we receive from the
        //server, in case one has to debug a problem with the installed certs.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Server certificate chain:");
            for (int i = 0; i < certs.length; i++) {
                LOG.debug("X509Certificate[" + i + "]=" + certs[i]);
            }
        }
        //get the common name from the first cert
        String cn = getCN(dn);
        if (hostname.equalsIgnoreCase(cn)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Target hostname valid: " + cn);
            }
        } else {
			try {
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        	java.security.cert.X509Certificate servCert = (java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certs[0].getEncoded()));
	        	if (!errorMng.continueErrorPeer(hostname, servCert)) {
	                throw new SSLPeerUnverifiedException(
	                        "HTTPS hostname invalid: expected '" + hostname + "', received '" + cn + "'");
	        	}
			} catch (CertificateException ex) {
				LOG.error(ex.getMessage(), ex);
                throw new SSLPeerUnverifiedException("Unexpected error checking HTTPS hostname: " + ex.getMessage());
			} catch (CertificateEncodingException ex) {
				LOG.error(ex.getMessage(), ex);
                throw new SSLPeerUnverifiedException("Unexpected error checking HTTPS hostname: " + ex.getMessage());
			}
        }
    }


    /**
     * Parses a X.500 distinguished name for the value of the 
     * "Common Name" field.
     * This is done a bit sloppy right now and should probably be done a bit
     * more according to <code>RFC 2253</code>.
     *
     * @param dn  a X.500 distinguished name.
     * @return the value of the "Common Name" field.
     */
    private String getCN(String dn) {
        X509Name name = new X509Name(dn);
        Vector<?> vector = name.getValues(X509Name.CN);
        if ((vector != null) && (vector.size() > 0)) {
        	return (String) vector.get(0);
        } else {
        	return null;
        }
    }
    
    public boolean equals(Object obj) {
        if ((obj != null) && obj.getClass().equals(OwnSSLProtocolSocketFactory.class)) {
            return true;
        } else {
            return false;
        }
    }

    public int hashCode() {
        return OwnSSLProtocolSocketFactory.class.hashCode();
    }
}
