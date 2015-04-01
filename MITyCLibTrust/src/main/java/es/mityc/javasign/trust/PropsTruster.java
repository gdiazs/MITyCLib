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
package es.mityc.javasign.trust;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Manager de confianza para objetos de tipo cadenas de certificados, CRLs, respuestas OCSP y sellos de tiempo con configuración por fichero de propiedades.</p>
 * <p>Este manager se configura mediante un fichero de propiedades con el formato: 
 * <pre>
 * # Indica los certificados de prestadores admitidos separados por comas
 * signcerts.issuers.&lt;id&gt;=
 * # Indica los certificados admitidos separados por comas
 * signcerts.certs.&lt;id&gt;=
 * # Indica los certificados de prestadores de entidades emisoras de CRLs admitidas separados por comas
 * crl.issuers.&lt;id&gt;=
 * # Indica los certificados de prestadores de entidades emisoras de respuestas OCSP admitidas separados por comas
 * ocsp.issuers.&lt;id&gt;=
 * # Indica los certificados de emisores de respuestas OCSP admitidos separados por comas
 * ocsp.certs.&lt;id&gt;=
 * # Indica los certificados de prestadores de entidades emisoras de sellos de tiempo admitidas separadas por comas
 * tsa.issuers.&lt;id&gt;=
 * # Indica los certificados de emisores de sellos de tiempo admitidos separados por comas
 * tsa.certs.&lt;id&gt;=
 * </pre>
 * Los recursos indicados en el fichero de propiedades se buscarán como recursos mediante el ClassLoader de contexto disponible. Se cargarán todas las líneas
 * de configuración con el mismo prefijo indistintamente de su id (v.g.: aunque se separe por lógica dos líneas <code>signcerts.issuers.id1</code> y 
 * <code>signcerts.issuers.id2</code> el manager leerá los certificados indicados en ambas líneas como válidos para entidades emisoras de certificados de firma).
 * </p>
 */
public class PropsTruster extends TrustAdapter {

	/** Logger. */
	private static final Log LOG = LogFactory.getLog(PropsTruster.class);
	/** Internacionalizador. */
    private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsTrust.LIB_NAME);

    /** Fichero de recursos por defecto. */
    private static final String CONF_DEFAULT = "trust/myTruster.properties";

	/**
	 * <p>Enumeración con los tipos de managers de confianza que se gestionan internamente.</p>
	 * <p>Estos managers son:
	 * 	<ul>
	 * 		<li>Issuers de certificados de firma</li>
	 * 		<li>Certificados de firma</li>
	 * 		<li>Issuers de certificados de OCSP Responder</li>
	 * 		<li>Certificados de OCSP Responder</li>
	 * 		<li>Certificados de emisores de CRLs</li>
	 * 		<li>Issuers de certificados de TSAs</li>
	 * 		<li>Certificados de TSAs</li>
	 * 	</ul>
	 * </p>
	 */
    public enum TrusterType {
    	/** Issuers de certificados de firma. */
		TRUSTER_SIGNCERTS_ISSUER("signcerts.issuers"),
		/** Certificados de firma. */
		TRUSTER_SIGNCERTS_CERTS("signcerts.certs"),
		/** Issuers de certificados de OCSP Responder. */
		TRUSTER_OCSP_ISSUER("ocsp.issuers"),
		/** Certificados de OCSP Responder. */
		TRUSTER_OCSP_CERTS("ocsp.certs"),
		/** Certificados de emisores de CRLs. */
		TRUSTER_CRL_ISSUER("crl.issuers"),
		/** Issuers de certificados de TSAs. */
		TRUSTER_TSA_ISSUER("tsa.issuers"),
		/** Certificados de TSAs. */
		TRUSTER_TSA_CERTS("tsa.certs");
		
		/** Clave de la propiedad asociada a este tipo de manager. */
		private String id;
		
		/**
		 * <p>Constructor.</p>
		 * @param key Nombre de propiedad asociada a este tupo de manager
		 */
		private TrusterType(final String key)  {
			this.id = key;
		}
		
		/**
		 * <p>Devuelve la clave asociada a este tipo de manager.</p>
		 * @return Clave de configuración de este tipo de manager
		 * @see java.lang.Enum#toString()
		 */
		@Override
		public String toString() {
			return id;
		}
	}
    
    protected Properties externalProps = new Properties();
    
	/** Instancia única del tipo de manager interno de confianza. */
    protected static TrustAdapter instance;
	
	/** Certificados de emisores de certificados de firma admitidos. */
    private CertStore issuersCerts;
    /** Certificados de firma admitidos. */
	private CertStore certsCerts;
	/** Certificados de emisores de certificados de OCSP Responder admitidos. */
	private CertStore issuersOCSP;
	/** Certificados de OCSP Responder admitidos. */
	private CertStore certsOCSP;
	/** Certificados de emisores de CRLs admitidos. */
	private CertStore issuersCRL;
	/** Certificados de emisores de certificados de TSA admitidos. */
	private CertStore issuersTSA;
	/** Certificados de TSA admitidos. */
	private CertStore certsTSA;
	
    /**
     * <p>Constructor.</p>
     * @param fileconf Nombre del fichero de propiedades que contiene la configuración
     */
    protected PropsTruster(final String fileconf) {
        loadConf(fileconf, new Properties());
    }
    
	/**
	 * <p>Constructor.</p>
     * @param fileconf Nombre del fichero de propiedades que contiene la configuración
     * @param extfileconf Nombre del fichero externo que contiene otra parte de configuración
	 */
	protected PropsTruster(final String fileconf, final InputStream extFileConf) {
		loadConf(fileconf, extFileConf);
	}
	
	protected synchronized void loadConf(final String fileconf, final InputStream extConf) {
		Properties extProps = null;
		// Se parsea la configuración con los certificados externos
		if (extConf != null) {
			try {
				extProps = new Properties();
				extProps.load(extConf);

			} catch (IOException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_1, extConf));
				if (LOG.isDebugEnabled())
					LOG.debug(ex);
			}
		} else {
			LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_1, extConf));
		}
		loadConf(fileconf, extProps);
	}
	
	protected synchronized void loadConf(final String fileconf, final Properties extProperties) {
		// se toman las propiedades externas parametrizadas
		externalProps = extProperties;
		// Se obtienen los certificados internos
		Properties internalProps = null;
		try {
			ClassLoader cl = getClassLoader();
			InputStream is = cl.getResourceAsStream(fileconf);
			if (is != null) {
				internalProps = new Properties();
				internalProps.load(is);
			} else {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_1, fileconf));
			}
		} catch (IOException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_1, fileconf));
		}

		if (internalProps != null) {
			try {
				CertificateFactory cf = CertificateFactory.getInstance("X509");
				issuersCerts = loadCerts(cf, internalProps, externalProps, TrusterType.TRUSTER_SIGNCERTS_ISSUER);
				certsCerts = loadCerts(cf, internalProps, externalProps, TrusterType.TRUSTER_SIGNCERTS_CERTS);
				issuersOCSP = loadCerts(cf, internalProps, externalProps, TrusterType.TRUSTER_OCSP_ISSUER);
				certsOCSP = loadCerts(cf, internalProps, externalProps, TrusterType.TRUSTER_OCSP_CERTS);
				issuersCRL = loadCerts(cf, internalProps, externalProps, TrusterType.TRUSTER_CRL_ISSUER);
				issuersTSA = loadCerts(cf, internalProps, externalProps, TrusterType.TRUSTER_TSA_ISSUER);
				certsTSA = loadCerts(cf, internalProps, externalProps, TrusterType.TRUSTER_TSA_CERTS);
			} catch (CertificateException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_9, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
			}
		}
	}
	
	/**
	 * <p>Comprueba que la CRL indicada ha sido emitida por algunos de los certificados permitidos.</p>
	 * @param crl Lista de certificados revocados
	 * @throws TrustException lanzada cuando el objeto no es de confianza o ha ocurrido algún error al intentar comprobarlo:
	 * <ul>
	 * 	<li>{@link UnknownTrustException} lanzada cuando se desconoce si el objeto es o no de confianza (el objeto es desconocido o no
	 * 		se puede comprobar su confianza).</li>
	 * 	<li>{@link NotTrustedException} lanzada cuando el objeto no es de confianza.</li>
	 * 	<li>{@link FakedTrustException} lanzada cuando se detecta que el objeto ha sido manipulado.</li>
	 * </ul>
	 * @see es.mityc.javasign.trust.ITrustCRLEmisor#isTrusted(java.security.cert.X509CRL)
	 */
	public void isTrusted(final X509CRL crl) throws TrustException {
		if (issuersCRL != null) {
			boolean faked = false;
			X509CertSelector certSelector = new X509CertSelector();
			certSelector.setSubject(crl.getIssuerX500Principal());
			Iterator< ? extends Certificate> it;
			try {
				it = issuersCRL.getCertificates(certSelector).iterator();
			} catch (CertStoreException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_21, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			}
			while (it.hasNext()) {
				X509Certificate issuer = (X509Certificate) it.next();
				try {
					crl.verify(issuer.getPublicKey());
					return;
				} catch (InvalidKeyException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_2, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (CRLException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_3, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (NoSuchAlgorithmException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_4, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (NoSuchProviderException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_5, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (SignatureException ex) {
					faked = true;
				}
			}
			if (faked) {
				throw new FakedTrustException();
			} else {
				throw new NotTrustedException();
			}
		}
		else {
			throw new UnknownTrustException();
		}
	}

	/**
	 * <p>Comprueba si la respuesta OCSP indicada ha sido emitida por una entidad de confianza.</p>
	 *  
	 * @param ocsp Respuesta OCSP
	 * @throws TrustException lanzada cuando el objeto no es de confianza o ha ocurrido algún error al intentar comprobarlo:
	 * <ul>
	 * 	<li>{@link UnknownTrustException} lanzada cuando se desconoce si el objeto es o no de confianza (el objeto es desconocido o no
	 * 		se puede comprobar su confianza).</li>
	 * 	<li>{@link NotTrustedException} lanzada cuando el objeto no es de confianza.</li>
	 * 	<li>{@link FakedTrustException} lanzada cuando se detecta que el objeto ha sido manipulado.</li>
	 * </ul>
	 * @see es.mityc.javasign.trust.ITrustOCSPProducer#isTrusted(org.bouncycastle.ocsp.OCSPResp)
	 */
	public void isTrusted(final OCSPResp ocsp) throws TrustException {
		BasicOCSPResp basicResp = null;
		try {
			basicResp = (BasicOCSPResp) ocsp.getResponseObject();
		} catch (OCSPException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_11, ex.getMessage()));
			if (LOG.isDebugEnabled()) {
				LOG.debug("", ex);
			}
			throw new UnknownTrustException();
		}
		if (certsOCSP != null) {
			X509CertSelector certSelector = null;
			// Prepara el selector de certificados de firma
			// Si hay disponible certificados de firma en la respuesta, se queda con los certificados de firm
			X509Certificate[] certs;
			try {
				certs = basicResp.getCerts("SUN");
			} catch (NoSuchProviderException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_12, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} catch (OCSPException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_12, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			}
			if ((certs != null) && (certs.length > 0)) {
				certSelector = new X509CertSelector();
				certSelector.setSubjectPublicKey(certs[0].getPublicKey());
			}
			// Si no hay certificados de firma entonces construye el selector con el identificador de ResponderID de
			// la respuesta OCSP: bien por nombre bien por clave pública
			else {
				ResponderID responderId = basicResp.getResponderId().toASN1Object();
				if (responderId != null) {
					ASN1TaggedObject tagged = (ASN1TaggedObject) responderId.toASN1Object();
					switch (tagged.getTagNo()) {
						case 1: // DN del responder
							X509Principal cerX509Principal = new X509Principal(X509Name.getInstance(tagged.getObject()).toString());
							X500Principal cerX500Principal = new X500Principal(cerX509Principal.getDEREncoded());
							certSelector = new X509CertSelector();
							certSelector.setSubject(cerX500Principal);
							break;
						case 2: // PK Hash del responder
							ASN1OctetString octect = (ASN1OctetString) tagged.getObject();
							certSelector = new X509CertSelector();
							try {
								certSelector.setSubjectPublicKey(octect.getOctets());
							} catch (IOException ex) {
								LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_13, ex.getMessage()));
								if (LOG.isDebugEnabled()) {
									LOG.debug("", ex);
								}
								throw new UnknownTrustException();
							}
							break;
						default:
							throw new UnknownTrustException();
					}
				}
			}
			if (certSelector != null) {
				Iterator< ? extends Certificate> it;
				try {
					it = certsOCSP.getCertificates(certSelector).iterator();
				} catch (CertStoreException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_22, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				}
				while (it.hasNext()) {
					X509Certificate cert = (X509Certificate) it.next();
			        try {
						// TODO: corregir el provider en función del tipo de firma de la respuesta
						if (basicResp.verify(cert.getPublicKey(), "SunRsaSign")) { // Y si no es firma RSA?
							return;
						} else {
							throw new FakedTrustException();
						}
					} catch (OCSPException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_15, ex.getMessage()));
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
						throw new UnknownTrustException();
					} catch (NoSuchProviderException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_14, ex.getMessage()));
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
						throw new UnknownTrustException();
					} 
				}
			}
		}
		if (issuersOCSP != null)  {
			// Si se tiene acceso al certificado firmante del OCSP, comprobar que fue emitido por un issuer de confianza 
			X509Certificate[] certs;
			try {
				certs = basicResp.getCerts("SUN");
			} catch (NoSuchProviderException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_12, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} catch (OCSPException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_12, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			}
			if ((certs == null) || (certs.length == 0)) {
				throw new UnknownTrustException();
			}
			// valida la cadena de certificación
			validateIssuer(certs, issuersOCSP);
			
	        // valida la respuesta
			try {
				// TODO: corregir el provider en función del tipo de firma de la respuesta
				if (basicResp.verify(certs[0].getPublicKey(), "SunRsaSign")) { // Modificar si no es firma RSA
					return;
				} else {
					throw new FakedTrustException();
				}
			} catch (OCSPException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_15, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} catch (NoSuchProviderException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_14, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} 
		}
		throw new NotTrustedException();
	}
	
	/**
	 * <p>Comprueba que todos los certificados indicados han sido emitidos por alguno de los certificados disponibles en el almacén de certificados indicado.</p>
	 * @param certs Array de certificados que se quiere comprobar
	 * @param store Almacén de certificados con emisores de certificados
	 * @throws UnknownTrustException Lanzado cuando se produce un error que impide realizar la comprobación
	 * @throws NotTrustedException Lanzada cuando alguno de los certificados no ha sido emitido por ninguno de los certificados contenidos en el almacén
	 */
	private void validateIssuer(final X509Certificate[] certs, final CertStore store) throws UnknownTrustException, NotTrustedException {
		for (int i = 0; i < certs.length; i++) {
			X509CertSelector certSelector = new X509CertSelector();
			if (certs.length > (i + 1)) {
				certSelector.setSubjectPublicKey(certs[i + 1].getPublicKey());
			} else {
				certSelector.setSubject(certs[i].getIssuerX500Principal());
			}
			Collection< ? extends Certificate> certsCollection;
			try {
				certsCollection = store.getCertificates(certSelector);
			} catch (CertStoreException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_22, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			}
			if (certsCollection.size() > 0) {
				Iterator< ? extends Certificate> it = certsCollection.iterator();
				while (it.hasNext()) {
					X509Certificate certIssuer = (X509Certificate) it.next();
					try {
						certs[i].verify(certIssuer.getPublicKey());
						return;
					} catch (InvalidKeyException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
						throw new UnknownTrustException();
					} catch (CertificateException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
						throw new UnknownTrustException();
					} catch (NoSuchAlgorithmException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
						throw new UnknownTrustException();
					} catch (NoSuchProviderException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
						throw new UnknownTrustException();
					} catch (SignatureException ex) {
					}
				}
				throw new FakedTrustException();
			}
			else if ((i + 1) < certs.length) {
				// TODO: comprobar que el certificado que expide tiene permisos para expedir certificados y la longitud de la cadena adecuada
				try {
					certs[i].verify(certs[i + 1].getPublicKey());
				} catch (InvalidKeyException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (CertificateException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (NoSuchAlgorithmException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (NoSuchProviderException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				} catch (SignatureException ex) {
					throw new FakedTrustException();
				}
			}
			else {
				throw new NotTrustedException();
			}
		}
		throw new NotTrustedException();
	}

	/**
	 * <p>Comprueba si el path de certificados indicado pertenece a una entidad de confianza.</p>
	 *  
	 * @param certs Path de certificados
	 * @throws TrustException lanzada cuando el objeto no es de confianza o ha ocurrido algún error al intentar comprobarlo:
	 * <ul>
	 * 	<li>{@link UnknownTrustException} lanzada cuando se desconoce si el objeto es o no de confianza (el objeto es desconocido o no
	 * 		se puede comprobar su confianza).</li>
	 * 	<li>{@link NotTrustedException} lanzada cuando el objeto no es de confianza.</li>
	 * 	<li>{@link FakedTrustException} lanzada cuando se detecta que el objeto ha sido manipulado.</li>
	 * </ul>
	 * @see es.mityc.javasign.trust.ITrustSignCerts#isTrusted(java.security.cert.CertPath)
	 */
	public void isTrusted(final CertPath certs) throws TrustException {
		if ((certs == null) || (certs.getCertificates().size() == 0)) {
			throw new UnknownTrustException();
		}
		// Primero comprueba si el certificado de firma es uno de los admitidos como de confianza
		if (certsCerts != null) {
			X509Certificate cert = (X509Certificate) certs.getCertificates().get(0);
			X509CertSelector certSelector = new X509CertSelector();
			certSelector.setCertificate(cert);
			Collection< ? extends Certificate> certsCollection = null;
			try {
				certsCollection = certsCerts.getCertificates(certSelector);
			} catch (CertStoreException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_24, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			}
			if (certsCollection.size() > 0) {
				return;
			}
		}
		// Si no es uno de los certificados busca a ver si ha sido emitido por una cadena de confianza
		if (issuersCerts != null)  {
			X509Certificate[] list = certs.getCertificates().toArray(new X509Certificate[0]);
			validateIssuer(list, issuersCerts);
			return;
		}
		throw new NotTrustedException();
	}

	/**
	 * <p>Comprueba si el TimeStampToken indicado ha sido emitido por una entidad de confianza.</p>
	 *  
	 * @param tst Sello de tiempo
	 * @throws TrustException lanzada cuando el objeto no es de confianza o ha ocurrido algún error al intentar comprobarlo:
	 * <ul>
	 * 	<li>{@link UnknownTrustException} lanzada cuando se desconoce si el objeto es o no de confianza (el objeto es desconocido o no
	 * 		se puede comprobar su confianza).</li>
	 * 	<li>{@link NotTrustedException} lanzada cuando el objeto no es de confianza.</li>
	 * 	<li>{@link FakedTrustException} lanzada cuando se detecta que el objeto ha sido manipulado.</li>
	 * </ul>
	 * @see es.mityc.javasign.trust.ITrustTSProducer#isTrusted(org.bouncycastle.tsp.TimeStampToken)
	 */
	public void isTrusted(final TimeStampToken tst) throws TrustException {
		if (certsTSA != null) {
			SignerId sid = tst.getSID();
			if (sid != null) {
				Collection< ? extends Certificate> certsColl;
				try {
					certsColl = certsTSA.getCertificates(sid);
				} catch (CertStoreException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_25, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
					throw new UnknownTrustException();
				}
				if (certsColl.size() > 0) {
					Iterator< ? extends Certificate> it = certsColl.iterator();
					while (it.hasNext()) {
						X509Certificate cert = (X509Certificate) it.next();
						try {
							tst.validate(cert, "SunRsaSign"); // Y si no es firma RSA?
							return;
						} catch (CertificateExpiredException ex) {
							LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_26), ex);
							throw new NotTrustedException(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_26));
						} catch (CertificateNotYetValidException ex) {
							LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_26), ex);
							throw new NotTrustedException(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_26));
						} catch (TSPValidationException ex) {
							throw new FakedTrustException();
						} catch (NoSuchProviderException ex) {
							LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_6, ex.getMessage()));
							if (LOG.isDebugEnabled()) {
								LOG.debug("", ex);
							}
							throw new UnknownTrustException();
						} catch (TSPException ex) {
							LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_7, ex.getMessage()));
							if (LOG.isDebugEnabled()) {
								LOG.debug("", ex);
							}
							throw new UnknownTrustException();
						}
					}
				}
			}
			else {
				throw new UnknownTrustException();
			}
		}
		if (issuersTSA != null) {
			// Si se tiene acceso al certificado firmante del OCSP, comprobar que fue emitido por un issuer de confianza 
			X509Certificate[] certs;
			try {
				certs = tst.getCertificatesAndCRLs("Collection", null).getCertificates(null).toArray(new X509Certificate[0]);
			} catch (NoSuchAlgorithmException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_19, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} catch (NoSuchProviderException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_19, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} catch (CMSException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_19, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} catch (CertStoreException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_25, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			}
			if ((certs == null) || (certs.length == 0)) {
				throw new UnknownTrustException();
			}
			// valida la cadena de certificación
			validateIssuer(certs, issuersTSA);
			
	        // valida la respuesta
			try {
				tst.validate(certs[0], "SunRsaSign"); // Y si no es firma RSA?
				return;
			} catch (CertificateExpiredException ex) {
			} catch (CertificateNotYetValidException ex) {
			} catch (TSPValidationException ex) {
				throw new FakedTrustException();
			} catch (NoSuchProviderException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_6, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			} catch (TSPException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_7, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
				throw new UnknownTrustException();
			}
		}
		throw new NotTrustedException();
	}
	
	/**
	 * <p>Deuelve una instancia única de este validador de confianza.</p>
	 * <p>La instancia creada utiliza como fichero de propiedades el recurso disponible en <code>/trust/myTruster.properties</code>.</p>
	 * @return Instancia única de un validador de confianza
	 */
	public static TrustAdapter getInstance() {
		if (instance == null) {
			instance = new PropsTruster(CONF_DEFAULT, null);
		}
		return instance;
	}
	
	/**
	 * <p>Recupera el ClassLoader de contexto si está disponible.</p>
	 * <p>Si no está disponible el de contexto devuelve el propio de la clase.</p>
	 * @return ClassLoader
	 */
	private static ClassLoader getClassLoader() {
		try {
			ClassLoader cl = AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
			    public ClassLoader run() {
					ClassLoader classLoader = null;
					try {
					    classLoader = Thread.currentThread().getContextClassLoader();
					} catch (SecurityException ex) {
					}
					return classLoader;
			    }
			});
			if (cl != null) {
				return cl;
			}
		} catch (Exception ex) {
		}
		return TrustFactory.class.getClassLoader();
	}

	/**
	 * <p>Recupera los certificados asociados a un tipo de manager de confianza.</p>
	 * <p>En este tipo de manager de confianza se administran cuatro tipos de manager.</p>
	 * @param cf Factoría de certificados
	 * @param props Propiedades de configuración de este manager
	 * @param trusterType Tipo de manager del que se quieren recuperar los certificados
	 * @return CertStore con los certificados asociados en la configuración
	 */
	private CertStore loadCerts(final CertificateFactory cf, final Properties internalProps, final Properties externalProps, final TrusterType trusterType) {
		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
		if (internalProps != null) {
			ClassLoader cl = getClassLoader();
			Enumeration< ? > en = internalProps.propertyNames();
			while (en.hasMoreElements()) {
				String propName = (String) en.nextElement();
				if (propName.startsWith(trusterType.toString())) {
					try {
						String value = internalProps.getProperty(propName);
						StringTokenizer st = new StringTokenizer(value, ",");
						while (st.hasMoreTokens()) {
							String res = st.nextToken();
							InputStream is = cl.getResourceAsStream(res);
							if (is != null) {
								try {
									list.add((X509Certificate) cf.generateCertificate(is));
								} catch (CertificateException ex) {
									LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_10, ex.getMessage()));
									if (LOG.isDebugEnabled()) {
										LOG.debug("", ex);
									}
								}
							}
							else {
								LOG.warn(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_8, res));
							}
						}
					} catch (MissingResourceException ex) { }
				}
			}
		}
		
		if (externalProps != null) {
			Enumeration< ? > en = externalProps.propertyNames();
			while (en.hasMoreElements()) {
				String propName = (String) en.nextElement();
				if (propName.startsWith(trusterType.toString())) {
					try {
						String value = externalProps.getProperty(propName);
						StringTokenizer st = new StringTokenizer(value, ",");
						String res = null;
						FileInputStream fis = null;
						while (st.hasMoreTokens()) {
							res = st.nextToken();
							fis = new FileInputStream(res);
							try {
								list.add((X509Certificate) cf.generateCertificate(fis));
							} catch (CertificateException ex) {
								ByteArrayOutputStream baos = null;
								try {
									fis.reset();
									baos = new ByteArrayOutputStream(fis.available());

									// Bucle para leer de un fichero y escribir en el otro.
									byte [] array = new byte[1000];
									int leidos = fis.read(array);
									while (leidos > 0) {
										baos.write(array,0,leidos);
										leidos = fis.read(array);
									}
									ByteArrayInputStream b64 = new ByteArrayInputStream(Base64.encode(baos.toByteArray()));

									list.add((X509Certificate) cf.generateCertificate(b64));
								} catch (Exception ex2) {
									LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_10, ex.getMessage()));
									if (LOG.isDebugEnabled()) {
										LOG.debug("", ex);
										LOG.debug("", ex2);
									}
								} finally {
									try { baos.close(); } catch(Exception e){}
								}
							} finally {
								try { fis.close(); } catch(Exception e){}
							}
						}
					} catch (MissingResourceException ex) {
						LOG.warn(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_8, ex.getMessage()));
					} catch (FileNotFoundException e) {
						LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_10, e.getMessage()));
					}
				}
			}
		}
		CertStore cs = null;
		if (list.size() > 0) {
			try {
				cs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(list));
			} catch (InvalidAlgorithmParameterException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_20, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
			} catch (NoSuchAlgorithmException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_20, ex.getMessage()));
				if (LOG.isDebugEnabled()) {
					LOG.debug("", ex);
				}
			}
		}
		return cs;
	}

	/**
	 * <p>Reconstruye la cadena de certificados que le corresponde al certificado indicado.</p>
	 * @param cert Certificado cuya cadena se va a reconstruir
	 * @return Cadena de certificados reconstruida.
	 * @throws UnknownTrustException En caso de error.
	 */
	public CertPath getCertPath(X509Certificate cert) throws UnknownTrustException {

		// Destino de la cadena de certificados reconstruida
		Vector<X509Certificate> certsChain = new Vector<X509Certificate>();
		certsChain.add(cert);

		// Se busca la cadena en todos los CertStores
		ArrayList<CertStore> arrayStores = new ArrayList<CertStore>();
		arrayStores.add(issuersCerts);
		arrayStores.add(certsCerts);
		arrayStores.add(issuersOCSP);
		arrayStores.add(certsOCSP);
		arrayStores.add(issuersCRL);
		arrayStores.add(issuersTSA);
		arrayStores.add(certsTSA);

		// Filtro de búsqueda
		X509CertSelector certSelector = new X509CertSelector();
		CertStore cs = null;
		X509Certificate certToValidate = cert;
		X509Certificate issuer = null;
		Iterator< ? extends Certificate> it = null;
		boolean chainCompleted = false;

		// Mientras la cadena no esté completa, se mira en todos los CertStores 
		for(int i = 0; i < arrayStores.size() && !chainCompleted; ++i) { 
			cs = arrayStores.get(i);
			int chainLenght = 0;
			while(chainLenght != certsChain.size() && cs != null) { // Condición de salida: No se encontraron nuevos certificados
				
				chainLenght = certsChain.size();
				
				// Se comprueba si el certificado a validar es un certificado raíz (autofirmado)
				try {
					certToValidate.verify(certToValidate.getPublicKey());
					// Si no ha saltado una excepción, la cadena está completa
					chainCompleted = true;
					break;					
				} catch (Exception ex) {/* No se hace nada */}

				// Se toman los certificados cuyo Subject coincida con el Issuer del certificado a validar
				certSelector.setSubject(certToValidate.getIssuerX500Principal());

				// Se recupera la lista de posibles emisores del almacén
				try {
					Collection < ? extends Certificate> preselCerts = cs.getCertificates(certSelector);
					if (preselCerts != null) {
						it = preselCerts.iterator();
					} else {
						continue;
					}
					
				} catch (CertStoreException ex) {
					throw new UnknownTrustException();
				}

				// Se comprueba que los preseleccionados hayan firmado al certificado a validar
				while (it.hasNext()) {
					issuer = (X509Certificate) it.next();
					try {
						certToValidate.verify(issuer.getPublicKey());
						// Si no ha saltado una excepción, el certificado ha pasado la validación
						certsChain.add(issuer); // Se agrega a la cadena
						certToValidate = issuer; // El nuevo certificado a validar es el emisor
						break;					
					} catch (Exception ex) {
						continue;
					}
				}
			}
		}
		
		// Se comprueba que se haya reconstruido la cadena completa
		if (!chainCompleted) {
			throw new UnknownTrustException(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_PROPS_23, cert.getSubjectX500Principal().getName() + " -issuer:  " + cert.getIssuerDN()));
		}
		
		// Se genera la estructura de certificados a devolver
		CertPath cp = null;		
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cp = cf.generateCertPath(certsChain);
		} catch (CertificateException ex) {
			throw new UnknownTrustException();
		}

		return cp;
	}
	
	public Vector<X509Certificate> getTrustedCAs(TrusterType type) {
		Vector<X509Certificate> trustedCerts = new Vector<X509Certificate>();
		if (type == null) {
			trustedCerts.addAll(extractAllCerts(certsCerts));
			trustedCerts.addAll(extractAllCerts(issuersCerts));
			trustedCerts.addAll(extractAllCerts(certsOCSP));
			trustedCerts.addAll(extractAllCerts(issuersOCSP));
			trustedCerts.addAll(extractAllCerts(certsTSA));
			trustedCerts.addAll(extractAllCerts(issuersTSA));
			trustedCerts.addAll(extractAllCerts(issuersCRL));	
		} else if (TrusterType.TRUSTER_SIGNCERTS_CERTS.equals(type)) {
			trustedCerts.addAll(extractAllCerts(certsCerts));
		} else if (TrusterType.TRUSTER_SIGNCERTS_ISSUER.equals(type)) {
			trustedCerts.addAll(extractAllCerts(issuersCerts));
		} else if (TrusterType.TRUSTER_OCSP_CERTS.equals(type)) {
			trustedCerts.addAll(extractAllCerts(certsOCSP));
		} else if (TrusterType.TRUSTER_OCSP_ISSUER.equals(type)) {
			trustedCerts.addAll(extractAllCerts(issuersOCSP));
		} else if (TrusterType.TRUSTER_TSA_CERTS.equals(type)) {
			trustedCerts.addAll(extractAllCerts(certsTSA));
		} else if (TrusterType.TRUSTER_TSA_ISSUER.equals(type)) {
			trustedCerts.addAll(extractAllCerts(issuersTSA));
		} else if (TrusterType.TRUSTER_CRL_ISSUER.equals(type)) {
			trustedCerts.addAll(extractAllCerts(issuersCRL));
		} else {
			LOG.debug("No se reconoció el tipo indicado: " + type);
		}

		return trustedCerts;
	}
	
	private Vector<X509Certificate> extractAllCerts(CertStore cs) {
		Vector<X509Certificate> trustedCerts = new Vector<X509Certificate>();

		if (cs != null) {
			Collection<? extends Certificate> certs = null;
			try {
				certs = cs.getCertificates(null);
			} catch (CertStoreException e) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("", e);
				}
				return trustedCerts;
			}
			if (certs != null) {				
				Iterator<? extends Certificate> it2 = certs.iterator();
				while (it2.hasNext()) {
					try {
						trustedCerts.add((X509Certificate) it2.next()); // Se agrega a la cadena
					} catch (Exception e) { // Posible ClassCastException
						if (LOG.isDebugEnabled()) {
							LOG.debug("", e);
						}
						continue;
					}
				}
			}
		}

		return trustedCerts;
	}
}
