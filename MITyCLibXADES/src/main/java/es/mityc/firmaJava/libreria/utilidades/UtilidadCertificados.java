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
package es.mityc.firmaJava.libreria.utilidades;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;

/**
 * Conjunto de utilidades para el tratamiento genérico de certificados.
 *
 */
public class UtilidadCertificados {
	
	private static final Log logger = LogFactory.getLog(UtilidadCertificados.class);
	
	public enum Filter { SIGN_SIGNER, CRL_SIGNER, OCSP_SIGNER, TS_SIGNER}; 
	private final static String OID_OCSP_SIGNING	= "1.3.6.1.5.5.7.3.9"; 
	private final static String OID_TS_SIGNING 		= "1.3.6.1.5.5.7.3.8";

	/**
     * Recupera los CertPath's de certificados que pueda encontrar en el listado de certificados provistos.
     * 
     * @param certificates Listado de certificados
     * @return ArrayList con los CertPath's que se han podido construir
     */
    public static ArrayList<CertPath> getCertPaths(Iterable<X509Certificate> certificates) {
    	ArrayList<ArrayList<X509Certificate>> list = getCertPathsArray(certificates);
    	ArrayList<CertPath> certPaths = new ArrayList<CertPath>();
    	Iterator<ArrayList<X509Certificate>> itArrays = list.iterator();
    	while (itArrays.hasNext()) {
			CertPath cp = convertCertPath(itArrays.next());
			if (cp != null)
				certPaths.add(cp);
    	}
    	return certPaths;
    }
    
	/**
     * Recupera los CertPath's de certificados que pueda encontrar en el listado de certificados provistos.
     * 
     * @param certificates Listado de certificados
     * @return ArrayList con los CertPath's que se han podido construir
     */
    public static ArrayList<ArrayList<X509Certificate>> getCertPathsArray(Iterable<X509Certificate> certificates) {
    	ArrayList<ArrayList<X509Certificate>> certPaths = new ArrayList<ArrayList<X509Certificate>>();
    	if (certificates != null) {
    		// Pasa todos los certificados a una lista enlazada eliminando los certificados repetidos
    		ArrayList<NTo1Link<X509Certificate>> list = new ArrayList<NTo1Link<X509Certificate>>();
    		Iterator<X509Certificate> itCerts = certificates.iterator();
    		while (itCerts.hasNext()) {
    			NTo1Link<X509Certificate> nodo = new NTo1Link<X509Certificate>(itCerts.next());
    			if (!list.contains(nodo))
    				list.add(nodo);
    		}
    		// Busca para cada certificado su relación (hijo de, padre de)
    		for (int i = 0; i < list.size(); i++) {
    			for (int j = i + 1; j < list.size(); j++) {
    				linkCerts(list.get(i), list.get(j));
    			}
    		}
    		// Busca los nodos que no tengan previos. Esos son los comienzos de una cadena
    		Iterator<NTo1Link<X509Certificate>> itNodos = list.iterator();
    		while (itNodos.hasNext()) {
    			NTo1Link<X509Certificate> nodo = itNodos.next();
    			if (nodo.getNumPrevs() == 0) {
    				ArrayList<X509Certificate> cp = convertCertPathArray(nodo);
    				if (cp != null)
    					certPaths.add(cp);
    			}
    		}
    	}
    	return certPaths;
    }
    
    /**
     * Aplica un filtro a una lista de certPaths
     * 
     * @param list Lista de certPaths
     * @param filter filtro a aplicar
     * @return lista de certpaths tras aplicar los filtros
     */
    public static ArrayList<ArrayList<X509Certificate>> filterCertPathsArrays(ArrayList<ArrayList<X509Certificate>> list, Filter filter) {
    	ArrayList<ArrayList<X509Certificate>> result = new ArrayList<ArrayList<X509Certificate>>();
    	Iterator<ArrayList<X509Certificate>> it = list.iterator();
    	while (it.hasNext()) {
    		ArrayList<X509Certificate> certs = it.next();
    		if ((certs != null) && (certs.size() > 0)) {
    			if (Filter.OCSP_SIGNER.equals(filter)) {
    				if (isOCSPSigning(certs.get(0)))
    	        		result.add(certs);
    			}
    			else if (Filter.TS_SIGNER.equals(filter)) {
    				if (isTSSigning(certs.get(0)))
    	        		result.add(certs);
    			}
    			else if (Filter.CRL_SIGNER.equals(filter)) {
    				if (isCRLSigning(certs.get(0)))
    	        		result.add(certs);
    			}
    			else if (Filter.SIGN_SIGNER.equals(filter)) {
    	        		result.add(certs);
    			}
    		}
    	}
    	return result;
    }
    
    /**
     * Recupera los CertPath's de certificados que pueda encontrar en el listado de certificados provistos.
     * 
     * @param certificates Listado de certificados
     * @return ArrayList con los CertPath's que se han podido construir
     */
    public static CertPath orderCertPath(Iterable<X509Certificate> certificates) {
    	CertPath cp = null;
    	if (certificates != null) {
    		// Pasa todos los certificados a una lista enlazada eliminando los certificados repetidos
    		ArrayList<NTo1Link<X509Certificate>> list = new ArrayList<NTo1Link<X509Certificate>>();
    		Iterator<X509Certificate> itCerts = certificates.iterator();
    		while (itCerts.hasNext()) {
    			NTo1Link<X509Certificate> nodo = new NTo1Link<X509Certificate>(itCerts.next());
    			if (!list.contains(nodo))
    				list.add(nodo);
    		}
    		// Busca para cada certificado su relación (hijo de, padre de)
    		for (int i = 0; i < list.size(); i++) {
    			for (int j = i + 1; j < list.size(); j++) {
    				linkCerts(list.get(i), list.get(j));
    			}
    		}
    		// Busca los nodos que no tengan previos. Esos son los comienzos de una cadena
    		Iterator<NTo1Link<X509Certificate>> itNodos = list.iterator();
    		while (itNodos.hasNext()) {
    			NTo1Link<X509Certificate> nodo = itNodos.next();
    			if (nodo.getNumPrevs() == 0) {
    				ArrayList<X509Certificate> cpa = convertCertPathArray(nodo);
    				if (cpa != null)
    					cp = convertCertPath(cpa);
    			}
    		}
    	}
    	return cp;
    }
    
    /**
     * Indica si un certificado es un firmante de respuestas OCSP
     * @param cert
     * @return true si es un certificado firmante de respuestas OCSP y false en caso contrario
     */
    private static boolean isOCSPSigning(X509Certificate cert) {
    	try {
			List<String> list = cert.getExtendedKeyUsage();
			if (list != null) {
				Iterator<String> it = list.iterator();
				while (it.hasNext()) {
					if (OID_OCSP_SIGNING.equals(it.next()))
						return true;
				}
			}
		} catch (CertificateParsingException ex) {
		}
    	return false;
    }

    /**
     * Indica si un certificado es un firmante de sellos de tiempo
     * @param cert
     * @return true si es un certificado firmante de sellos de tiempo y false en caso contrario
     */
    private static boolean isTSSigning(X509Certificate cert) {
    	try {
			List<String> list = cert.getExtendedKeyUsage();
			if (list != null) {
				Iterator<String> it = list.iterator();
				while (it.hasNext()) {
					if (OID_TS_SIGNING.equals(it.next()))
						return true;
				}
			}
		} catch (CertificateParsingException ex) {
		}
    	return false;
    }

    /**
     * Indica si un certificado es un firmante de CRLs
     * @param cert
     * @return true si es un certificado firmante de CRLs y false en caso contrario
     */
    private static boolean isCRLSigning(X509Certificate cert) {
		boolean[] usage = cert.getKeyUsage();
		if ((cert != null) && (usage[6]))
			return true;
		return false;
    }

    /**
     * Relaciona los certificados indicados entre si (si existe alguna relación)
     * @param nodo1
     * @param nodo2
     * 
     * TODOLARGO: permitir establecer políticas de severidad a la hora de buscar las relaciones entre los certificados. Estas
     * políticas pueden ser por ejemplo que se compruebe que un certificado ha firmado al otro, que campos opcionales sean
     * exigidos como presentes, que alguno de los certificados de las cadenas resultantes sean certificados de confianza, etc.
     */
    private static void linkCerts(NTo1Link<X509Certificate> nodo1, NTo1Link<X509Certificate> nodo2) {
    	if (nodo1.getData().getIssuerX500Principal().equals(nodo2.getData().getSubjectX500Principal())) {
    		// Comprueba que el certificado padre generó al certificado hijo
    		try {
				nodo1.getData().verify(nodo2.getData().getPublicKey());
			} catch (InvalidKeyException ex) {
				return;
			} catch (CertificateException ex) {
				return;
			} catch (NoSuchAlgorithmException ex) {
				return;
			} catch (NoSuchProviderException ex) {
				return;
			} catch (SignatureException ex) {
				return;
			}
    		
    		nodo1.setNext(nodo2);
    		nodo2.addPrev(nodo1);
    	} else if (nodo2.getData().getIssuerX500Principal().equals(nodo1.getData().getSubjectX500Principal())) {
    		// Comprueba que el certificado padre generó al certificado hijo
    		try {
				nodo2.getData().verify(nodo1.getData().getPublicKey());
			} catch (InvalidKeyException ex) {
				return;
			} catch (CertificateException ex) {
				return;
			} catch (NoSuchAlgorithmException ex) {
				return;
			} catch (NoSuchProviderException ex) {
				return;
			} catch (SignatureException ex) {
				return;
			}

    		nodo2.setNext(nodo1);
    		nodo1.addPrev(nodo2);
    	}
    }
    
    /**
     * Convierte una sucesion de nodos enlazados en un CertPath
     * @param Array de certificados
     * @return
     */
    public static CertPath convertCertPath(Certificate[] certs) {
    	if (certs == null)
    		return null;
    	ArrayList<X509Certificate> input = new ArrayList<X509Certificate>();
    	for (int i = 0; i < certs.length; ++i) {
    		if (certs[i] instanceof X509Certificate)
    			input.add((X509Certificate) certs[i]);
    		else {
    			try {
    				input.add((X509Certificate) certs[i]);
    			} catch (Exception e) {
    				logger.debug("El certificado no es de tipo X509", e);
    			}
    		}
    	}
    	
    	return convertCertPath(input);
    }
    
    /**
     * Convierte una sucesion de nodos enlazados en un CertPath
     * @param Listado de certificados X509
     * @return
     */
    public static CertPath convertCertPath(ArrayList<X509Certificate> certs) {
    	CertPath cp = null;
    	try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cp = cf.generateCertPath(certs);
		} catch (CertificateException ex) {
			logger.error("Error al intentar generar CertPaths", ex);
		}
    	return cp;
    }
    
    /**
     * Convierte una sucesion de nodos enlazados en un CertPath
     * @param nodo
     * @return
     */
    private static ArrayList<X509Certificate> convertCertPathArray(NTo1Link<X509Certificate> nodo) {
    	ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
    	Iterator<NTo1Link<X509Certificate>> itNodo = nodo.iterator();
    	while (itNodo.hasNext()) {
    		certs.add(itNodo.next().getData());
    	}
    	return certs;
    }
    
    /**
     * Obtiene el nombre común
     * 
     * @param dname X500Principal Directory name del que se obtiene el nombre común
     * @return String CN obtenido 
     */
    public static String getCN(X500Principal dname){
    	String retorno = null;
    	X509Principal nombre = new X509Principal(dname.getName());
    	
    	// Se obtienen sus valores asociados
    	Vector<?> commonNameOIDs = nombre.getOIDs();
    	Vector<?> commonName = nombre.getValues();
		int longitudValues = commonName.size();
    	
		if (longitudValues != 0) {
			// Se busca el valor "CN"
			int indexCN = commonNameOIDs.indexOf(X509Name.CN);
			if (indexCN != -1) {
				Object elemento = commonName.get(indexCN);
				if (elemento instanceof String)
					retorno = (String) elemento;
			}
		}

		return retorno;
    }
    
    /**
     * <p>Compara dos nombres X500 para ver si son iguales (independientemente del orden de las partículas.</p>
     * @param prin1 Nombre
     * @param prin2 Nombre
     * @return
     */
    public static boolean isSameName(X500Principal prin1, X500Principal prin2) {
		X509Name name1 = new X509Name(prin1.getName());
		X509Name name2 = new X509Name(prin2.getName());
		return name1.equals(name2);
    }

}
