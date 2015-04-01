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
package es.mityc.javasign.pkstore.iexplorer;

import java.security.AccessController;
import java.security.PrivilegedAction;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.utils.CopyFilesTool;

/**
 * Clase JNI para el acceso al CSP de Windows.
 * 
 */

public final class IECSPJNI  {
	
	 /** Logger. */
	private static final Log LOG = LogFactory.getLog(IECSPJNI.class);
    
    /**
     * <p>Firma un hash mediante un certificado.</p>
     * @param paraFirmar datos en binario a firmar
     * @param certificadoBinario certificado en binario que realizará la firma
     * @return contenido firmado
     */
	public native byte[] signHash(byte[] paraFirmar, byte[] certificadoBinario);
    /**
     * <p>Recupera los certificados de un almacén en forma binaria.</p>
     * @param almacenaNombre nombre del almacén interno de windows
     * @return array de certificados en binario disponibles en el almacén
     */
	public native byte[][] getCertificatesInSystemStore(String almacenaNombre);
    /**
     * <p>Recupera el DN del issuer de un certificado.</p>
     * @param certificado certificado en binario
     * @return cadena con el DN del issuer
     */
	public native String getIssuerDN(byte[] certificado);
    /**
     * <p>Obtiene el número serie del certificado.</p>
     * @param certificado certificado en binarios
     * @return número serie en binario
     */
    public native byte[] getSerialNumber(byte[] certificado);
    /**
     * <p>Obtiene el DN del subject de un certificado.
     * @param certificado certificado en binario
     * @return cadena con el DN del subject
     */
    public native String getSubjectDn(byte[] certificado);
    
    
    /**
     * <p>Devuelve el último error que se produjo en la librería DLL externa.</p>
     * @return Número entero que especifíca el tipo de error según la lista siguiente,
     * definida en la DLL externa basada en OPENSIGN
     * <CODE>#define OPENSIGN_ERROR_NONE 0
     * #define OPENSIGN_ERROR_DIGEST_VALUE_UNAVAILABLE 1
     * #define OPENSIGN_ERROR_DIGEST_SIZE_UNAVAILABLE 2
     * #define OPENSIGN_ERROR_HHASH_DESTROY_FAILURE 3
     * #define OPENSIGN_ERROR_HHASH_CREATE_FAILURE 4
     * #define OPENSIGN_ERROR_HCRYPTPROV_RELEASE_FAILURE 5
     * #define OPENSIGN_ERROR_HCRYPTPROV_ACQUIRE_FAILURE 6
     * #define OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE 7
     * #define OPENSIGN_ERROR_CERTSTORE_CERTIFICATE_NOT_FOUND 8
     * #define OPENSIGN_ERROR_CERTSTORE_CLOSE_FAILURE 9
     * #define OPENSIGN_ERROR_CCONTEXT_PROVINFO_VALUE_UNAVAILABLE 10
     * #define OPENSIGN_ERROR_HHASH_SIGNATURE_VALUE_UNAVAILABLE 11
     * #define OPENSIGN_ERROR_HHASH_SIGNATURE_SIZE_UNAVAILABLE 13
     * #define OPENSIGN_ERROR_CCONTEXT_PROVINFO_SIZE_UNAVAILABLE 14
     * #define OPENSIGN_ERROR_HHASH_HASHDATA_FAILURE 15
     * #define OPENSIGN_ERROR_CERTGETNAMESTRING_SIZE_FAILURE 16
     * #define OPENSIGN_ERROR_CERTGETNAMESTRING_VALUE_FAILURE 17
     * #define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE 18
     * #define OPENSIGN_ERROR_KEYUSAGE_NOT_PRESENT 19</CODE>
     */
    public native int getLastErrorCode();
    
    
    /**
     * <p>Crea una nueva instancia de FirmaMS.</p>
     */
    public IECSPJNI() {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {           	
            	String key = ConstantsCert.CSP_JNI_IE;
            	try {
            		System.loadLibrary(key);
            	} catch (Throwable e) {
        			LOG.debug("No se pudo cargar la instancia de la librería " + ConstantsCert.CSP_JNI_IE + ": " + e.getMessage(), e);
        		
        			try {
        				String random = new Long(System.currentTimeMillis()).toString();
        				CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_IE_PROPERTIES, this.getClass().getClassLoader());
        				cft.copyFilesOS(null, ConstantsCert.CP_EXPLORER, true, random);
        				System.loadLibrary(key + random);
                    } catch (Exception e2) {
                    	LOG.debug("No se pudo cargar definitivamente la instancia de la librería " + ConstantsCert.CSP_JNI_IE + ": " + e2.getMessage(), e2);
                    }
            	}
                return null;
            }
        });
    }
}
