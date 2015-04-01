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

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.CertificateEncodingException;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.exception.CopyFileException;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.utils.CopyFilesTool;

/**
 * <p>Implementación de SignatureSpy para la firma en IE.</p>
 *
 */
public final class IESignEngine extends SignatureSpi { 
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(IESignEngine.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
   
	/** Referencia al acceso nativo al almacén. */
	private static IECSPJNI cspBridge = null;
	/** Datos que se quieren firmar. */
    private byte[] paraFirmar 	= null;
    /** Certificado que se quiere utilizar el almacén. */
    private byte[] certificadoBinario = null;
    
    /**
     * <p>Crea una nueva instancia de FirmaMS.</p>
     */
    public IESignEngine() {
    	loadLibrary();
    }

    /**
     * Obtiene el valor del parámetro especificado del algoritmo.
     * Este método provee un mecanismo de uso general a través del cual
     * es posible obtener varios parámetros de este objeto. Un parámetro
     * puede ser cualquiera que pueda ser fijado para el algoritmo,
     * como el tamaño, o una fuente de bits al azar para la 
     * generación de firmas (si es apropiado), o una indicación que puede
     * o no realizar un cómputo específico pero opcional. 
     * @param parametro nombre del parámetro.
     * @return el objeto que representa el valor del parámetro, o nulo si
     * no hay nada.
     * @throws InvalidParameterException si el parámetro es  
     * inválido para este motor, o si ocurre otra excepción mientras que intenta
     * obtener este parámetro.
     * 
     * @deprecated La función esta deprecada.
     */
    @Override
	public Object engineGetParameter(String parametro) throws InvalidParameterException {
    	
        throw new InvalidParameterException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_3));
    }
       
    /**
     * Inicializa el objeto de la firma con la clave privada 
     * especificada para las operaciones de firma.
     * @param clavePrivada La clave privada que será generada
     * @exception InvalidKeyException Si la clave se codifica incorrectamente,
     * o si faltan parámetros, etc.
     */
    @Override
	public void engineInitSign(PrivateKey clavePrivada) throws InvalidKeyException {
    	try {
			this.certificadoBinario = ((PKProxyIE) clavePrivada).getCertificate().getEncoded();
		} catch (CertificateEncodingException ex) {
			LOG.error("Error al obtener certificado de firma en codificación DER", ex);
		}
    }
      
    /**
     * Actualiza los datos que se firmaron o verificaron, usando arrays de
     * bytes específicos, comenzando en el offset especificado.
     * @param b array de bytes
     * @param off El offset al comienzo del array de bytes
     * @param len El número de bytes en uso, empezando en offset
     * @exception SignatureException si el motor no ha sido inicializado
     * adecuadamente.
     */
    @Override
	public void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        byte [] copia = new byte[len];
        System.arraycopy(b, off, copia, 0, len);
        this.setToSign(copia);
    }
    
    /**
     * Estable un valor específico para un parámetro específico. 
     * Este método suple un mecanismo de propósito genera a través
     * del cual es posible establecer varios parámetros para este objeto.
     * @param param nombre del parámetro
     * @param value valor del parámetro
     * @exception InvalidParameterException si el parámetro es inválido
     * para el algoritmo de firma, si el parámetro ya está establecido y
     * no puede establecerse de nuevo, etc.
     * @deprecated reemplazada por {@link
     * #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     * engineSetParameter}.
     */
    @Override
	public void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_2));
    }
     
    /**
     * <p>Especifica los parámetros para configurar la firma.</p>
     * @param paramSpec objeto de la clase AlgorithmParameterSpec
     * con la configuración
     * @throws java.security.InvalidParameterException en caso de que
     * los parámetros no sean correctos
     */
    @Override
    public void engineSetParameter(AlgorithmParameterSpec paramSpec) throws InvalidParameterException {
    	// NO implementado
    }
      
    /**
     * Actualiza los datos que han sido firmados o verificados usando
     * el byte especificado. 
     * 
     * @param b byte utilizado para la actualización
     * @exception SignatureException si el motor no ha sido inicializado
     * adecuadamente
     */
    @Override
    public void engineUpdate(byte b) throws SignatureException {
        throw new UnsupportedOperationException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_2));
    }
      
    /**
     * <p>Este método verifica la firma.</p>
     * 
     * @param firmaBytes la firma en formato binario a verificar
     * @return verdadero si la firma está verificada, y falso si no. 
     * @exception SignatureException si el motor no ha sido inicializado
     * adecuadamente, o la firma pasada está codificada incorrectamente o
     * de tipo incorrecto, etc.
     */
    @Override
    public boolean engineVerify(byte[] firmaBytes) throws SignatureException {
        throw new SignatureException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_4));
    }
     
    /**
     * <p>Inicializa la firma con la clave pública especificada
     * para las operaciones de la verificación.</p>
     * 
     * @param clavePublica clave pública de la identidad que firma a
     * ser verificada
     * @exception InvalidKeyException la clave está codificada
     * incorrectamente, los parámetros se han perdido, etc.
     */
    @Override
    public void engineInitVerify(PublicKey clavePublica) throws InvalidKeyException {
        throw new InvalidKeyException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_4));
    }
    
    /**
     * <p>Copia la librería externa DLL al directorio temporal.</p>
     * @throws CopyFileException lanzada cuando no se puede copiar la librería nativa
     */
    private void copyLibrary() throws CopyFileException  {
		CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_IE_PROPERTIES, this.getClass().getClassLoader());
		cft.copyFilesOS(null, ConstantsCert.CP_EXPLORER, true);
	}
    
    /**
     * <p>Carga la librería externa DLL encargada de realizar el puente con CSP.</p>
     */
    private synchronized void loadLibrary() {
        try {
            if (cspBridge == null) {
            	copyLibrary();
                cspBridge = new IECSPJNI();
            }
        }
        catch (Exception ex) {
        	LOG.fatal(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_1, ex.getMessage()));
        	if (LOG.isDebugEnabled()) {
        		LOG.error(ex);
        	}
        }
    }

     
    /**
     * Devuelve la firma en formato binario con todos los datos actualizados
     * hasta el momento. El formato de la firma depende de su esquema subyacente.
     * 
     * @return La firma en formato binario del resultado de la operac	ión de firma.
     * @exception SignatureException Si el motor no ha sido inicializado
     * adecuadamente.
     */
    @Override
    public byte[] engineSign() throws java.security.SignatureException {
        if (this.certificadoBinario == null) {
            throw new SignatureException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_5));
        }
        if (this.getToSign() == null) {
            throw new SignatureException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_6));
        }
        byte [] firma = cspBridge.signHash(this.getToSign(), this.certificadoBinario);
        if (firma == null) {
        	LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_7, cspBridge.getLastErrorCode()));
            throw new SignatureException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_7, cspBridge.getLastErrorCode()));
        }
        byte [] copia = new byte[firma.length];
        System.arraycopy(firma, 0, copia, 0, firma.length);
        return copia;
    }

    
    /**
     * Verifica la firma en formato binario empezando por el offset especificado.
     * Nota: Las subclases deben sobreescribir la puesta en práctica
     * por defecto
     * 
     * @param firmaBytes firma en formato binario a verificar 
     * @param offset offset del comienzo del array de bytes
     * @param longitud número de bytes a usar, empezando en offset 
     * @return verdadero si la firma esta verificada, falso si no. 
     * @exception SignatureException Si el motor no está inicializado
     * adecuadamente, o la firma pasada está codificada incorrectamente,
     * o es del tipo incorrecto, etc.
     */
    @Override
    protected boolean engineVerify(byte[] firmaBytes, int offset, int longitud) throws SignatureException {
        throw new SignatureException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_4));
    }
    
    /**
     * Inicializa la firma con la clave privada
     * especificada y la fuente de aleatoriedad para las operaciones
     * de firma.
     * Este método concreto se ha agregado a la clase abstracta
     * anteriormente definida. (Para mantener a la compatibilidad, no
     * puede ser abstracto).
     * 
     * @param clavePrivada clave privada que identifica a quien generará
     * la firma.
     * @param random fuente de aleatoriedad.
     * @exception InvalidKeyException si la clave esta codificada
     * incorrectamente, los parámetros se han perdido, etc.- 
     */
    @Override
    protected void engineInitSign(PrivateKey clavePrivada, SecureRandom random) throws InvalidKeyException {
        this.engineInitSign(clavePrivada);
    }
    

    /**
     * <p>Devuelve el array de bytes a firmar.</p>
     * @return array de bytes a firmar
     */
    public byte[] getToSign() {
        return paraFirmar.clone();
    }
 
    /**
     * <p>Asigna el array de bytes a firmar.</p>
     * @param paraFirmar array de bytes a firmar
     */
    public void setToSign(byte[] paraFirmar) {
        this.paraFirmar = paraFirmar.clone();
    }

    /**
     * <p>Devuelve un array de bytes con el certificado seleccionado.</p>
     * @return array de bytes con el certificado seleccionado
     */
    public byte[] getBinaryCertificate() {
        return certificadoBinario.clone();
    }

    /**
     * <p>Asigna un array de bytes con el certificado seleccionado.</p>
     * @param certificadoBinario Array de bytes con el certificado seleccionado
     */
    public void setBinaryCertificate(byte[] certificadoBinario) {
        this.certificadoBinario = certificadoBinario.clone();
    }
}
