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
package es.mityc.crypto;

public class ConstantsCrypto {
	
	public static final String LIB_NAME = "MITyCLibCrypt";
	
	public static final String[] SYMMETRIC_CIPHERS = { 
		"AES", "Camellia", "CAST5", "Grainv1", "Grain128", "IDEA", "Noekeon", "SEED" };
	
	/** Algoritmos de encriptación. */
	public static final String RSA_ALGORITHM = "RSA";
	public static final String TripleDES_ALGORITHM = "DESede";
	public static final String PBE_DES_ALGORITHM = "PBEWithMD5AndDES";
	public static final String AES_ALGORITHM = "AES";
	public static final String AES_CBC_PKCS5Padding_ALGORITHM = "AES/CBC/PKCS5Padding";
	public static final String PBEWithSHA256And256BitAES_CBC_BC_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
	
	public static final String BLOWFISH_ALGORITHM = "Blowfish";
	public static final String BLOWFISH_CFB64_NO_PADDING = "Blowfish/CFB64/NoPadding";
	
	/** Algoritmos de Digest */
	public static final String DIGEST_ALG_SHA1 = "SHA1";
	public static final String DIGEST_ALG_SHA256 = "SHA256";
	public static final String DIGEST_ALG_MD5 = "MD5";
	
	/** Algoritmos de negociado de claves. */
	public static final String EL_GAMAL_ALGORITHM = "ElGamal";
	public static final String EL_GAMAL_NO_PADDING = "ElGamal/None/NoPadding";
	public static final String DIFFIE_HELLMAN_ALGORITHM = "DH";
	public static final String ELIPTIC_CURVE_DH = "ECDH";

}
