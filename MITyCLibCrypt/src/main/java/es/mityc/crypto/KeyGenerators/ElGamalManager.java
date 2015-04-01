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
package es.mityc.crypto.KeyGenerators;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.Utils;
import es.mityc.javasign.ConstantsAPI;

public class ElGamalManager {

	public static void main(String[] args) throws Exception {
		if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) == null) {
			es.mityc.javasign.utils.Utils.addBCProvider();
		}

		byte[] input = "textoEnClaroElGammal".getBytes();
		Cipher cipher = Cipher.getInstance(ConstantsCrypto.EL_GAMAL_NO_PADDING, ConstantsAPI.PROVIDER_BC_NAME);
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ConstantsCrypto.EL_GAMAL_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		SecureRandom random = new SecureRandom();

		generator.initialize(1024, random);

		KeyPair pair = generator.generateKeyPair();
		Key pubKey = pair.getPublic();
		Key privKey = pair.getPrivate();
		
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);//, random);
		byte[] cipherText = cipher.doFinal(input);
		System.out.println("cipher: " + new String(cipherText));

		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] plainText = cipher.doFinal(cipherText);
		System.out.println("plain : " + new String(plainText));
		
		
		/******************************************************************/
        
//        // create the symmetric key and iv
//        Key             sKey = Utils.createKeyForAES(256, random);
//        IvParameterSpec sIvSpec = Utils.createCtrIvForAES(0, random);
//        
//        byte[] keyBlock = xCipher.doFinal(packKeyAndIv(sKey, sIvSpec));
//        
//        // symmetric key/iv unwrapping step
//        xCipher.init(Cipher.DECRYPT_MODE, privKey);
//        
//        Object[]	keyIv = unpackKeyAndIV(xCipher.doFinal(keyBlock));
//        
//        // decryption step
//        sCipher.init(Cipher.DECRYPT_MODE, (Key)keyIv[0], (IvParameterSpec)keyIv[1]);		
	}
}
