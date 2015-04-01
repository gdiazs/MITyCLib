/*
 * Copyright (c) 2005, 2012, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package es.mityc.javasign.pkstore.mscapi.mityc;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.security.action.PutAllAction;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.utils.CopyFilesTool;
import es.mityc.javasign.utils.OSTool;


/**
 * A Cryptographic Service Provider for the Microsoft Crypto API.
 *
 * @since 1.6
 */

public final class SunMSCAPI_MITyC extends Provider {

    private static final long serialVersionUID = -7526518963202322999L;

    private static final String INFO = "Sun's Microsoft Crypto API provider with MITyC modifications";
    /** Logger. */
	private static final Log LOG = LogFactory.getLog(SunMSCAPI_MITyC.class);

    static {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
            	String key = "sunmscapimityc";
            	try {
            		//String absKey = System.getProperty(ConstantsAPI.SYSTEM_PROPERTY_LIBRARY_PATH);
            		//absKey = absKey.substring(0, absKey.indexOf(File.pathSeparator)) + File.separator + key + ".dll";
            		String absKey = "";
            		try{
            			absKey = new File(OSTool.getTempDir()).getCanonicalPath() + File.separator + key + ".dll";
            		} catch (IOException e) {
            			absKey = new File(OSTool.getTempDir()).getAbsolutePath() + File.separator + key + ".dll";
            		}
            		if (LOG.isDebugEnabled()) {
            			LOG.debug("Cargando la librería: " + absKey);
            		}
            		if (new File(absKey).exists())
            			System.load(absKey);
            		else {
            			LOG.error("Unable to find " + absKey);
            			try {
            				System.loadLibrary(key); // Requiere que el path actual apunte al lugar apropiado
            			} catch (Exception e) {
            				throw new FileNotFoundException(key);
            			}
            		}
            	} catch (Throwable e) {
            		LOG.debug("No se pudo cargar la instancia de la librería sunmscapi: " + e.getMessage(), e);
        			try {
        				String random = new Long(System.currentTimeMillis()).toString();
        				CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_SUNMSCAPIMITYC_PROPERTIES, this.getClass().getClassLoader());
        				String dir = cft.copyFilesOS(null, ConstantsCert.CP_SUNMSCAPIMITYC, true, random);
        				String libPath = System.getProperty(ConstantsAPI.SYSTEM_PROPERTY_LIBRARY_PATH);
        				if (!libPath.contains(dir)) {
        					libPath = dir + File.pathSeparator + libPath;
        					System.setProperty(ConstantsAPI.SYSTEM_PROPERTY_LIBRARY_PATH, libPath);
        				}
        				System.loadLibrary(key + random);
                    } catch (Throwable e2) {
                    	LOG.debug("No se pudo cargar definitivamente la instancia de la librería sunmscapi: " + e2.getMessage(), e2);
                    }
            	}
                return null;
            }
        });
    }

    public SunMSCAPI_MITyC() {
        super("SunMSCAPI_MITyC", 1.71d, INFO);

        // if there is no security manager installed, put directly into
        // the provider. Otherwise, create a temporary map and use a
        // doPrivileged() call at the end to transfer the contents
        final Map<Object, Object> map = (System.getSecurityManager() == null)
                        ? (Map<Object, Object>)this : new HashMap<Object, Object>();

        /*
         * Secure random
         */
        map.put("SecureRandom.Windows-PRNG", "es.mityc.javasign.pkstore.mscapi.mityc.PRNG");

        /*
         * Key store
         */
        map.put("KeyStore.Windows-MY", "es.mityc.javasign.pkstore.mscapi.mityc.KeyStore$MY");
        map.put("KeyStore.Windows-ROOT", "es.mityc.javasign.pkstore.mscapi.mityc.KeyStore$ROOT");
        map.put("KeyStore.Windows-CA", "es.mityc.javasign.pkstore.mscapi.mityc.KeyStore$CA");
        map.put("KeyStore.Windows-LocalMachine-MY", "es.mityc.javasign.pkstore.mscapi.mityc.KeyStore$LocalMachineMY");
        map.put("KeyStore.Windows-LocalMachine-ROOT", "es.mityc.javasign.pkstore.mscapi.mityc.KeyStore$LocalMachineROOT");
        map.put("KeyStore.Windows-LocalMachine-CA", "es.mityc.javasign.pkstore.mscapi.mityc.KeyStore$LocalMachineCA");

        /*
         * Signature engines
         */
        map.put("Signature.SHA1withRSA",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSASignature$SHA1");
        map.put("Signature.SHA256withRSA",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSASignature$SHA256");
        map.put("Signature.SHA384withRSA",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSASignature$SHA384");
        map.put("Signature.SHA512withRSA",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSASignature$SHA512");
        map.put("Signature.MD5withRSA",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSASignature$MD5");
        map.put("Signature.MD2withRSA",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSASignature$MD2");

        /*
         * Algorithms aliases
         */
        map.put("Alg.Alias.Signature.RSA", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHA/RSA", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHA-1/RSA", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHA1/RSA", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHAwithRSA", "SHA1witRSA");
        map.put("Alg.Alias.Signature.RSAWithSHA1", "SHA1withRSA");
        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
        map.put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
        map.put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHA1withRSAEncryption", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHA1WithRSAEncryption", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHA1RSA", "SHA1withRSA");
        map.put("Alg.Alias.Signature.SHA1WITHRSAENCRYPTION", "SHA1withRSA");
        map.put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.1", "SHA1withRSA");
        map.put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.5", "SHA1withRSA");

        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256withRSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", "SHA256withRSA");
        map.put("Alg.Alias.Signature.SHA256withRSAEncryption", "SHA256withRSA");
        map.put("Alg.Alias.Signature.SHA256WithRSAEncryption", "SHA256withRSA");
        map.put("Alg.Alias.Signature.SHA256/RSA", "SHA256withRSA");
        map.put("Alg.Alias.Signature.SHA-256/RSA", "SHA256withRSA");
        map.put("Alg.Alias.Signature.SHA256RSA", "SHA256withRSA");
        map.put("Alg.Alias.Signature.SHA256WITHRSAENCRYPTION", "SHA256withRSA");

        map.put("Alg.Alias.Signature.SHA384withRSA", "SHA384withRSA");
        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384withRSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", "SHA384withRSA");
        map.put("Alg.Alias.Signature.SHA384withRSAEncryption", "SHA384withRSA");
        map.put("Alg.Alias.Signature.SHA384WithRSAEncryption", "SHA384withRSA");
        map.put("Alg.Alias.Signature.SHA384/RSA", "SHA384withRSA");
        map.put("Alg.Alias.Signature.SHA-384/RSA", "SHA384withRSA");
        map.put("Alg.Alias.Signature.SHA384RSA", "SHA384withRSA");
        map.put("Alg.Alias.Signature.SHA384WITHRSAENCRYPTION", "SHA384withRSA");

        map.put("Alg.Alias.Signature.SHA512withRSA", "SHA512withRSA");
        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512withRSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", "SHA512withRSA");
        map.put("Alg.Alias.Signature.SHA512withRSAEncryption", "SHA512withRSA");
        map.put("Alg.Alias.Signature.SHA512WithRSAEncryption", "SHA512withRSA");
        map.put("Alg.Alias.Signature.SHA512/RSA", "SHA512withRSA");
        map.put("Alg.Alias.Signature.SHA-512/RSA", "SHA512withRSA");
        map.put("Alg.Alias.Signature.SHA512RSA", "SHA512withRSA");
        map.put("Alg.Alias.Signature.SHA512WITHRSAENCRYPTION", "SHA512withRSA");
        
        // supported key classes
        map.put("Signature.SHA1withRSA SupportedKeyClasses",
            "es.mityc.javasign.pkstore.mscapi.mityc.Key");
        map.put("Signature.SHA256withRSA SupportedKeyClasses",
            "es.mityc.javasign.pkstore.mscapi.mityc.Key");
        map.put("Signature.SHA384withRSA SupportedKeyClasses",
            "es.mityc.javasign.pkstore.mscapi.mityc.Key");
        map.put("Signature.SHA512withRSA SupportedKeyClasses",
            "es.mityc.javasign.pkstore.mscapi.mityc.Key");
        map.put("Signature.MD5withRSA SupportedKeyClasses",
            "es.mityc.javasign.pkstore.mscapi.mityc.Key");
        map.put("Signature.MD2withRSA SupportedKeyClasses",
            "es.mityc.javasign.pkstore.mscapi.mityc.Key");
        map.put("Signature.NONEwithRSA SupportedKeyClasses",
            "es.mityc.javasign.pkstore.mscapi.mityc.Key");

        /*
         * Key Pair Generator engines
         */
        map.put("KeyPairGenerator.RSA",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSAKeyPairGenerator");
        map.put("KeyPairGenerator.RSA KeySize", "1024");

        /*
         * Cipher engines
         */
        map.put("Cipher.RSA", "es.mityc.javasign.pkstore.mscapi.mityc.RSACipher");
        map.put("Cipher.RSA/ECB/PKCS1Padding",
            "es.mityc.javasign.pkstore.mscapi.mityc.RSACipher");
        map.put("Cipher.RSA SupportedModes", "ECB");
        map.put("Cipher.RSA SupportedPaddings", "PKCS1PADDING");
        map.put("Cipher.RSA SupportedKeyClasses", "es.mityc.javasign.pkstore.mscapi.mityc.Key");

        if (map != this) {
            AccessController.doPrivileged(new PutAllAction(this, map));
        }
    }
}
