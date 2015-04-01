package es.mityc.javasign.utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertsUtil {
    public static boolean isRootCA(X509Certificate cert) {
        boolean ret = false;
        try {
            cert.verify(cert.getPublicKey());
            ret = true;
        } catch (InvalidKeyException e) {
        } catch (CertificateException e) {
        } catch (NoSuchAlgorithmException e) {
        } catch (NoSuchProviderException e) {
        } catch (SignatureException e) {
        }
        return ret;
    }

}
