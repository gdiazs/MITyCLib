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
package es.mityc.javasign.ts;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.tsa.ITimeStampValidator;
import es.mityc.javasign.tsa.TSValidationResult;
import es.mityc.javasign.tsa.TimeStampException;
import es.mityc.javasign.utils.Base64Coder;

/**
 * <p>Clase encargada de validar sellos de tiempo. Se corresponde con una
 * implementación de la interfaz ITimeStampValidator utilizando librerías de 
 * BouncyCastle y de acuerdo con la RFC 3161</p>
 * 
 */
public class TimeStampValidator implements ITimeStampValidator {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsTSA.LIB_NAME);
	/** Looger. */
	static Log log = LogFactory.getLog(TimeStampValidator.class.getName());
	
    /**
     * <p>Este método valida el Sello de Tiempo.</p>
     * @param sealedData fichero binario a validar
     * @param timeStamp El Sello de Tiempo se ingresa en formato binario
     * @return TSValidacion Información sobre el sello de tiempo validado
     * @throws TimeStampException Si ocurre algun error al validar el sello de tiempo
     */
    public TSValidationResult validateTimeStamp(final byte[] sealedData, final byte[] timeStamp)
    		 throws TimeStampException {
    	
        TimeStampToken tst = null;
        TSValidationResult tsv = new TSValidationResult();
        
        try {
        	tst = new TimeStampToken(new CMSSignedData(timeStamp));
		} catch (CMSException e) {
        	// Intenta obtenerlo como una timestamResp
        	try {
	        	TimeStampResponse tsr = new TimeStampResponse(timeStamp);
	        	tst = tsr.getTimeStampToken();
	        	if (tst == null) {
	    			throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_2));
	        	}
        	} catch (TSPException ex) {
    			throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_2));
        	} catch (IOException ex) {
    			throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_2));
        	}
		} catch (TSPException e) {
			throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_2), e);
		} catch (IOException e) {
            throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_2), e);
        }   	

		try {
            tsv.setTimeStamRawToken(tst.toCMSSignedData().getEncoded());
        } catch (IOException e) {
            throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.LIBRERIA_TSA_ERROR_2));
        }
		TimeStampTokenInfo tokenInfo = tst.getTimeStampInfo();

		MessageDigest resumen = TSPAlgoritmos.getDigest(tokenInfo.getMessageImprintAlgOID());
		if (resumen == null) {
            throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.I18N_VALIDATE_1, tokenInfo.getMessageImprintAlgOID()));
		}
		
		resumen.update(sealedData);
		if (MessageDigest.isEqual(resumen.digest(), tst.getTimeStampInfo().getMessageImprintDigest())) {
			SimpleDateFormat formato = new SimpleDateFormat(ConstantsTSA.FORMATO_FECHA);
			tsv.setFormattedDate(formato.format(tokenInfo.getGenTime()));
			tsv.setDate(tokenInfo.getGenTime());

			GenTimeAccuracy precision = tokenInfo.getGenTimeAccuracy();

			long accuLong = 0;
			if (precision != null) {
				accuLong =  (precision.getMicros()  * 1L)
					+ (precision.getMillis()  * 1000L)
					+ (precision.getSeconds() * 1000000L);
			}
			tsv.setTimeAccurracy(accuLong);	        

			tsv.setStamp(tokenInfo.getSerialNumber());
			tsv.setSignDigest(new String(Base64Coder.encode(tokenInfo.getMessageImprintDigest())));
			tsv.setStampAlg(tokenInfo.getMessageImprintAlgOID());

			// Obtiene el nombre del firmante del sello
			
			// Intenta extraer información de los certificados firmantes contenidos en el token
			X500Principal signer = null;
			GeneralName gn =  tokenInfo.getTsa();
			if (gn != null) {
				// Si es del tipo X500 lo transforma
				if (gn.getTagNo() == 4) {
					try {
                        signer = new X500Principal(X509Name.getInstance(gn.getName()).getEncoded());
                    } catch (IOException e) {
                    }
				}
			}

			try {
				CertStore cs = tst.getCertificatesAndCRLs("Collection", null);
				Collection<? extends Certificate> certs = cs.getCertificates(null);
				if (certs.size() > 0) {
					tsv.setCadena(CertificateFactory.getInstance("X.509").generateCertPath(new ArrayList<Certificate>(certs)));
					// si el token no indica el nombre del firmante, intenta extraerlo por el certificado
					Certificate cert = certs.iterator().next();
					if (signer == null && cert instanceof X509Certificate) {
						signer = ((X509Certificate) cert).getSubjectX500Principal();
					}
				}
			} catch (Exception e) {
				log.error(e);
			}
			tsv.setTimeStampIssuer(signer);

		} else {
			throw new TimeStampException(I18N.getLocalMessage(ConstantsTSA.I18N_VALIDATE_2));
		}
		return tsv;
    }
}
