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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.tsa.ITimeStampValidator;
import es.mityc.javasign.tsa.TSValidationResult;
import es.mityc.javasign.tsa.TimeStampException;

/**
 * <p>Clase de utilidad para extraer el certificado firmante de un sello de tiempo.</p>
 */
public final class ExtractSigner {
	
	/** Logger. */
	private static final II18nManager i18n = I18nFactory.getI18nManager(ConstantsTSA.LIB_NAME);
	/** Tamaño máximo del buffer que admitirá los sellos de tiempo leidos. */
	private static final int BUFFER_SIZE = 32000;
	/** Nombre del fichero en el que se extraerá el fichero firmante del sello de tiempo. */
	private static final String CERT_FILE_NAME = "tsasigner.cer";
	
	/**
	 * <p>Constructor.</p>
	 */
	private ExtractSigner() {
	}

	/**
	 * <p>Extrae el certificado firmante del sello de tiempo indicado si se puede al fichero tsasigner.cer.</p>
	 * @param args fichero donde se encuentra el sello de tiempo
	 */
	public static void main(String[] args) {
		if ((args == null) || (args.length < 1)) {
			System.out.println("Modo de uso:");
			System.out.println("       ExtractSigner  <ts-file>");
			System.out.println("            <ts-file>     Fichero donde se encuentra en sello de tiempo en binario");
		} else {
			try {
				File file = new File(args[0]);
				if (file.exists()) {
					if (file.length() > BUFFER_SIZE) {
						System.out.println("El fichero indicado es demasiado grande");
					} else {
						FileInputStream fis = new FileInputStream(file);
						byte[] ts = new byte[(int) file.length()];
						fis.read(ts);
						fis.close();
						
						X509Certificate cert = null;
						try {
							ITimeStampValidator tsValidator = new TimeStampValidator();
							TSValidationResult data = tsValidator.validateTimeStamp(ts, ts);

							// Intenta extraer información de los certificados firmantes contenidos en el token
							TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(data.getTimeStampRawToken()));
							CertStore cs = timeStampToken.getCertificatesAndCRLs("Collection", null);
							Collection<? extends Certificate> certs = cs.getCertificates(null);
							if (certs.size() > 0) {
								Certificate cer = certs.iterator().next();
								if (cer instanceof X509Certificate) {
									cert = ((X509Certificate) cer);
								}
							}
						} catch (NoSuchAlgorithmException ex) {
							System.out.println(i18n.getLocalMessage(ConstantsTSA.I18N_VALIDATE_8, ex.getMessage()));
						} catch (NoSuchProviderException ex) {
							System.out.println(i18n.getLocalMessage(ConstantsTSA.I18N_VALIDATE_8, ex.getMessage()));
						} catch (CertStoreException ex) {
							System.out.println(i18n.getLocalMessage(ConstantsTSA.I18N_VALIDATE_8, ex.getMessage()));
						} catch (TimeStampException ex) {
							System.out.println("Error procesando el sello de tiempo: " + ex.getMessage());
						} catch (Exception ex) {
							System.out.println(i18n.getLocalMessage(ConstantsTSA.I18N_VALIDATE_8, ex.getMessage()));
						}

						if (cert != null) {
							FileOutputStream fos = new FileOutputStream(CERT_FILE_NAME, false);
							fos.write(cert.getEncoded());
							fos.flush();
							fos.close();
							System.out.println("Certificado extraido y disponible en " + CERT_FILE_NAME);
						} else {
							System.out.println("El sello de tiempo no incluye el certificado firmante");
						}
					}
				} else {
					System.out.println("El fichero indicado no existe");
				}
			} catch (FileNotFoundException ex) {
				System.out.println("El fichero indicado no existe");
			} catch (IOException ex) {
				System.out.println("Error leyendo el fichero con el sello de tiempo: " + ex.getMessage());
			} catch (CertificateEncodingException ex) {
				System.out.println("Error procesando formato de certificado firmante: " + ex.getMessage());
			}
		}
	}

}
