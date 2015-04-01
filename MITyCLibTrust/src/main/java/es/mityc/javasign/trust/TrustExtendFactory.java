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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Extiende la factoría básica para permitir instanciar validadores específicos.</p>
 * 
 * <p>Los validadores de confianza específicos que gestiona esta factoría son:
 * <ul>
 * 	<li>Validador de cadenas de certificados</li>
 * 	<li>Validador de CRLs</li>
 * 	<li>Validador de respuestas OCSP</li>
 * 	<li>Validador de sellos de tiempo TSA</li>
 * </ul></p>
 * 
 * <p>Reutiliza la parametrización de la factoría básica (a través de ficheros de configuración <code>trust.properties</code>) incluyendo un sufijo específico
 * en función del tipo de validador buscado:
 * <ul>
 * 	<li><b>.SignCerts</b>: para validador de cadenas de certificados</li>
 * 	<li><b>.CRLEmisor</b>: para validador de CRLs</li>
 * 	<li><b>.OCSPProducer</b>: para validador de respuestas OCSP</li>
 * 	<li><b>.TSProducer</b>: para validador de sellos de tiempo TSA</li>
 * 	<li><b>.All</b>: para validador que cumple con los anteriores tipos</li>
 * </ul></p>
 * 
 */
public class TrustExtendFactory extends TrustFactory {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(TrustExtendFactory.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsTrust.LIB_NAME);

	/** Sufijo para managers de confianza de certificados de firma. */
	private static final String TRUSTER_PROPS_SIGNCERTS = ".SignCerts";
	/** Sufijo para managers de confianza de emisores de CRLs. */
	private static final String TRUSTER_PROPS_CRLS 	  	= ".CRLEmisor";
	/** Sufijo para managers de confianza de emisores de respuestas OCSP. */
	private static final String TRUSTER_PROPS_OCSP 	  	= ".OCSPProducer";
	/** Sufijo para managers de confianza de emisores de sellos de tiempo. */
	private static final String TRUSTER_PROPS_TSA 	  	= ".TSProducer";
	/** Sufijo para managers de confianza genéricos (que cubren todos los anteriores tipos). */
	private static final String TRUSTER_PROPS_ALL 	  	= ".All";

	/**
	 * Constructor.
	 */
	protected TrustExtendFactory() {
		super();
	}
	
	/**
	 * Una factoría que quiera sustituir a esta deberá implementar este método devolviendo una instancia de sí misma.
	 * @return Nueva instancia de la factoría extendida
	 */
	protected static TrustFactory newInstance() {
		return new TrustExtendFactory();
	}
	
	/**
	 * Devuelve el validador de confianza de certificados asociado a la clave indicada. Funciona como una factory que instancia un 
	 * nuevo validador en cada llamada.
	 *  
	 * @param prefix Grupo de claves bajo la que se encuentra el validador
	 * @return Una instancia del validador de confianza de certificados asociado o <code>null</code> si no hay ninguno asociado o no 
	 * 		   se puede instanciar.
	 * 
	 * TODO: permitir funcionar a la factory en varios modos de trabajo (instanciador, cache, singleton, instanciador propio del validador)
	 */
	public ITrustSignCerts getSignCertsTruster(final String prefix) {
		String clave = (prefix != null) ? (prefix + TRUSTER_PROPS_SIGNCERTS) : TRUSTER_PROPS_SIGNCERTS;
		TrustAbstract res = getTrusterSuper(clave);
		if (res != null) {
			if (res instanceof ITrustSignCerts) {
				return (ITrustSignCerts) res;
			} else {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_1));
			}
		}
		return null;
	}
	
	/**
	 * Devuelve el validador de confianza de emisores de CRLs asociado a la clave indicada. Funciona como una factory que instancia un 
	 * nuevo validador en cada llamada.
	 *  
	 * @param prefix Grupo de claves bajo la que se encuentra el validador
	 * @return Una instancia del validador de confianza de emisores de CRLs asociado o <code>null</code> si no hay ninguno asociado o no 
	 * 		   se puede instanciar.
	 */
	public ITrustCRLEmisor getCRLTruster(final String prefix) {
		String clave = (prefix != null) ? (prefix + TRUSTER_PROPS_CRLS) : TRUSTER_PROPS_CRLS;
		TrustAbstract res = getTrusterSuper(clave);
		if (res != null) {
			if (res instanceof ITrustCRLEmisor) {
				return (ITrustCRLEmisor) res;
			} else {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_2));
			}
		}
		return null;
	}

	/**
	 * Devuelve el validador de confianza de respuestas OCSP asociado a la clave indicada. Funciona como una factory que instancia un 
	 * nuevo validador en cada llamada.
	 *  
	 * @param prefix Grupo de claves bajo la que se encuentra el validador
	 * @return Una instancia del validador de confianza de respuestas OCSP asociado o <code>null</code> si no hay ninguno asociado o no 
	 * 		   se puede instanciar.
	 */
	public ITrustOCSPProducer getOCSPTruster(final String prefix) {
		String clave = (prefix != null) ? (prefix + TRUSTER_PROPS_OCSP) : TRUSTER_PROPS_OCSP;
		TrustAbstract res = getTrusterSuper(clave);
		if (res != null) {
			if (res instanceof ITrustOCSPProducer) {
				return (ITrustOCSPProducer) res;
			} else {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_3));
			}
		}
		return null;
	}

	/**
	 * <p>Devuelve el validador de confianza de sellos de tiempo asociado a la clave indicada. Funciona como una factory que instancia un 
	 * nuevo validador en cada llamada.</p>
	 *  
	 * @param prefix Grupo de claves bajo la que se encuentra el validador
	 * @return Una instancia del validador de confianza de sellos de tiempo asociado o <code>null</code> si no hay ninguno asociado o no 
	 * 		   se puede instanciar.
	 */
	public ITrustTSProducer getTSATruster(final String prefix) {
		String clave = (prefix != null) ? (prefix + TRUSTER_PROPS_TSA) : TRUSTER_PROPS_TSA;
		TrustAbstract res = getTrusterSuper(clave);
		if (res != null) {
			if (res instanceof ITrustTSProducer) {
				return (ITrustTSProducer) res;
			} else {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_4));
			}
		}
		return null;
	}
	
	/**
	 * <p>Devuelve el truster indicado por la clase padre.</p>
	 * @param key Clave que identifica el truster
	 * @return Truster asociado a la clave
	 */
	public TrustAbstract getTrusterSuper(final String key) {
		return super.getTruster(key);
	}
	
	/**
	 * <p>Devuelve el validador de confianza genérico asociado a la clave indicada. Funciona como una factoría que instancia un nuevo validador
	 * en cada llamada.</p>
	 * @param key Grupo de claves bajo la que se encuentra el validador
	 * @return Una instancia del validador de confianza genérico asociado o <code>null</code> si no hay ninguno asociado o no 
	 * 		   se puede instanciar.
	 * @see es.mityc.javasign.trust.TrustFactory#getTruster(java.lang.String)
	 */
	@Override
	public TrustAbstract getTruster(final String key) {
		String clave = (key != null) ? (key + TRUSTER_PROPS_ALL) : TRUSTER_PROPS_ALL;
		TrustAbstract res = getTrusterSuper(clave);
		if (res != null) {
			if (res instanceof TrustAdapter) {
				return (TrustAdapter) res;
			} else {
				LOG.error(I18N.getLocalMessage(ConstantsTrust.I18N_TRUST_4));
			}
		}
		return null;
	}
}
