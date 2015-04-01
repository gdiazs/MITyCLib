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
package es.mityc.javasign.certificate;

import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.certificate.IOCSPCertStatus.TYPE_RESPONDER;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.utils.Base64Coder;

/**
 * <p>Contiene los datos que identifican a un OCSP Responder.</p>
 * 
 */
public abstract class OCSPResponderID {

	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsAPI.LIB_NAME);
	
	/** Indica el tipo de identificador del responder. */
	protected TYPE_RESPONDER typeResponderID = null;

	/**
	 * <p>Identifica a un OCSP responder mediante un nombre (X500 Name).</p>
	 */
	public static class OCSPResponderIDName extends OCSPResponderID {
		/** Nombre del responder. */
		private X500Principal nameResponder = null;
		/**
		 * <p>Construye un identificador de OCSP Responder por nombre.</p>
		 * @param name Nombre del respodner
		 */
		protected OCSPResponderIDName(X500Principal name) {
			super(TYPE_RESPONDER.BY_NAME);
			this.nameResponder = name;
		}
		/**
		 * <p>Compara los campos internos de la respuesta.</p>
		 * @param arg0 Objeto con el que comparar si son el mismo OCSP Responder
		 * @return <code>true</code> si es un responder con el mismo X500Name, <code>false</code> en otro caso
		 * @see es.mityc.javasign.certificate.OCSPResponderID#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(final Object arg0) {
			if (arg0 instanceof OCSPResponderIDName) {
				if (nameResponder != null) {
					return nameResponder.equals(((OCSPResponderIDName) arg0).nameResponder);
				} else {
					return (((OCSPResponderIDName) arg0).nameResponder == null);
				}
			} else if (arg0 instanceof OCSPResponderIDUnknown) {
				return arg0.equals(this);
			}
			return false;
		}
		/**
		 * <p>Devuelve el hashCode del nombre del responder.</p>
		 * @return hashCode
		 * @see java.lang.Object#hashCode()
		 */
		@Override
		public int hashCode() {
			return (nameResponder != null) ? nameResponder.hashCode() : super.hashCode();
		}
		/**
		 * <p>Devuelve un objeto X500Principal como dato de identificación.</p>
		 * @return X500Principal con el nombre del responder
		 * @see es.mityc.javasign.certificate.OCSPResponderID#getIdentifierData()
		 */
		@Override
		public Object getIdentifierData() {
			return nameResponder;
		}
		/**
		 * <p>Devuelve array de bytes de texto del responder.</p>
		 * @return identificador
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return super.toString() + I18N.getLocalMessage(ConstantsAPI.I18N_CERT_5, (nameResponder != null) ? nameResponder.getName() : "null");
		}
	}
	
	/**
	 * <p>Identifica a un OCSP responder mediante el hash de su clave privada.</p>
	 */
	public static class OCSPResponderIDHash extends OCSPResponderID {
		/** Hash de la clave pública del responder. */
		private byte[] hashPK = null;
		/**
		 * <p>Construye un identificador de OCSP Responder por hash.</p>
		 * @param hash hash de la clave pública del responder
		 */
		protected OCSPResponderIDHash(byte[] hash) {
			super(TYPE_RESPONDER.BY_KEY);
			this.hashPK = hash;
		}
		/**
		 * <p>Compara los campos internos de la respuesta.</p>
		 * @param arg0 Objeto con el que comparar si son el mismo OCSP Responder
		 * @return <code>true</code> si es un responder con el mismo hash, <code>false</code> en otro caso
		 * @see es.mityc.javasign.certificate.OCSPResponderID#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(final Object arg0) {
			if (arg0 instanceof OCSPResponderIDHash) {
				return Arrays.equals(hashPK, ((OCSPResponderIDHash) arg0).hashPK);
			} else if (arg0 instanceof OCSPResponderIDUnknown) {
				return arg0.equals(this);
			}
			return false;
		}
		/**
		 * <p>Devuelve como hashCode el del hash de la clave privada.</p>
		 * @return hashCode
		 * @see java.lang.Object#hashCode()
		 */
		@Override
		public int hashCode() {
			if (hashPK != null) {
				return hashPK.hashCode();
			} else {
				return super.hashCode();
			}
		}
		/**
		 * <p>Devuelve un objeto byte[] como dato de identificación.</p>
		 * @return byte[] con el hash de la clave pública del responder
		 * @see es.mityc.javasign.certificate.OCSPResponderID#getIdentifierData()
		 */
		@Override
		public Object getIdentifierData() {
			return hashPK;
		}
		/**
		 * <p>Devuelve array de bytes de texto del responder.</p>
		 * @return identificador
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return super.toString() + I18N.getLocalMessage(ConstantsAPI.I18N_CERT_5, Arrays.toString(hashPK));
		}
	}
	
	/**
	 * <p>Identifica a un OCSP responder mediante una clave.</p>
	 * @author  Ministerio de Industria, Turismo y Comercio
	 * @version 1.0
	 */
	public static class OCSPResponderIDUnknown extends OCSPResponderID {
		/** Identifica al responder mediante una cadena. */
		private String identifier = null;
		/**
		 * <p>Construye un identificador de OCSP Responder desconocido.</p>
		 * @param id identificador en textual del responder
		 */
		public OCSPResponderIDUnknown(String id) {
			super(null);
			this.identifier = new String(id);
		}
		/**
		 * <p>Compara los campos internos de la respuesta.</p>
		 * <p>Las comparaciones realizadas dependen del tipo de objeto contra el que se compara:
		 * 	<ul>
		 * 		<li>OCSPResponderIDName: convierte la cadena identificativa en un X500 y los compara</li>
		 * 		<li>OCSPResponderIDHash: convierte la cadena identificativa en binario (suponiéndola bas64binary) y los compara</li>
		 * 		<li>OCSPResponderIDUnknown: compara los identificadores</li>
		 * 	</ul>
		 * </p>
		 * @param arg0 Objeto con el que comparar si son el mismo OCSP Responder
		 * @return <code>true</code> si es un responder con la misma identificación, <code>false</code> en otro caso
		 * @see es.mityc.javasign.certificate.OCSPResponderID#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(final Object arg0) {
			if (arg0 instanceof OCSPResponderIDName) {
				if (identifier != null) {
					try {
						X500Principal prin = new X500Principal(identifier);
						return (prin.equals(((OCSPResponderIDName) arg0).nameResponder));
					} catch (IllegalArgumentException ex) {
						return false;
					}
				} else {
					return (((OCSPResponderIDName) arg0).nameResponder == null);
				}
			} else if (arg0 instanceof OCSPResponderIDHash) {
				if (identifier != null) {
					try {
						byte[] hash = Base64Coder.decode(identifier);
						return Arrays.equals(hash, ((OCSPResponderIDHash) arg0).hashPK);
					} catch (IllegalArgumentException ex) {
						return false;
					}
				} else {
					return (((OCSPResponderIDHash) arg0).hashPK == null);
				}
			} else if (arg0 instanceof OCSPResponderIDUnknown) {
				if (identifier != null) {
					return identifier.equals(((OCSPResponderIDUnknown) arg0).identifier);
				} else {
					return (((OCSPResponderIDUnknown) arg0).identifier == null);
				}
			}
			return false;
		}
		/**
		 * <p>Devuelve el hashCode de la cadena identificadora.</p>
		 * @return hashCode
		 * @see java.lang.Object#hashCode()
		 */
		@Override
		public int hashCode() {
			return (identifier != null) ? identifier.hashCode() : super.hashCode();
		}
		/**
		 * <p>Devuelve un objeto String como dato de identificación.</p>
		 * @return String con el identificador del responder
		 * @see es.mityc.javasign.certificate.OCSPResponderID#getIdentifierData()
		 */
		@Override
		public Object getIdentifierData() {
			return identifier;
		}
		/**
		 * <p>Devuelve el identificador de texto del responder.</p>
		 * @return identificador
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return super.toString()  + I18N.getLocalMessage(ConstantsAPI.I18N_CERT_5, identifier);
		}
	}
	
	/**
	 * <p>Construye una instancia del objeto indicando su tipo.</p>
	 * @param type tipo de responder
	 */
	protected OCSPResponderID(TYPE_RESPONDER type) {
		typeResponderID = type;
	}
	
	/**
	 * <p>Crea un identificado de OCSP responder por nombre.</p>
	 * @param name Nombre X500 del responder
	 * @return identificador
	 */
	public static OCSPResponderID getOCSPResponderID(final X500Principal name) {
		return new OCSPResponderIDName(name);
	}
	
	/**
	 * <p>Crea un identificador de OCSP responder por hash de clave pública.</p>
	 * @param data hash de la clave pública del responder
	 * @return identificador
	 */
	public static OCSPResponderID getOCSPResponderID(final byte[] data) {
		return new OCSPResponderIDHash(data.clone());
	}
	
	/**
	 * <p>Crea un identificador de OCSP responder.</p>
	 * @param id cadena identificativa del responder
	 * @return identificador
	 */
	public static OCSPResponderID getOCSPresponderID(final String id) {
		return new OCSPResponderIDUnknown(id);
	}
	
	/**
	 * <p>Indica el tipo de responder de este objeto.</p>
	 * <p>Si se desconoce el tipo de responder se devuelve <code>null</code>.</p>
	 * @return Tipo de responder de este objeto, <code>null</code> si es desconocido
	 */
	public TYPE_RESPONDER getTypeResponderID() {
		return typeResponderID;
	}
	
	/**
	 * <p>Devuelve los datos de identificación.</p>
	 * @return Instancia que contiene datos de identificación
	 */
	public abstract Object getIdentifierData();
	
	/**
	 * <p>Cadena descriptiva del OCSPResponder.</p>
	 * @return tipo de responder
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String res = null;
		if (typeResponderID != null) {
			switch (typeResponderID) {
				case BY_NAME:
					res = I18N.getLocalMessage(ConstantsAPI.I18N_CERT_2);
					break;
				case BY_KEY:
				default:
					res = I18N.getLocalMessage(ConstantsAPI.I18N_CERT_3);
			}
		} else {
			res = I18N.getLocalMessage(ConstantsAPI.I18N_CERT_4);
		}
		return I18N.getLocalMessage(ConstantsAPI.I18N_CERT_1, res);
	}
}
