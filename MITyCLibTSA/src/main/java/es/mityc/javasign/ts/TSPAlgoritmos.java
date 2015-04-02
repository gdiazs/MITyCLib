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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tsp.TSPAlgorithms;

/**
 * <p>Clase con los algortimos de codificacion permitidos
 * para el sellado de tiempo.</p>
 * 
 */
public class TSPAlgoritmos {
	
	/**
	 * Tipo de algoritmo SHA1
	 */
	public static final String SHA1 = "SHA-1";
	/**
	 * Tipo de algoritmo SHA2
	 */
	public static final String SHA2 = "SHA-2";
	/**
	 * Tipo de algoritmo SHA224
	 */
	public static final String SHA224 = "SHA-224";
	/**
	 * Tipo de algoritmo SHA256
	 */
	public static final String SHA256 = "SHA-256";
	/**
	 * Tipo de algoritmo SHA384
	 */
	public static final String SHA384 = "SHA-384";
	/**
	 * Tipo de algoritmo SHA512
	 */
	public static final String SHA512 = "SHA-512";
	
	public static final String MD5 = "MD5";
	
	/**
	 * <p>Devuelve una lista de algoritmos de sellado de tiempo aceptados.</p>
	 * @return Lista de algoritmos
	 */
	public static Set<String> getPermitidos() {
		Set<String> permitidos = new HashSet<String>(Arrays.asList(getValoresPermitidos()));
		
		return permitidos;
	}
	
	/**
	 * <p>Resuelve el nombre del algortimo de digest a partir del OID.</p>
	 * @param oid OID del algortimo buscado
	 * @return Nopmbre del algoritmo, o el OID proveído en caso de no poder ser resuelto
	 */
	public static String getAlgName(final String oid) {
		if (TSPAlgorithms.SHA1.equals(oid)) {
			return SHA1;
		} else if (TSPAlgorithms.SHA256.equals(oid)) {
			return SHA2;
		} else if (TSPAlgorithms.SHA224.equals(oid)) {
			return SHA224;
		} else if (TSPAlgorithms.SHA256.equals(oid)) {
			return SHA256;
		} else if (TSPAlgorithms.SHA384.equals(oid)) {
			return SHA384;
		} else if (TSPAlgorithms.SHA512.equals(oid)) {
			return SHA512;
		}
		
		return oid;
	}

	/**
	 * <p>Resuelve el OID del algoritmo de Digest a partir del nombre.</p>
	 * @param algoritmo Nombre del algoritmo buscado
	 * @return El OID del algoritmo, o <code>null</code> si no pudo resolverse
	 */
	public static String getOID(final String algoritmo) {
		Set<String> permitidos = new HashSet<String>(Arrays.asList(getValoresPermitidos()));
		
		if (permitidos.contains(algoritmo)) {
			if (SHA1.equals(algoritmo)) {
				return TSPAlgorithms.SHA1;
			} else if (SHA2.equals(algoritmo)) {
				return TSPAlgorithms.SHA256;
			} else if (SHA224.equals(algoritmo)) {
				return TSPAlgorithms.SHA224;
			} else if (SHA256.equals(algoritmo)) {
				return TSPAlgorithms.SHA256;
			} else if (SHA384.equals(algoritmo)) {
				return TSPAlgorithms.SHA384;
			} else if (SHA512.equals(algoritmo)) {
				return TSPAlgorithms.SHA512;
			}
		}
		
		return null;
	}
	
	/** <p>Correspondencia entre nombre de algoritmo y OID.</p> */
	private static HashMap<String, String> algoritmosVSoids = null;
	static {
		algoritmosVSoids = new HashMap<String, String>();
		
		algoritmosVSoids.put(TSPAlgorithms.SHA1, SHA1);
		algoritmosVSoids.put(TSPAlgorithms.SHA224, SHA224);
		algoritmosVSoids.put(TSPAlgorithms.SHA256, SHA256);
		algoritmosVSoids.put(TSPAlgorithms.SHA384, SHA384);
		algoritmosVSoids.put(TSPAlgorithms.SHA512, SHA512);
		algoritmosVSoids.put(TSPAlgorithms.MD5, MD5);
	}
	
	/**
	 * Devuelve el algoritmo de digest asociado con el OID de algoritmo de digest indicado.
	 * 
	 * @param oid Cadena de texto con el OID del algoritmo
	 * @return MessageDigest del OID indicado, o <code>null</code> si no se dispone de un
	 * 		   algoritmo de digest asociado al OID indicado.
	 */
	public static MessageDigest getDigest(final String oid) {
		String algName = algoritmosVSoids.get(oid);
		if (algName == null) {
			return null;
		}
		try {
			MessageDigest md = MessageDigest.getInstance(algName);
			return md;
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}
	
	/**
	 * <p>Devuelve un array con los valores permitidos de algoritmos de Digest.</p>
	 * @return Array de Strings con os valores permitidos
	 */
	public static String[] getValoresPermitidos() {
		String[] valoresPermitidos = new String[6];
		valoresPermitidos[0] = SHA1;
		valoresPermitidos[1] = SHA2;
		valoresPermitidos[2] = SHA224;
		valoresPermitidos[3] = SHA256;
		valoresPermitidos[4] = SHA384;
		valoresPermitidos[5] = SHA512;
		
		return valoresPermitidos;
	}	
}
