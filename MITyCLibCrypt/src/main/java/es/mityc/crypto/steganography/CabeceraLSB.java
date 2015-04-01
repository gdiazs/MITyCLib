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
package es.mityc.crypto.steganography;

import es.mityc.crypto.Utils;

/**
 * <p>Cabecera de datos que se anteponen a los datos a embeber durante un proceso esteganográfico.
 * Los datos que se incluyen son:
 * 	- Sello que marca el comienzo de información embebida.
 * 	- Un conjunto de bits que indican el tipo y formato del mensaje embebido
 * 	- El nombre del fichero embebido dentro de la imagen
 * </p>
 **/
public class CabeceraLSB {
	    /**
	     * Sello que indica el comienzo de los datos.
	     */
	    protected static final byte[] SELLO = "STEGANOGRAFIADA".getBytes();

	    /**
	     * Bytes reservados para indicar información relevante sobre el formato.
	     */
	    public static final int ESPACIO_RESERVADO = 8;

	    /**
	     * Longitud de los datos a embeber
	     */
	    private int datosLength = 0;

	    /**
	     * Cantidad de bits utilizados por pixel
	     */
	    private int bitsCanalUtilizados = 0;

	    /**
	     * Nombre del fichero a embeber
	     */
	    private byte[] fileName = null;

	    /**
	     * Instancia de configuración
	     */
	    private StegoConfig config = null;

	    /**
	     * <p>Constructor que crea una instancia con los parametros indicados.</p>
	     * @param datosLength Longitud de los datos a embeber
	     * @param bitsUtilizados Bits utilizados por canal
	     * @param fileName Nombre del fichero a embeber
	     * @param config
	     */
	    public CabeceraLSB(int datosLength, int bitsUtilizados, String fileName, StegoConfig config) {
	        this.datosLength = datosLength;
	        this.bitsCanalUtilizados = bitsUtilizados;
	        this.config = config;

	        if(fileName == null) {
	            this.fileName = "datos.bin".getBytes();
	        } else {
	            try {
	                this.fileName = fileName.getBytes("UTF-8");
	            } catch(Exception unEx) {
	                this.fileName = fileName.getBytes();
	            }
	        }
	    }

	    /**
	     * Constructor por defecto.
	     */
	    public CabeceraLSB() { }

	    /**
	     * <p>Calcula los bytes correspondientes a la cabecera actualmente configurada.</p>
	     * @return Los bytes a escribir de la cabecera Least Significant Bit
	     */
	    public byte[] getDatosCabecera(byte[] pass) {
	        byte[] out = null;
	        int stampLen = 0;
	        int currIndex = 0;

	        byte[] dataStamp = SELLO;
	        byte[] finalFileName = fileName;
	        if (pass != null && pass.length > 0) {
				dataStamp = Utils.obfuscate(new String(dataStamp), StegoUtils.hashPassLong(new String(pass))).getBytes();
				finalFileName = Utils.obfuscate(new String(fileName), StegoUtils.hashPassLong(new String(pass))).getBytes();
	        }
	        stampLen = SELLO.length;
	        out = new byte[stampLen + ESPACIO_RESERVADO + finalFileName.length];

	        System.arraycopy(dataStamp, 0, out, currIndex, stampLen);
	        currIndex += stampLen;

	        out[currIndex++] = (byte) ((datosLength & 0x000000FF));
	        out[currIndex++] = (byte) ((datosLength & 0x0000FF00) >> 8);
	        out[currIndex++] = (byte) ((datosLength & 0x00FF0000) >> 16);
	        out[currIndex++] = (byte) ((datosLength & 0xFF000000) >> 32);
	        out[currIndex++] = (byte) bitsCanalUtilizados;
	        out[currIndex++] = (byte) finalFileName.length;
	        out[currIndex++] = (byte) (config.isComprimir() ? 1 : 0);
	        out[currIndex++] = (byte) (config.isEncriptar() ? 1 : 0);

	        if(finalFileName.length > 0) {
	            System.arraycopy(finalFileName, 0, out, currIndex, finalFileName.length);
	            currIndex += finalFileName.length;
	        }

	        return out;
	    }

	    public int getBitsUtilizados() {
	        return bitsCanalUtilizados;
	    }

	    public void setBitsUtilizados(int bitsUtilizados) {
	        this.bitsCanalUtilizados = bitsUtilizados;
	    }

	    public int getLongitudDatos() {
	        return datosLength;
	    }

	    public String getFileName() {
	        String name = null;

	        try {
	            name = new String(fileName, "UTF-8");
	        } catch(Exception e) {
	            name = new String(fileName);
	        }
	        
	        return name;
	    }
	    
	    public void setFileName(byte[] fileName) {
	    	this.fileName = fileName;
	    }

	    /**
	     * <p>Devuelve la longitud actual de la cabecera.</p>
	     * @return
	     */
	    public int getLongitudCabecera() {
	        return SELLO.length + ESPACIO_RESERVADO + fileName.length;
	    }

	    /**
	     * Method to get the maximum possible size of the header
	     * @return Maximum possible header size
	     */
	    public static int getLongMaxCabecera() {
	        // El nombre de fichero se supone no mayor de 256 caracteres
	        return SELLO.length + ESPACIO_RESERVADO + 256;
	    }
	}