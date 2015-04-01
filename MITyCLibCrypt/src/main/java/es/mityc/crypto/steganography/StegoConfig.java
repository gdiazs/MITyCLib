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


/**
 * <p>Estructura de datos que implementa la configuración de un proceso esteganográfico random lsb.</p>
 */
public class StegoConfig {
    
    /**
     * Flag para comprimir. Con <code>true</code> se realiza un ZIP sobre los datos a embeber.
     */
    private boolean comprimir = true;

    /**
     * Flag para encriptar. Con <code>true</code> se realiza un TripleDES en los datos a embeber.
     */
    private boolean encriptar = false;

    /**
     * Password
     */
    private String password = null;
    
    /**
     * Máximo numero de bits a utilizar por canal de color. Se debe tener en cuenta que cuanto más 
     * significante es el bit de color a utilizar, mayor es la distorsión en la imagen. 
     */
    private int maxBitsCanal = 3;

    /**
     * Default Constructor (with default values for configuration items)
     */
    public StegoConfig() { }

    /**
     * Get method for configuration item - useCompression
     * @return useCompression
     */
    public boolean isComprimir() {
        return comprimir;
    }

    /**
     * Flag para comprimi. Con <code>true</code> se realiza un ZIP en los datos a embeber.
     */
    public void setComprimir(boolean comprimir) {
        this.comprimir = comprimir;
    }

    public boolean isEncriptar() {
        return encriptar;
    }

    /**
     * Flag para encriptar. Con <code>true</code> se realiza un TripleDES en los datos a embeber.
     */
    public void setEncriptar(boolean encriptar) {
        this.encriptar = encriptar;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    public int getMaxBitsPorCanal() {
        return maxBitsCanal;
    }

    public void setMaxBitsPorCanal(int maxBitsUsedPerChannel) {
        this.maxBitsCanal = maxBitsUsedPerChannel;
    }
}
