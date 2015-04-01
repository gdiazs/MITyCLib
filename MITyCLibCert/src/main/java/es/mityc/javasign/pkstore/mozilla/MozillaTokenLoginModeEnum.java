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
package es.mityc.javasign.pkstore.mozilla;

/**
 * <p>Enumerado de los modos de funcionamiento del login de tokens en Mozilla.</p>
 */
public enum MozillaTokenLoginModeEnum {
	/** Sólo hay que logarse en el token la primera vez que se accede a el. */
    ONE_TIME (0),
    /** Hay que logarse en el token cada # tiempo. */
    TIMEOUT (1),
    /** hay que logarse en el token cada vez que se intenta acceder a el. */
    EVERY_TIME (2);
    
    /** Valor numérico equivalente al modo del enumerado .*/
    private int emode = 0;
    
    /**
     * <p>Construye un modo del enumerado relacionándolo con un valor numérico.</p>
     * @param mode equivalente numérico al modo según Mozilla
     */
    private MozillaTokenLoginModeEnum(int mode) {
    	emode = mode;
    }
    
    /**
     * <p>Indica cuál es el modo de funcionamiento por defecto.</p>
     * <p>El modo por defecto es: logarse sólo la primera vez que se utiliza.</p>
     * @return modo de funcionamiento por defecto
     */
    public static MozillaTokenLoginModeEnum getDefault() {
    	return ONE_TIME;
    }
    
    /**
     * <p>Devuelve el enumerado de funcionamiento en función de un valor numérico.</p>
     * <p>La correspondencia es:
     * 	<dd>0</dd><dt>ONE_TIME</dt>
     * 	<dd>1</dd><dt>TIMEOUT</dt>
     * 	<dd>2</dd><dt>EVERY_TIME</dt>
     * </p>
     * 
     * @param mode valor numérico de mozilla
     * @return enumerado relacionado
     */
    public static MozillaTokenLoginModeEnum getLoginMode(final int mode) {
    	MozillaTokenLoginModeEnum emod;
    	switch (mode) {
	    	case 0:
	    		emod = ONE_TIME;
	    		break;
	    	case 1:
	    		emod = TIMEOUT;
	    		break;
	    	case 2:
	    		emod = EVERY_TIME;
	    		break;
	    	default:
	    		emod = ONE_TIME;
    	}
    	return emod;
    }

    /**
     * <p>Devuelve el valor numérico según Mozilla equivalente al enumerado.</p>
     * @return valor numérico del modo
     */
    public int getInteger() {
    	return emode;
    }
}
