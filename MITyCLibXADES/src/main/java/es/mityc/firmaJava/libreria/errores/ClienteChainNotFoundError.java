/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES".
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

package es.mityc.firmaJava.libreria.errores;

public class ClienteChainNotFoundError extends ClienteError {
    
    private String tipoCertificado = null;
    
    /**
     * Crea una nueva instancia de ClienteChainNotFoundError sin el mensaje de detalle
     */
    public ClienteChainNotFoundError() {
    }
    
    /**
     * Crea una nueva instancia de ClienteChainNotFoundError con el mensaje de detalle
     * @param msg Detalle del mensaje
     */
    public ClienteChainNotFoundError(String msg)
    {
        super(msg);
    }

    /**
     * Crea una nueva instancia de ClienteChainNotFoundError con el mensaje de detalle y el tipo de certificado
     * @param msg Detalle del mensaje
     */
    public ClienteChainNotFoundError(String msg, String tipoCertificado)
    {
        super(msg);
        this.tipoCertificado = tipoCertificado;
    }

    /**
     * Crea una nueva instancia de ClienteChainNotFoundError
     * @param msg Excepción a propagar
     */
    public ClienteChainNotFoundError(Throwable msg)
    {
        super(msg);
    }
    
    public ClienteChainNotFoundError(String msg, Throwable th) {
        super(msg, th);
    }

    /**
     * Crea una nueva instancia de ClienteChainNotFoundError
     * @param msg Excepción a propagar
     */
    public ClienteChainNotFoundError(Throwable msg, String tipoCertificado)
    {
        super(msg);
        this.tipoCertificado = tipoCertificado;
    }

    public ClienteChainNotFoundError(String msg, Throwable th, String tipoCertificado) {
        super(msg, th);
        this.tipoCertificado = tipoCertificado;
    }

    public String getTipoCertificado() {
        return tipoCertificado;
    }     
}
