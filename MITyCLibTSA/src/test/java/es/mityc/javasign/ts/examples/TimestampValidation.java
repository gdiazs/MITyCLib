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
package es.mityc.javasign.ts.examples;

import org.bouncycastle.util.encoders.Base64;

import es.mityc.javasign.ts.TimeStampValidator;
import es.mityc.javasign.tsa.ITimeStampValidator;
import es.mityc.javasign.tsa.TSValidationResult;
import es.mityc.javasign.tsa.TimeStampException;

/**
 * <p>
 * Ejemplo que muestra como realizar validaciones de sellos de tiempo a partir
 * de los datos originales y los tokens.
 * </p>
 * <p>
 * Para simplificar el código del programa se usan una serie constantes para su
 * configuración. Las constantes usadas, y que pueden ser modificadas según las
 * necesidades específicas, son las siguientes:
 * </p>
 * <ul>
 * <li><code>DATA1</code></li>
 * <li><code>TOKEN_DATA1</code></li>
 * <li><code>DATA2</code></li>
 * <li><code>TOKEN_DATA2</code></li>
 * </ul>
 * <p>
 * El ejemplo, tal y como se distribuye, realiza una validación cruzada de los
 * conjuntos de datos con los tokens de sellado de tiempo, de tal forma que se
 * realizan 4 validaciones:
 * </p>
 * <ul>
 * <li><code>DATA1</code> con <code>TOKEN_DATA1</code>, esperando un resultado
 * correcto</li>
 * <li><code>DATA1</code> con <code>TOKEN_DATA2</code>, esperando un resultado
 * erróneo</li>
 * <li><code>DATA2</code> con <code>TOKEN_DATA1</code>, esperando un resultado
 * erróneo</li>
 * <li><code>DATA2</code> con <code>TOKEN_DATA2</code>, esperando un resultado
 * correcto</li>
 * </ul>
 * 
 */
public class TimestampValidation {

    /**
     * <p>
     * Conjunto 1 de datos codificados en base64.
     * </p>
     */
    public static final String DATA1 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /**
     * <p>
     * Token de sellado de tiempo codificado en base64 asociado a los datos del
     * conjunto 1.
     * </p>
     */
    public static final String TOKEN_DATA1 = 
        "MIIF6QYJKoZIhvcNAQcCoIIF2jCCBdYCAQMxDzANBglghkgBZQMEAgEFADBSBgsqhkiG9w0BCRAB"+
        "BKBDBEEwPwIBAQYDKgMEMCEwCQYFKw4DAhoFAAQUXD64AGZCAAK8Pcx8pKtu+tftSuUCAQEYDzIw"+
        "MTAwMTIwMTA1MDE3WqCCA6kwggOlMIIDDqADAgECAgIAgjANBgkqhkiG9w0BAQUFADByMQswCQYD"+
        "VQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxDjAMBgNVBAoTBU1JVHlD"+
        "MRswGQYDVQQLExJNSVR5QyBETkllIFBydWViYXMxFDASBgNVBAMTC0NBIHVzdWFyaW9zMB4XDTA5"+
        "MDgyNDA4NDYyNVoXDTEwMDgyNDA4NDYyNVowgYExCzAJBgNVBAYTAkVTMQ8wDQYDVQQIEwZNYWRy"+
        "aWQxDzANBgNVBAcTBk1hZHJpZDEOMAwGA1UEChMFTUlUeUMxGzAZBgNVBAsTEk1JVHlDIEROSWUg"+
        "UHJ1ZWJhczEjMCEGA1UEAxMaU2VydmljaW8gZGUgcHJ1ZWJhcyBkZSBUU0EwgZ8wDQYJKoZIhvcN"+
        "AQEBBQADgY0AMIGJAoGBAKTu0i/a5dNzNDzbm/PAEwVbVCCyrZTQd2HBuqlU7i0bXxdYoeX4KLFI"+
        "9xf0CrL6gDEtAK6d5jApUuBjM0NN2BYlgungF37wHIUP7P9kfwcrA0LostONCDrNWB2P4Lf/MvL6"+
        "Ch5HUgsIbuqImYCjgYpynHKCMNIPoPSNOVvH+fZ/AgMBAAGjggE4MIIBNDAJBgNVHRMEAjAAMAsG"+
        "A1UdDwQEAwIDyDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUJasyiJe3kzrgc2dN"+
        "j8v6fijwHoUwgZgGA1UdIwSBkDCBjYAU9aFqqHdPW7EEjKd+SPEOn8V2jxuhcqRwMG4xDzANBgNV"+
        "BAgTBk1hZHJpZDEPMA0GA1UEBxMGTWFkcmlkMQ4wDAYDVQQKEwVNSVR5QzEbMBkGA1UECxMSTUlU"+
        "eUMgRE5JZSBQcnVlYmFzMRAwDgYDVQQDEwdSb290IENBMQswCQYDVQQGEwJFU4IBAzA9BgNVHR8E"+
        "NjA0MDKgMKAuhixodHRwOi8vbWluaXN0ZXItOGpneHk5Lm1pdHljLmFnZS9QS0kvY3JsLmNybDAJ"+
        "BgNVHREEAjAAMA0GCSqGSIb3DQEBBQUAA4GBAE2HBlKBFTypGszcljAZTyRFCVui2dVo3gNpPqmk"+
        "hhCBjY4y+X76pn17di53XY5LSJyGSlDRdX+byHlpqjz6bqv77dhMIdRIowHYmHW6p1BTiEsaDmR5"+
        "2TSJQeeH7d4oPoB2d/+kG7tEv0QVy3UxZi3aSObgIXZkqbIfm2O22vyIMYIBvTCCAbkCAQEweDBy"+
        "MQswCQYDVQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxDjAMBgNVBAoT"+
        "BU1JVHlDMRswGQYDVQQLExJNSVR5QyBETkllIFBydWViYXMxFDASBgNVBAMTC0NBIHVzdWFyaW9z"+
        "AgIAgjANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI"+
        "hvcNAQkFMQ8XDTEwMDEyMDEwNTAxN1owKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQUBVHbMOMqOLPl"+
        "lgOFsFThkHbtNocwLwYJKoZIhvcNAQkEMSIEIKF5HAznZUgTWugAXe6sFH8eOXS/9z85pN7qi9QP"+
        "qXM7MA0GCSqGSIb3DQEBAQUABIGAl5QtPubTqurQ51ss5XLLaB6d0bPfuJ8SjZnTSMrNzbTIT8me"+
        "TOLyU4HwIykwJJEXtsrsVMYVNfsg41g7fTTPm8OA4Pr9Cnaxuvcygl9on7PWMoy7dAUshD2KPTcU"+
        "ogoEU35/TIoKfNWuToA00AyjzM/3HqS3EKs3gtnNapeE9J0=";

    /**
     * <p>
     * Conjunto 2 de datos codificados en base64.
     * </p>
     */
    public static final String DATA2 = 
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" +
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /**
     * <p>
     * Token de sellado de tiempo codificado en base64 asociado a los datos del
     * conjunto 1.
     * </p>
     */
    public static final String TOKEN_DATA2 = 
        "MIIF6QYJKoZIhvcNAQcCoIIF2jCCBdYCAQMxDzANBglghkgBZQMEAgEFADBSBgsqhkiG9w0BCRAB"+
        "BKBDBEEwPwIBAQYDKgMEMCEwCQYFKw4DAhoFAAQUPvigjskOJE/iqJSLcB6vzB0GVxICAQEYDzIw"+
        "MTAwMTIwMTEzOTE4WqCCA6kwggOlMIIDDqADAgECAgIAgjANBgkqhkiG9w0BAQUFADByMQswCQYD"+
        "VQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxDjAMBgNVBAoTBU1JVHlD"+
        "MRswGQYDVQQLExJNSVR5QyBETkllIFBydWViYXMxFDASBgNVBAMTC0NBIHVzdWFyaW9zMB4XDTA5"+
        "MDgyNDA4NDYyNVoXDTEwMDgyNDA4NDYyNVowgYExCzAJBgNVBAYTAkVTMQ8wDQYDVQQIEwZNYWRy"+
        "aWQxDzANBgNVBAcTBk1hZHJpZDEOMAwGA1UEChMFTUlUeUMxGzAZBgNVBAsTEk1JVHlDIEROSWUg"+
        "UHJ1ZWJhczEjMCEGA1UEAxMaU2VydmljaW8gZGUgcHJ1ZWJhcyBkZSBUU0EwgZ8wDQYJKoZIhvcN"+
        "AQEBBQADgY0AMIGJAoGBAKTu0i/a5dNzNDzbm/PAEwVbVCCyrZTQd2HBuqlU7i0bXxdYoeX4KLFI"+
        "9xf0CrL6gDEtAK6d5jApUuBjM0NN2BYlgungF37wHIUP7P9kfwcrA0LostONCDrNWB2P4Lf/MvL6"+
        "Ch5HUgsIbuqImYCjgYpynHKCMNIPoPSNOVvH+fZ/AgMBAAGjggE4MIIBNDAJBgNVHRMEAjAAMAsG"+
        "A1UdDwQEAwIDyDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUJasyiJe3kzrgc2dN"+
        "j8v6fijwHoUwgZgGA1UdIwSBkDCBjYAU9aFqqHdPW7EEjKd+SPEOn8V2jxuhcqRwMG4xDzANBgNV"+
        "BAgTBk1hZHJpZDEPMA0GA1UEBxMGTWFkcmlkMQ4wDAYDVQQKEwVNSVR5QzEbMBkGA1UECxMSTUlU"+
        "eUMgRE5JZSBQcnVlYmFzMRAwDgYDVQQDEwdSb290IENBMQswCQYDVQQGEwJFU4IBAzA9BgNVHR8E"+
        "NjA0MDKgMKAuhixodHRwOi8vbWluaXN0ZXItOGpneHk5Lm1pdHljLmFnZS9QS0kvY3JsLmNybDAJ"+
        "BgNVHREEAjAAMA0GCSqGSIb3DQEBBQUAA4GBAE2HBlKBFTypGszcljAZTyRFCVui2dVo3gNpPqmk"+
        "hhCBjY4y+X76pn17di53XY5LSJyGSlDRdX+byHlpqjz6bqv77dhMIdRIowHYmHW6p1BTiEsaDmR5"+
        "2TSJQeeH7d4oPoB2d/+kG7tEv0QVy3UxZi3aSObgIXZkqbIfm2O22vyIMYIBvTCCAbkCAQEweDBy"+
        "MQswCQYDVQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxDjAMBgNVBAoT"+
        "BU1JVHlDMRswGQYDVQQLExJNSVR5QyBETkllIFBydWViYXMxFDASBgNVBAMTC0NBIHVzdWFyaW9z"+
        "AgIAgjANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI"+
        "hvcNAQkFMQ8XDTEwMDEyMDExMzkxOFowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQUBVHbMOMqOLPl"+
        "lgOFsFThkHbtNocwLwYJKoZIhvcNAQkEMSIEIIkSxlHIfNTohrvPd9rR0b5qlZCDY5ekypYy6QkG"+
        "2OsKMA0GCSqGSIb3DQEBAQUABIGATll7dJg2GPbaKu/RSDb+qwtl+QcWUoqeuRPXiLZfV1RlaEP0"+
        "Mq8dwH7kpA81x/iEAMWI28dU01jDVim2XPNixrDtQpo3GNd0RMM40+K7sAEkVIFsakdfWKqgSSfu"+
        "mtJx0bvYkn8SJEupII7ESOK3I1t2/9zYpzPYrbfT8uNStGU=";

    /**
     * <p>Punto de entrada al programa</p>
     * @param args Argumentos del programa
     */
    public static void main(String[] args) {
        TimestampValidation timestampValidation = new TimestampValidation();
        timestampValidation.execute();
    }

    /**
     * <p>Ejecución del ejemplo</p>
     */
    private void execute() {
        //Craeción de un validador de sellos de tiempo
        ITimeStampValidator tsValidator = new TimeStampValidator();
        TSValidationResult result = null;
        System.out.println("-------------------------------------");
        System.out.println("-- Resultado DATA1 con TOKEN_DATA1 --");
        System.out.println("-------------------------------------");
        try {
            result = tsValidator.validateTimeStamp(Base64.decode(DATA1), Base64.decode(TOKEN_DATA1));
            System.out.println("Resultado: Correcto");
            System.out.println("Fecha del sello: "+result.getFormattedDate());
            System.out.println("Emisor del sello: "+(result.getTimeStampIssuer() != null ? result.getTimeStampIssuer() : "Desconocido") );
            System.out.println("");
        } catch (TimeStampException e) {
            System.out.println("Resultado: Error, el token no se corresponde con los datos: "+e.getMessage());
            System.out.println("");
        } 

        System.out.println("-------------------------------------");
        System.out.println("-- Resultado DATA2 con TOKEN_DATA2 --");
        System.out.println("-------------------------------------");
        try {
            result = tsValidator.validateTimeStamp(Base64.decode(DATA2), Base64.decode(TOKEN_DATA2));
            System.out.println("Resultado: Correcto");
            System.out.println("Fecha del sello: " + result.getFormattedDate());
            System.out.println("Emisor del sello: "+(result.getTimeStampIssuer() != null ? result.getTimeStampIssuer() : "Desconocido") );
            System.out.println("");
        } catch (TimeStampException e) {
            System.out.println("Resultado: Error, el token no se corresponde con los datos: "+e.getMessage());
            System.out.println("");
        } 
			
        System.out.println("-------------------------------------");
        System.out.println("-- Resultado DATA1 con TOKEN_DATA2 --");
        System.out.println("-------------------------------------");
        try {
            result = tsValidator.validateTimeStamp(Base64.decode(DATA1), Base64.decode(TOKEN_DATA2));
            System.out.println("Resultado: Correcto");
            System.out.println("Fecha del sello: " + result.getFormattedDate());
            System.out.println("Emisor del sello: "+(result.getTimeStampIssuer() != null ? result.getTimeStampIssuer() : "Desconocido") );
            System.out.println("");
        } catch (TimeStampException e) {
            System.out.println("Resultado: Error, el token no se corresponde con los datos: "+e.getMessage());
            System.out.println("");
        } 

        System.out.println("-------------------------------------");
        System.out.println("-- Resultado DATA2 con TOKEN_DATA1 --");
        System.out.println("-------------------------------------");
        try {
            result = tsValidator.validateTimeStamp(Base64.decode(DATA2), Base64.decode(TOKEN_DATA1));
            System.out.println("Resultado: Correcto");
            System.out.println("Fecha del sello: " + result.getFormattedDate());
            System.out.println("Emisor del sello: "+(result.getTimeStampIssuer() != null ? result.getTimeStampIssuer() : "Desconocido") );
            System.out.println("");
        } catch (TimeStampException e) {
            System.out.println("Resultado: Error, el token no se corresponde con los datos: "+e.getMessage());
            System.out.println("");
        } 	
    }
}
