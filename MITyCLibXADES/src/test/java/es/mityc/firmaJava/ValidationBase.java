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
package es.mityc.firmaJava;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import es.mityc.firmaJava.libreria.xades.ExtraValidators;
import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.ValidarFirmaXML;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import es.mityc.javasign.ts.TimeStampValidator;
import es.mityc.javasign.tsa.ITimeStampValidator;
import es.mityc.javasign.xml.xades.policy.IValidacionPolicy;

/**
 * Métodos base para la carga y validación de firmas 
 */
public abstract class ValidationBase {
	
	protected static final Log LOGGER = LogFactory.getLog(ValidationBase.class);
	
	protected static final ITimeStampValidator tsValidator = new TimeStampValidator();
	
	protected InputStream loadRes(String path) {
		InputStream is = this.getClass().getResourceAsStream(path);
		if (is == null) {
			fail("El recurso indicado (" + path + ") no está disponible");
		}
		return is;
	}
	
	protected String getBaseUri(String path) {
		URL url = this.getClass().getResource(path);
		if (url == null) {
			fail("El recurso indicado (" + path + ") no está disponible");
		}
		return url.toString();
	}

	protected File cargaFichero(String ruta) {
		File file = new File(ruta);
		if (!file.exists()) {
			fail("Fichero indicado no existe: " + ruta);
		}
		return file;
	}
	
	protected boolean validaFichero(File file, IValidacionPolicy policy) {
		try
		{
			ArrayList<IValidacionPolicy> policies = null;
			if (policy != null) {
				policies = new ArrayList<IValidacionPolicy>(1);
				policies.add(policy);
			}
			ValidarFirmaXML vXml = new ValidarFirmaXML();
			ExtraValidators extra = new ExtraValidators(policies, null, null);
			List<ResultadoValidacion> results = vXml.validar(file, extra, tsValidator);
			return results.get(0).isValidate();
		} catch (Exception ex) {
		}
		return false;
	}

	protected boolean validateStream(InputStream is, String baseUri, IValidacionPolicy policy) {
		try
		{
			ArrayList<IValidacionPolicy> policies = null;
			if (policy != null) {
				policies = new ArrayList<IValidacionPolicy>(1);
				policies.add(policy);
			}
			ValidarFirmaXML vXml = new ValidarFirmaXML();
			ExtraValidators extra = new ExtraValidators(policies, null, null);
			List<ResultadoValidacion> results = vXml.validar(is, baseUri, extra, tsValidator);
			return results.get(0).isValidate();
		} catch (Exception ex) {
			LOGGER.info(ex.getMessage());
			LOGGER.info("", ex);
		}
		return false;
	}

	protected boolean validateDoc(Document doc, String baseUri, IValidacionPolicy policy) {
		try
		{
			ArrayList<IValidacionPolicy> policies = null;
			if (policy != null) {
				policies = new ArrayList<IValidacionPolicy>(1);
				policies.add(policy);
			}
			ValidarFirmaXML vXml = new ValidarFirmaXML();
			ExtraValidators extra = new ExtraValidators(policies, null, null);
			List<ResultadoValidacion> results = vXml.validar(doc, baseUri, extra, tsValidator);
			return results.get(0).isValidate();
		} catch (Exception ex) {
			LOGGER.info(ex.getMessage());
			LOGGER.info("", ex);
		}
		return false;
	}

	protected boolean validateStreamThrowable(InputStream is, String baseUri, IValidacionPolicy policy) throws FirmaXMLError {
		ArrayList<IValidacionPolicy> policies = null;
		if (policy != null) {
			policies = new ArrayList<IValidacionPolicy>(1);
			policies.add(policy);
		}
		ValidarFirmaXML vXml = new ValidarFirmaXML();
		ExtraValidators extra = new ExtraValidators(policies, null, null);
		List<ResultadoValidacion> results = vXml.validar(is, baseUri, extra, tsValidator);
		return results.get(0).isValidate();
	}
	
	protected Document loadDoc(String res) {
		Document doc = null;
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			doc = dbf.newDocumentBuilder().parse(this.getClass().getResourceAsStream(res));
		} catch (ParserConfigurationException ex) {
			fail("No se puede generar document para firmar: " + ex.getMessage());
		} catch (SAXException ex) {
			fail("No se puede generar document para firmar: " + ex.getMessage());
		} catch (IOException ex) {
			fail("No se puede generar document para firmar: " + ex.getMessage());
		} catch (IllegalArgumentException ex) {
			fail("No se ha encontrado el recurso con el documento xml");
		}
		assertNotNull("No se ha podido generar el documento xml", doc);
		return doc;
	}

}
