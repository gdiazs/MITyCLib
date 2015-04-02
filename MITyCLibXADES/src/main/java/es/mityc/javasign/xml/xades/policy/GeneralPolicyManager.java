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
/**
 * 
 */
package es.mityc.javasign.xml.xades.policy;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import adsi.org.apache.xml.security.c14n.CanonicalizationException;
import adsi.org.apache.xml.security.signature.XMLSignatureInput;
import adsi.org.apache.xml.security.transforms.TransformationException;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFicheros;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFirmaElectronica;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.xades.DocumentationReference;
import es.mityc.firmaJava.libreria.xades.elementos.xades.Int;
import es.mityc.firmaJava.libreria.xades.elementos.xades.NoticeRef;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SPURI;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SPUserNotice;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SigPolicyQualifier;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SignaturePolicyId;
import es.mityc.firmaJava.libreria.xades.elementos.xades.SignaturePolicyIdentifier;
import es.mityc.firmaJava.libreria.xades.elementos.xmldsig.Transform;
import es.mityc.firmaJava.libreria.xades.elementos.xmldsig.Transforms;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.xml.xades.policy.PolicyResult.DownloadPolicy;

/**
 * <p>Gestionado genérico de políticas.</p>
 * <p>Cuando no se tiene acceso a un validador de políticas se recurre a éste para al menos recuperar información sobre la política que se ha aplicado
 * a la firma. Este validador marcará la política como desconocida pero permite obtener información y/o documentación sobre la política.</p>
 * 
 */
public class GeneralPolicyManager implements IValidacionPolicy {
	
	private final static Log logger = LogFactory.getLog(GeneralPolicyManager.class);
	
	private final static String GENERAL_ID = "self:policy/general";

	/**
	 * 
	 */
	public GeneralPolicyManager() {
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.policy.IValidacionPolicy#getIdentidadPolicy()
	 */
	public String getIdentidadPolicy() {
		return GENERAL_ID;
	}

	/* (non-Javadoc)
	 * @see es.mityc.firmaJava.policy.IValidacionPolicy#validaPolicy(org.w3c.dom.Element, es.mityc.firmaJava.libreria.xades.ResultadoValidacion)
	 */
	public PolicyResult validaPolicy(Element nodoFirma, ResultadoValidacion resultadoValidacion) {
		PolicyResult pr = new PolicyResult();
		pr.setResult(PolicyResult.StatusValidation.unknown);
		
		try {
			SignaturePolicyIdentifier signaturePolicyIdentifier = extractInfo(nodoFirma, resultadoValidacion);
			
			// extrae la informacion de la politica
			if (!signaturePolicyIdentifier.isImplied()) {
				SignaturePolicyId spi = signaturePolicyIdentifier.getSignaturePolicyId();
				
				// extrae la información
				pr.setPolicyID(spi.getSigPolicyId().getIdentifier().getUri());
				if (spi.getSigPolicyId().getDescription() != null)
					pr.setDescription(spi.getSigPolicyId().getDescription().getValue());
				if (spi.getSigPolicyId().getReferences() != null) {
					ArrayList<DocumentationReference> references = spi.getSigPolicyId().getReferences().getList();
					if ((references != null) && (references.size() > 0)) {
						ArrayList<URI> uris = new ArrayList<URI>(references.size());
						Iterator<DocumentationReference> it = references.iterator();
						while (it.hasNext()) {
							uris.add(it.next().getValue());
						}
						pr.setDocumentation(uris.toArray(new URI[0]));
					}
				}
				if (spi.getSigPolicyQualifiers() != null) {
					ArrayList<SigPolicyQualifier> list = spi.getSigPolicyQualifiers().getList();
					if ((list != null) && (list.size() > 0)) {
						MessageDigest md = UtilidadFirmaElectronica.getMessageDigest(spi.getSigPolicyHash().getDigestMethod().getAlgorithm());
						String digestValue = spi.getSigPolicyHash().getDigestValue().getValue();

						ArrayList<PolicyResult.DownloadPolicy> downloadbles = new ArrayList<PolicyResult.DownloadPolicy>();
						ArrayList<String> notices = new ArrayList<String>();
						Iterator<SigPolicyQualifier> it = list.iterator();
						while (it.hasNext()) {
							SigPolicyQualifier spq = it.next();
							Object obj = spq.getQualifier();
							if (obj instanceof SPURI) {
								downloadbles.add(checkIntegrity(pr, ((SPURI)obj).getValue(), spi, resultadoValidacion.getBaseURI(), md, digestValue, nodoFirma.getOwnerDocument()));
							}
							else if (obj instanceof SPUserNotice) {
								StringBuffer notice = new StringBuffer(""); 
								String expl = ((SPUserNotice)obj).getExplicitText();
								if (expl != null)
									notice.append(expl).append(" ");
								NoticeRef nr = ((SPUserNotice)obj).getNoticeRef();
								if (nr != null) {
									notice.append("(").append(nr.getOrganization().getValue());
									Iterator<Int> itInt = nr.getNoticeNumbers().getInts().iterator();
									if (itInt.hasNext())
										notice.append(" ");
									while (itInt.hasNext()) {
										notice.append(itInt.next().getValue().toString());
										if (itInt.hasNext())
											notice.append(".");
									}
									notice.append(")");
								}
								notices.add(notice.toString());
							}
							// TODO: hacer algo con el contenido desconocido
						}
						if (downloadbles.size() > 0) {
							pr.setDownloable(downloadbles.toArray(new PolicyResult.DownloadPolicy[0]));
						}
						if (notices.size() > 0) {
							pr.setNotices(notices.toArray(new String[0]));
						}
					}
				}
				
			}
		} catch (PolicyException ex) {
			pr.setResult(PolicyResult.StatusValidation.invalid);
			pr.setDescriptionResult(ex.getMessage());
		}

		return pr;
	}
	
	private DownloadPolicy checkIntegrity(PolicyResult pr, URI uri, SignaturePolicyId spi, URI baseUri, MessageDigest md, String digestValue, Document doc) {
		PolicyResult.StatusValidation status = PolicyResult.StatusValidation.unknown;

		if (md != null) {
			// Intenta recuperar el contenido
			URI descarga = uri;
			if ((!uri.isAbsolute()) && (baseUri != null))
				descarga = baseUri.resolve(uri);
			
			if ("file".equals(descarga.getScheme())) {
				byte[] data;
				data = UtilidadFicheros.readFile(new File((descarga.getSchemeSpecificPart())));
				if (data == null)
					logger.warn("No se puede obtener el contenido referenciado");
				else {
					// Si hay transformadas intenta aplicarlas sobre un documento xml
					if (spi.getTransforms() != null) {
						data = transform(data, spi.getTransforms(), doc);
					}
					
					// calcula el hash según el algoritmo
					md.update(data);
					byte[] resData = md.digest();
					String res = new String(Base64Coder.encode(resData));
					if (res.equals(digestValue))
						status = PolicyResult.StatusValidation.valid;
					else
						status = PolicyResult.StatusValidation.invalid;
				}
			}
			else
				logger.warn("No se puede obtener el contenido referenciado en: " + descarga);
		}
		else
			logger.warn("Algoritmo desconocido");
		return pr.newDownloadPolicy(uri, status);
	}
	
	private byte[] transform(byte[] in, Transforms transforms, Document doc) {
		adsi.org.apache.xml.security.transforms.Transforms t = new adsi.org.apache.xml.security.transforms.Transforms(doc);
		
		ArrayList<Transform> list = transforms.getList();
		if (list != null) {
			Iterator<Transform> it = list.iterator();
			while (it.hasNext()) {
				Transform tr = it.next();
				try {
					if (adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS.equals(tr.getAlgorithm())) {
						t.addTransform(adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
					}
					else if (adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS.equals(tr.getAlgorithm())) {
						t.addTransform(adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS);
					}
					else if (adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_OMIT_COMMENTS.equals(tr.getAlgorithm())) {
						t.addTransform(adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
					}
					else if (adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_WITH_COMMENTS.equals(tr.getAlgorithm())) {
						t.addTransform(adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_WITH_COMMENTS);
					}
					else if (adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_XPATH.equals(tr.getAlgorithm())) {
						t.addTransform(adsi.org.apache.xml.security.transforms.Transforms.TRANSFORM_XPATH, tr.getExtraNodes());
					}
				} catch (TransformationException ex) {
					logger.error("Error incluyendo transformada", ex);
					return in;
				}
			}
		}
		else
			return in;
    	
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(in);
		try {
			XMLSignatureInput resultado = null;
			resultado = t.performTransforms(xmlSignatureInput);
			baos.write(resultado.getBytes());
		} catch (TransformationException ex) {
			logger.error("Error calculando transformada de política", ex);
			return in;
		} catch (CanonicalizationException ex) {
			logger.error("Error calculando transformada de política", ex);
			return in;
		} catch (IOException ex) {
			logger.error("Error calculando transformada de política", ex);
			return in;
		}

		return baos.toByteArray();
	}
	
	private SignaturePolicyIdentifier extractInfo(Element nodoFirma, ResultadoValidacion resultadoValidacion) throws PolicyException {
		XAdESSchemas schema = resultadoValidacion.getDatosFirma().getEsquema();
		if (schema == null) {
			throw new PolicyException("Error obteniendo esquema de firma");
		}
		
		String esquema = schema.getSchemaUri();

		// Nodo SignaturePolicyIdentifier
		ArrayList<Element> signaturePolicyList = null;
		try {
			signaturePolicyList = UtilidadTratarNodo.obtenerNodos(nodoFirma, 5,
				new NombreNodo(esquema, ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER));	
		} catch (FirmaXMLError e) {
			logger.error(e.getMessage(), e);
			throw new PolicyException("Error obteniendo el nodo de política: " + e.getMessage());
		}
				
		if (signaturePolicyList.size() != 1)
			throw new PolicyException("Error obteniendo nodo de política (no hay nodo, o hay más de uno)");
		if (signaturePolicyList.get(0).getNodeType() != Node.ELEMENT_NODE)
			throw new PolicyException("Error obteniendo nodo de política (no es del tipo elemento)");

		try {
			SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier(schema);
			if (!signaturePolicyIdentifier.isThisNode(signaturePolicyList.get(0)))
				throw new InvalidInfoNodeException("No se ha encontrado política");
			signaturePolicyIdentifier.load((Element)signaturePolicyList.get(0));
			
			return signaturePolicyIdentifier;
		} catch (InvalidInfoNodeException ex) {
			throw new PolicyException(ex.getMessage(), ex);
		}
	}

	public void setTruster(TrustAbstract truster) {
	}
}
