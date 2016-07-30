package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.BeansException;

/** Enables SHA256 or SHA512 Digital Signatures and Signature Reference Digests to SAML Requests & Assertions
  *
  */
public class SAMLBootstrap extends org.springframework.security.saml.SAMLBootstrap {

    public static final String DEFAULT_ALGORITHM = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
    String signatureUrl =  DEFAULT_ALGORITHM;
    
    /**
     * Class logger.
     */
    protected final static Logger log = LoggerFactory.getLogger(SAMLBootstrap.class);
        
    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        super.postProcessBeanFactory(beanFactory);
        if (signatureUrl.equals(DEFAULT_ALGORITHM))
          return;
        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
        config.registerSignatureAlgorithmURI("RSA", signatureUrl);
        if (signatureUrl.equals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256))
          config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        else if (signatureUrl.equals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512))
          config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
    }
        
    public void setSignatureAlgorithm(String url) {
      if (SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1.equals(url) ||
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256.equals(url) ||
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512.equals(url)) {
        this.signatureUrl = url;
      }
      else {
        log.warn("Invalid SAML digital signature: " + url + ", defaulting to " + this.signatureUrl);
      }
    }
}
