package com.eideasy.samples;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.util.List;

@RestController
public class ESignatureController {

    private static final Logger logger = LoggerFactory.getLogger(ESignatureController.class);

    @GetMapping("/api/sign-pdf")  // TODO test
    public ResponseEntity<InputStreamResource> getTest() throws IOException, CertificateException {
        // Load unsigned file and signing certificates from local file.
        DSSDocument toSignDocument = new FileDocument("src/main/resources/test.pdf");
        Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken("src/main/resources/teststore.p12", new KeyStore.PasswordProtection("123456".toCharArray()));

        // Exctract first private key from the keystore for signing.
        List<DSSPrivateKeyEntry> keys = signingToken.getKeys();
        DSSPrivateKeyEntry privateKey = null;
        for (DSSPrivateKeyEntry entry : keys) {
            privateKey = entry;
            break;
        }
        CertificateToken signerCert = privateKey.getCertificate();

        // Construct data to sign.
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningCertificate(signerCert);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        PAdESService service = new PAdESService(commonCertificateVerifier);

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        // Create signature and attach it to the PDF file.
        SignatureValue signatureValue = signingToken.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);
        DSSDocument signedFile = service.signDocument(toSignDocument, parameters, signatureValue);

        InputStreamResource resource = new InputStreamResource(signedFile.openStream());

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed-pdf.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(resource);
    }
}
