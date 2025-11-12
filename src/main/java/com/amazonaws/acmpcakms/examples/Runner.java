package com.amazonaws.acmpcakms.examples;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import software.amazon.awssdk.services.acmpca.model.CertificateAuthorityType;
import software.amazon.awssdk.services.acmpca.model.GetCertificateResponse;
import software.amazon.awssdk.services.acmpca.model.KeyAlgorithm;
import software.amazon.awssdk.services.acmpca.model.SigningAlgorithm;
import software.amazon.awssdk.services.kms.model.KeySpec;

import java.nio.charset.StandardCharsets;
import java.security.Security;

public class Runner {

    private static final String ROOT_COMMON_NAME = "TestCodeSigningRoot";
    private static final String SUBORDINATE_COMMON_NAME = "TestCodeSigningSubordinate";
    private static final String END_ENTITY_COMMON_NAME = "TestCodeSigningCertificate";
    private static final String CMK_ALIAS = "TestCodeSigningCMK";
    private static final String TBS_DATA = "The data that I want signed";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static void privateCaDemo(KeyAlgorithm keyAlg, SigningAlgorithm signingAlg) throws Exception {
        /* Creating a CA hierarcy in ACM Private CA. This CA hiearchy consistant of a Root and subordinate CA */
        System.out.println("\nStep 1: Creating a CA hierarchy\n");

        PrivateCA rootPrivateCA = PrivateCA.builder()
                .withCommonName(ROOT_COMMON_NAME + "-" + keyAlg.name())
                .withType(CertificateAuthorityType.ROOT)
                .withKeyAlgorithm(keyAlg)
                .withSigningAlgorithm(signingAlg)
                .getOrCreate();

        PrivateCA subordinatePrivateCA = PrivateCA.builder()
                .withIssuer(rootPrivateCA)
                .withCommonName(SUBORDINATE_COMMON_NAME + "-" + keyAlg.name())
                .withType(CertificateAuthorityType.SUBORDINATE)
                .withKeyAlgorithm(keyAlg)
                .withSigningAlgorithm(signingAlg)
                .getOrCreate();

        /* Creating a asymmetric key pair using AWS KMS */
        System.out.println();
        System.out.println("\nStep 2: Creating a asymmetric key pair using AWS KMS\n");

        AsymmetricCMK codeSigningCMK = AsymmetricCMK.builder()
                .withAlias(CMK_ALIAS+ "-" + keyAlg.name())
                .withKeySpec(KeySpec.fromValue(keyAlg.name()))
                .getOrCreate();

        /* Creating a asymmetric key pair using AWS KMS */
        System.out.println();
        System.out.println("\nStep 3: Creating a CSR(Certificate signing request) for creating a code signing certificate\n");
        String codeSigningCSR = codeSigningCMK.generateCSR(END_ENTITY_COMMON_NAME + "-" + keyAlg.name());

        /* Issuing the code signing certificate from ACM Private CA */
        System.out.println();
        System.out.println("\nStep 4: Issuing a code signing certificate from ACM Private CA\n");
        GetCertificateResponse codeSigningCertificate = subordinatePrivateCA.issueCodeSigningCertificate(codeSigningCSR);

        /* Creating a custom code signing object */
        System.out.println();
        System.out.println("\nStep 5: Creating a custom code signing object\n");
        CustomCodeSigningObject customCodeSigningObject = CustomCodeSigningObject.builder()
                .withAsymmetricCMK(codeSigningCMK)
                .withDataBlob(TBS_DATA.getBytes(StandardCharsets.UTF_8))
                .withCertificate(codeSigningCertificate.certificate())
                .build();

        /* Creating a custom code signing object */
        System.out.println();
        System.out.println("\nStep 6: Object was signed successfully\n");

        /* Verifying the authenticity of the signature and the integrity of the signed data */
        System.out.println();
        System.out.println("\nStep 7: Verifying the authenticity of the signature and the integrity of the signed data\n");

        /* The root CA certificate is stored in rootPrivate CA, which is an object of the PrivateCA class. This sample code is not implementing a full fledged trust store and hence
           the root CA cert is stored in an object instance. This allows to perform the signature validation by getting the root CA from the object instance instead of making a ACM private CA API
           call getCertificateAuthorityCertificate to get the root CA certificate. You can see this happening in the file PrivateCA.java lines 62-70

           In this implementation, we don’t use a trust store that’s either part of a browser or part of a file system within the resident OS of a device or a server.
           The trust store is placed in an instance of Java class PrivateCA as this is only a test sample. Anyone planning to use this DIY code signing mechanism for
           production should consider building secure trust stores in which the root CA certificate will be placed.
        */
        String rootCACertificate = rootPrivateCA.getCertificate();
        String customCodeSigningObjectCertificateChain = codeSigningCertificate.certificate() + "\n" + codeSigningCertificate.certificateChain();

        CustomCodeSigningObject.getInstance(customCodeSigningObject.toString())
                .validate(rootCACertificate, customCodeSigningObjectCertificateChain);
    }


    public static void main(final String[] args) throws Exception {

        privateCaDemo(KeyAlgorithm.ML_DSA_65, SigningAlgorithm.ML_DSA_65);

        System.out.println("\n------------------------------\n");
        privateCaDemo(KeyAlgorithm.RSA_2048, SigningAlgorithm.SHA256_WITHRSA);

    }
}
