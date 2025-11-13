package com.amazonaws.acmpcakms.examples;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamilyRegistry;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import software.amazon.awssdk.services.acmpca.model.*;

public class Runner {
  private static final String DEFAULT_FILE_PATH =
      "target/diy-code-signing-kms-private-ca-1.0-SNAPSHOT.jar";
  private static final String CA_VERSION = "-v1";
  private static final String ROOT_COMMON_NAME = "TestCodeSigningRoot" + CA_VERSION;
  private static final String SUBORDINATE_COMMON_NAME = "TestCodeSigningSubordinate" + CA_VERSION;
  private static final String END_ENTITY_COMMON_NAME = "TestCodeSigningCertificate" + CA_VERSION;
  private static final String CMK_ALIAS = "TestCodeSigningCMK" + CA_VERSION;

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static String getSupportedAlgorithmsString() {
    return String.join(", ", AlgorithmFamilyRegistry.getSupportedFamilies());
  }

  private static void privateCaDemo(AlgorithmFamily algorithmFamily, byte[] dataToSign)
      throws Exception {

    System.out.println("\n\n--------------------------------------------------");
    System.out.println("Beginning Private CA Demo");
    System.out.println(
        "AlgorithmFamily: "
            + algorithmFamily.getFamilyName()
            + ", dataToSign: "
            + dataToSign.length
            + " bytes");
    System.out.println("--------------------------------------------------");

    byte[] originalDataFromFile = Arrays.copyOf(dataToSign, dataToSign.length);

    // Create algorithm-specific names to avoid collisions between different
    // algorithm families
    String algorithmSpecificRootName = ROOT_COMMON_NAME + "-" + algorithmFamily.getFamilyName();
    String algorithmSpecificSubordinateName =
        SUBORDINATE_COMMON_NAME + "-" + algorithmFamily.getFamilyName();
    String algorithmSpecificCmkAlias = CMK_ALIAS + "-" + algorithmFamily.getFamilyName();

    /*
     * Creating a CA hierarcy in AWS Private CA. This CA hiearchy consistant of a
     * Root and subordinate CA
     */
    System.out.println("\nStep 1: Creating a CA hierarchy in AWS Private CA\n");

    PrivateCA rootPrivateCA =
        PrivateCA.builder()
            .withCommonName(algorithmSpecificRootName)
            .withType(CertificateAuthorityType.ROOT)
            .withAlgorithmFamily(algorithmFamily)
            .getOrCreate();

    PrivateCA subordinatePrivateCA =
        PrivateCA.builder()
            .withIssuer(rootPrivateCA)
            .withCommonName(algorithmSpecificSubordinateName)
            .withType(CertificateAuthorityType.SUBORDINATE)
            .withAlgorithmFamily(algorithmFamily)
            .getOrCreate();

    /* Creating a asymmetric key pair using AWS KMS */
    System.out.println();
    System.out.println("\nStep 2: Creating a asymmetric key pair using AWS KMS\n");

    AsymmetricCMK codeSigningCMK =
        AsymmetricCMK.builder()
            .withAlias(algorithmSpecificCmkAlias)
            .withAlgorithmFamily(algorithmFamily)
            .getOrCreate();

    /* Creating a asymmetric key pair using AWS KMS */
    System.out.println();
    System.out.println(
        "\nStep 3: Creating a Certificate Signing Request for creating a code signing certificate\n");
    String codeSigningCSR = codeSigningCMK.generateCSR(END_ENTITY_COMMON_NAME);

    /* Issuing the code signing certificate from AWS Private CA */
    System.out.println();
    System.out.println("\nStep 4: Issuing a code signing certificate using AWS Private CA\n");
    GetCertificateResponse codeSigningCertificate =
        subordinatePrivateCA.issueCodeSigningCertificate(codeSigningCSR);

    /* Creating a detached CMS code signing object */
    System.out.println();
    System.out.println("\nStep 5: Creating a detached signature\n");

    // Parse signer certificate from PEM
    X509CertificateHolder signerCert =
        CertificateUtils.fromPEM(codeSigningCertificate.certificate());

    Collection<X509CertificateHolder> chainCerts =
        CertificateUtils.toCertificateHolders(codeSigningCertificate.certificateChain());

    // Build certificate chain including signer cert and intermediate certs
    Collection<X509CertificateHolder> certChain = new ArrayList<>();
    certChain.add(signerCert);

    // Add intermediate certificates (excluding the signer cert itself)
    for (X509CertificateHolder chainCert : chainCerts) {
      if (!chainCert.equals(signerCert)) {
        certChain.add(chainCert);
      }
    }

    // Create detached CMS signature
    CMSCodeSigningObject cmsCodeSigningObject =
        CMSCodeSigningObject.createDetachedSignature(
            codeSigningCMK, algorithmFamily, dataToSign, signerCert, certChain);

    /* Save signature and root CA certificate to files */
    System.out.println();
    System.out.println(
        "\nStep 6: Saving detached signature and root CA certificate to files on disk\n");

    // Save detached signature to .p7s file
    String signatureFileName = "signature-" + algorithmFamily.getFamilyName() + ".p7s";
    try (FileOutputStream sigOut = new FileOutputStream(signatureFileName)) {
      sigOut.write(cmsCodeSigningObject.toBytes());
    }
    System.out.println("Detached signature saved to: " + signatureFileName);

    // Save Root CA certificate to PEM file
    String rootCAPEM = rootPrivateCA.getCertificate();
    String rootCAFileName = "root-ca-" + algorithmFamily.getFamilyName() + ".pem";
    try (FileOutputStream rootCAOut = new FileOutputStream(rootCAFileName)) {
      rootCAOut.write(rootCAPEM.getBytes(StandardCharsets.UTF_8));
    }
    System.out.println("Root CA certificate saved to: " + rootCAFileName);

    System.out.println();
    System.out.println(
        "\nStep 7: Verifying the authenticity of in-memory detached signature and the integrity of the signed data\n");

    String rootCACertificatePEM =
        new String(Files.readAllBytes(Paths.get(rootCAFileName)), StandardCharsets.UTF_8);
    X509CertificateHolder rootCACertificate = CertificateUtils.fromPEM(rootCACertificatePEM);

    // Verify the detached CMS signature using the root CA loaded from file
    cmsCodeSigningObject.verifyDetachedSignature(dataToSign, rootCACertificate);

    System.out.println("In memory detached signature verification successful!");

    // Demonstrate verification from files (simulating real-world usage)
    System.out.println();
    System.out.println(
        "\nStep 8: Demonstrating verification of detached signatures from files on disk\n");

    // Read and parse CMS signature from .p7s file
    byte[] signatureFromFile = Files.readAllBytes(Paths.get(signatureFileName));
    CMSCodeSigningObject cmsFromFile = CMSCodeSigningObject.fromBytes(signatureFromFile);
    System.out.println("Loaded detached signature from disk. File: " + signatureFromFile + ", Size: " + );

    // Verify signature against original data
    cmsFromFile.verifyDetachedSignature(originalDataFromFile, rootCACertificate);

    System.out.println("On disk detached signature verification successful!");
  }

  public static void main(String[] args) throws Exception {
    // Read the file to be signed
    byte[] dataToSign = Files.readAllBytes(Paths.get(DEFAULT_FILE_PATH));

    privateCaDemo(AlgorithmFamilyRegistry.RSA2048.getFamily(), dataToSign);
    privateCaDemo(AlgorithmFamilyRegistry.MLDSA65.getFamily(), dataToSign);

    System.out.println("\n--------------------------------------------------");
    System.out.println("End of Private CA Demo");
    System.out.println("--------------------------------------------------");
  }
}
