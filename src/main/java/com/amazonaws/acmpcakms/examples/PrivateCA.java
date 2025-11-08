package com.amazonaws.acmpcakms.examples;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.waiters.WaiterResponse;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.services.acmpca.AcmPcaAsyncClient;
import software.amazon.awssdk.services.acmpca.model.*;
import software.amazon.awssdk.services.acmpca.waiters.AcmPcaAsyncWaiter;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class PrivateCA {

    private final AcmPcaAsyncClient client;
    private final String commonName;
    private final CertificateAuthorityType type;
    private final CertificateAuthority ca;
    private final String certificate;
    private final KeyAlgorithm keyAlgorithm;
    private final SigningAlgorithm signingAlgorithm;

    private PrivateCA(final Optional<PrivateCA> issuerOption, final String commonName, final CertificateAuthorityType type, KeyAlgorithm keyAlgorithm, SigningAlgorithm signingAlgorithm) {
        if (Objects.isNull(commonName) || commonName.isBlank()) {
            throw new IllegalArgumentException("A non-empty common name must be specified");
        }

        if (Objects.isNull(type)) {
            throw new IllegalArgumentException("A CA type must be specified");
        }

        if (Objects.isNull(keyAlgorithm)) {
            throw new IllegalArgumentException("Key Algorithm may not be null.");
        }

        if (Objects.isNull(signingAlgorithm)) {
            throw new IllegalArgumentException("Signing Algorithm may not be null.");
        }

        if (type.equals(CertificateAuthorityType.ROOT) && issuerOption.isPresent()) {
            throw new IllegalArgumentException("A root CA cannot have an issuer specified");
        }

        if (type.equals(CertificateAuthorityType.SUBORDINATE) && !issuerOption.isPresent()) {
            throw new IllegalArgumentException("A subordinate CA must have an issuer specified");
        }

        // Set up a PQ TLS HTTP client that will be used when connecting to AWS
        SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .postQuantumTlsEnabled(true)
                .build();

        this.client = AcmPcaAsyncClient.builder()
                .httpClient(awsCrtHttpClient)
                .build();

        this.commonName = commonName;
        this.type = type;
        this.keyAlgorithm = keyAlgorithm;
        this.signingAlgorithm = signingAlgorithm;

        List<CertificateAuthority> discoveredCAs = listCAs();

        Optional<CertificateAuthority> matchingIssuerCAOption = issuerOption.flatMap(issuer -> discoveredCAs.stream()
                .filter(issuer::matches)
                .findFirst());

        if (issuerOption.isPresent() && !matchingIssuerCAOption.isPresent()) {
            throw new IllegalArgumentException("Could not find issuer matching " + issuerOption.get());
        }

        this.ca = discoveredCAs.stream()
                .filter(this::matches)
                .findFirst()
                .orElseGet(this::createCA);

        System.out.println("Got CA with CN="  + commonName + ": arn=" + ca.arn() + ", status=" + ca.status());

        if (ca.status().equals(CertificateAuthorityStatus.ACTIVE.toString())) {
            certificate = getCACertificate();
            return;
        }

        if (type == CertificateAuthorityType.ROOT) {
            this.certificate = activateRootCA();
        } else {
            this.certificate = activateSubordinateCA(matchingIssuerCAOption.get());
        }
    }

    public String getCertificate() {
        return certificate;
    }

    private boolean matches(final CertificateAuthority ca) {
        System.out.println("CA: " + ca.toString());
        return type.toString().equals(ca.type().toString())
                && commonName.equals(ca.certificateAuthorityConfiguration().subject().commonName())
                && keyAlgorithm.equals(ca.certificateAuthorityConfiguration().keyAlgorithm())
                && signingAlgorithm.equals(ca.certificateAuthorityConfiguration().signingAlgorithm());
    }

    private CertificateAuthority createCA() {
        System.out.println("No matching CA found, creating a new one (" + this + ")");

        try {
            CreateCertificateAuthorityRequest createCARequest = CreateCertificateAuthorityRequest.builder()
                    .tags(Tag.builder()
                            .key("Name")
                            .value(commonName)
                            .build())
                    .idempotencyToken(UUID.randomUUID().toString())
                    .certificateAuthorityType(type)
                    .certificateAuthorityConfiguration(CertificateAuthorityConfiguration.builder()
                            .subject(ASN1Subject.builder()
                                    .commonName(commonName)
                                    .build())
                            .keyAlgorithm(keyAlgorithm)
                            .signingAlgorithm(signingAlgorithm)
                            .build())
                    .build();

            String caArn = client.createCertificateAuthority(createCARequest).get().certificateAuthorityArn();

            DescribeCertificateAuthorityRequest describeCARequest = DescribeCertificateAuthorityRequest.builder()
                    .certificateAuthorityArn(caArn)
                    .build();

            return client.describeCertificateAuthority(describeCARequest).get().certificateAuthority();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getCACertificate() {
        try {
            GetCertificateAuthorityCertificateRequest getCACertificateRequest = GetCertificateAuthorityCertificateRequest.builder()
                    .certificateAuthorityArn(ca.arn())
                    .build();

            return client.getCertificateAuthorityCertificate(getCACertificateRequest).get().certificate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private List<CertificateAuthority> listCAs() {
        try {
            String nextToken = null;
            List<CertificateAuthority> discoveredCAs = new ArrayList<>();
            do {
                ListCertificateAuthoritiesResponse results = client.listCertificateAuthorities(ListCertificateAuthoritiesRequest.builder()
                        .nextToken(nextToken).build()).get();

                discoveredCAs.addAll(results.certificateAuthorities());
                nextToken = results.nextToken();
            } while (Objects.nonNull(nextToken));

            System.out.println("Discovered "+ discoveredCAs.size() + " CA's");
            return discoveredCAs;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getCACSR() {
        System.out.println("Retrieving CA CSR for arn=" + ca.arn());

        try {
            GetCertificateAuthorityCsrRequest getCACSRRequest = GetCertificateAuthorityCsrRequest.builder()
                    .certificateAuthorityArn(ca.arn())
                    .build();

            AcmPcaAsyncWaiter asyncWaiter = client.waiter();
            CompletableFuture<WaiterResponse<GetCertificateAuthorityCsrResponse>> waiterResponse = asyncWaiter
                    .waitUntilCertificateAuthorityCSRCreated(getCACSRRequest);

            String caCSR = waiterResponse.join().matched().response().get().csr();

            System.out.println("CA CSR for arn=" + ca.arn() + ":\n" + caCSR);

            return caCSR;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private GetCertificateResponse getCertificate(final CertificateAuthority ca, final String certificateArn) {
        System.out.println("Retrieving certificate for arn=" + certificateArn);

        try {
            GetCertificateRequest getCertificateRequest = GetCertificateRequest.builder()
                    .certificateAuthorityArn(ca.arn())
                    .certificateArn(certificateArn)
                    .build();

            AcmPcaAsyncWaiter asyncWaiter = client.waiter();

            CompletableFuture<WaiterResponse<GetCertificateResponse>> waiterResponse = asyncWaiter.waitUntilCertificateIssued(getCertificateRequest);
            GetCertificateResponse response = waiterResponse.join().matched().response().get();

            System.out.println("GetCertificateResponse: "
                    + "Status Code:" + response.sdkHttpResponse().statusCode()
                    + ", Status Text:" + response.sdkHttpResponse().statusText().orElseGet(() -> "None")
                    + ", Headers: " + response.sdkHttpResponse().headers());
            System.out.println("Certificate for arn=" + certificateArn + ":\nChain= " + response.certificateChain() + "\nCert= " + response.certificate());

            return response;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String activateRootCA() {
        String caCSR = getCACSR();
        System.out.println("Issuing CA certificate for for arn=" + ca.arn());

        try {
            Validity validity = Validity.builder()
                    .type(ValidityPeriodType.YEARS)
                    .value(10L)
                    .build();

            IssueCertificateRequest issueCertificateRequest = IssueCertificateRequest.builder()
                    .idempotencyToken(UUID.randomUUID().toString())
                    .certificateAuthorityArn(ca.arn())
                    .csr(SdkBytes.fromByteArray(caCSR.getBytes()))
                    .signingAlgorithm(signingAlgorithm)
                    .templateArn("arn:aws:acm-pca:::template/RootCACertificate/V1")
                    .validity(validity)
                    .build();

            String caCertificateArn = client.issueCertificate(issueCertificateRequest).get().certificateArn();

            GetCertificateResponse getCertificateResult = getCertificate(ca, caCertificateArn);

            System.out.println("Importing CA certificate for for arn=" + ca.arn());

            ImportCertificateAuthorityCertificateRequest importCACertRequest = ImportCertificateAuthorityCertificateRequest.builder()
                    .certificateAuthorityArn(ca.arn())
                    .certificate(SdkBytes.fromByteArray(getCertificateResult.certificate().getBytes()))
                    .build();

            client.importCertificateAuthorityCertificate(importCACertRequest).get();

            return getCertificateResult.certificate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String activateSubordinateCA(final CertificateAuthority issuingCA) {
        String caCSR = getCACSR();

        System.out.println("Issuing CA certificate for for arn=" + ca.arn());

        try {
            Validity validity = Validity.builder()
                    .type(ValidityPeriodType.YEARS)
                    .value(5L)
                    .build();

            IssueCertificateRequest issueCertificateRequest = IssueCertificateRequest.builder()
                    .idempotencyToken(UUID.randomUUID().toString())
                    .certificateAuthorityArn(issuingCA.arn())
                    .csr(SdkBytes.fromByteArray(caCSR.getBytes()))
                    .signingAlgorithm(signingAlgorithm)
                    .templateArn("arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1")
                    .validity(validity)
                    .build();

            String caCertificateArn = client.issueCertificate(issueCertificateRequest).get().certificateArn();

            GetCertificateResponse getCertificateResult = getCertificate(issuingCA, caCertificateArn);

            System.out.println("Importing CA certificate for for arn=" + ca.arn());

            ImportCertificateAuthorityCertificateRequest importCACertRequest = ImportCertificateAuthorityCertificateRequest.builder()
                    .certificateAuthorityArn(ca.arn())
                    .certificateChain(SdkBytes.fromByteArray(getCertificateResult.certificateChain().getBytes()))
                    .certificate(SdkBytes.fromByteArray(getCertificateResult.certificate().getBytes()))
                    .build();

            client.importCertificateAuthorityCertificate(importCACertRequest);

            return getCertificateResult.certificate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public GetCertificateResponse issueCodeSigningCertificate(final String csr) {
        System.out.println("Issuing code signing certificate for for arn=" + ca.arn());

        try {
            Validity validity = Validity.builder()
                    .type(ValidityPeriodType.YEARS)
                    .value(1L)
                    .build();

            IssueCertificateRequest issueCertificateRequest = IssueCertificateRequest.builder()
                    .idempotencyToken(UUID.randomUUID().toString())
                    .certificateAuthorityArn(ca.arn())
                    .csr(SdkBytes.fromByteArray(csr.getBytes()))
                    .signingAlgorithm(signingAlgorithm)
                    .templateArn("arn:aws:acm-pca:::template/CodeSigningCertificate/V1")
                    .validity(validity)
                    .build();

            String certificateArn = client.issueCertificate(issueCertificateRequest).get().certificateArn();

            GetCertificateRequest getCertificateRequest = GetCertificateRequest.builder()
                    .certificateAuthorityArn(ca.arn())
                    .certificateArn(certificateArn)
                    .build();

            AcmPcaAsyncWaiter asyncWaiter = client.waiter();
            CompletableFuture<WaiterResponse<GetCertificateResponse>> waiterResponse = asyncWaiter.waitUntilCertificateIssued(getCertificateRequest);
            GetCertificateResponse response = waiterResponse.join().matched().response().get();

            System.out.println("Generated code signing certificate:\n" + response.certificate());

            return response;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return "PrivateCA{" +
                "commonName='" + commonName + '\'' +
                ", type=" + type +
                ", keyAlg=" + keyAlgorithm +
                ", signingAlg=" + signingAlgorithm +
                '}';
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private PrivateCA issuer;
        private String commonName;
        private CertificateAuthorityType type;
        private KeyAlgorithm keyAlgorithm;
        private SigningAlgorithm signingAlgorithm;

        private Builder() {}

        public Builder withIssuer(final PrivateCA issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder withCommonName(final String commonName) {
            this.commonName = commonName;
            return this;
        }

        public Builder withType(final CertificateAuthorityType type) {
            this.type = type;
            return this;
        }

        public Builder withKeyAlgorithm(final KeyAlgorithm keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
            return this;
        }

        public Builder withSigningAlgorithm(final SigningAlgorithm signingAlgorithm) {
            this.signingAlgorithm = signingAlgorithm;
            return this;
        }

        public PrivateCA getOrCreate() {
            return new PrivateCA(Optional.ofNullable(issuer), commonName, type, keyAlgorithm, signingAlgorithm);
        }
    }
}
