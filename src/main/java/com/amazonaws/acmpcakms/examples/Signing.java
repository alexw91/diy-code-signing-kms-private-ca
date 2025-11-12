package com.amazonaws.acmpcakms.examples;


import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.*;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Objects;

public class Signing {

    public static Signature generateSignature(final AsymmetricCMK cmk, final byte[] encoded) throws Exception {
        ContentSigner contentSigner = new KMSCMKContentSignerBuilder(cmk).build();

        OutputStream outputStream = contentSigner.getOutputStream();
        outputStream.write(encoded);
        outputStream.close();

        byte[] signature = contentSigner.getSignature();

        return new Signature(cmk.getSigningAlg(), signature);
    }

    public static PKCS10CertificationRequest sign(final AsymmetricCMK cmk, final PKCS10CertificationRequestBuilder csrBuilder) {
        ContentSigner contentSigner = new KMSCMKContentSignerBuilder(cmk).build();

        return csrBuilder.build(contentSigner);
    }
    private static AlgorithmIdentifier findAlgorithmIdentifier(final SigningAlgorithmSpec signatureAlgorithm) {
        SignatureAlgorithmIdentifierFinder algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder();
        switch (signatureAlgorithm.name()) {
            case "RSASSA_PSS_SHA_256":
                return algorithmIdentifier.find("SHA256WITHRSAANDMGF1");
            case "RSASSA_PSS_SHA_384":
                return algorithmIdentifier.find("SHA384WITHRSAANDMGF1");
            case "RSASSA_PSS_SHA_512":
                return algorithmIdentifier.find("SHA512WITHRSAANDMGF1");
            case "RSASSA_PKCS1_V1_5_SHA_256":
                return algorithmIdentifier.find("SHA256WITHRSA");
            case "RSASSA_PKCS1_V1_5_SHA_384":
                return algorithmIdentifier.find("SHA384WITHRSA");
            case "RSASSA_PKCS1_V1_5_SHA_512":
                return algorithmIdentifier.find("SHA512WITHRSA");
            case "ECDSA_SHA_256":
                return algorithmIdentifier.find("SHA256WITHECDSA");
            case "ECDSA_SHA_384":
                return algorithmIdentifier.find("SHA384WITHECDSA");
            case "ECDSA_SHA_512":
                return algorithmIdentifier.find("SHA512WITHECDSA");
            default:
                throw new IllegalArgumentException("SignatureAlgorithm " + signatureAlgorithm + " is not supported");
        }
    }

    private static class KMSCMKContentSignerBuilder {
        private final AsymmetricCMK cmk;

        public KMSCMKContentSignerBuilder(final AsymmetricCMK cmk) {
            this.cmk = cmk;
        }

        public ContentSigner build() {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            AlgorithmIdentifier algorithmIdentifier = findAlgorithmIdentifier(cmk.getSigningAlg());

            return new ContentSigner() {
                @Override
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return algorithmIdentifier;
                }

                @Override
                public OutputStream getOutputStream() {
                    return outputStream;
                }

                @Override
                public byte[] getSignature() {
                    KmsAsyncClient client = cmk.getClient();
                    String keyId = cmk.getKeyId();
                    byte[] input = outputStream.toByteArray();

                    System.out.println("Generating signature with key=" + cmk.getKeyId() + " for input " + Base64.getEncoder().encodeToString(input));

                    SdkBytes message = SdkBytes.fromByteArray(input);

                    try {
                        SignRequest signRequest = SignRequest.builder()
                                .keyId(keyId)
                                .signingAlgorithm(cmk.getSigningAlg())
                                .message(message)
                                .build();

                        byte[] signature = client.sign(signRequest).get()
                                .signature()
                                .asByteArray();

                        System.out.println("Signature with key=" + keyId + ": " + Base64.getEncoder().encodeToString(signature));

                        return signature;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            };
        }
    }

    public static class Signature {
        private final AlgorithmIdentifier algorithmIdentifier;
        private final DERBitString signature;

        public Signature(final SigningAlgorithmSpec signatureAlgorithm, final byte[] signature) {
            this.algorithmIdentifier = findAlgorithmIdentifier(signatureAlgorithm);
            this.signature = new DERBitString(signature);
        }

        public Signature(final AlgorithmIdentifier algorithmIdentifier, final DERBitString signature) {
            if (Objects.isNull(algorithmIdentifier)) {
                throw new IllegalArgumentException("An algorithm identifier must be specified");
            }

            if (Objects.isNull(signature)) {
                throw new IllegalArgumentException("A signature must be specified");
            }

            this.algorithmIdentifier = algorithmIdentifier;
            this.signature = signature;
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algorithmIdentifier;
        }

        public DERBitString getSignature() {
            return signature;
        }
    }
}
