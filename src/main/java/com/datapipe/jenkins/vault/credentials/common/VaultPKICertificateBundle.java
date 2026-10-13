package com.datapipe.jenkins.vault.credentials.common;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;

/**
 * Immutable PEM material of a single Vault PKI issuance.
 *
 * <p>Certificate, private key and CA certificates always originate from the same Vault
 * {@code /issue} response, so consumers never combine a certificate with the private key of a
 * different issuance (which could otherwise happen when the cached certificate is renewed
 * between two separate getter calls).</p>
 */
public final class VaultPKICertificateBundle {

    private final String certificatePem;
    private final Secret privateKeyPem;
    private final String issuingCaPem;
    private final String caChainPem;

    public VaultPKICertificateBundle(@NonNull String certificatePem, @NonNull Secret privateKeyPem,
        @NonNull String issuingCaPem, @NonNull String caChainPem) {
        this.certificatePem = certificatePem;
        this.privateKeyPem = privateKeyPem;
        this.issuingCaPem = issuingCaPem;
        this.caChainPem = caChainPem;
    }

    /** PEM-encoded leaf certificate. */
    @NonNull
    public String getCertificatePem() {
        return certificatePem;
    }

    /** PEM-encoded private key of the leaf certificate. */
    @NonNull
    public Secret getPrivateKeyPem() {
        return privateKeyPem;
    }

    /** PEM-encoded direct issuer certificate ({@code issuing_ca}). */
    @NonNull
    public String getIssuingCaPem() {
        return issuingCaPem;
    }

    /** PEM-encoded CA chain ({@code ca_chain}), or the issuing CA for a root CA setup. */
    @NonNull
    public String getCaChainPem() {
        return caChainPem;
    }
}
