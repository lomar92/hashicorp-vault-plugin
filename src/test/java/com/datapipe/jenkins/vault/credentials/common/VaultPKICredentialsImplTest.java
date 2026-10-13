package com.datapipe.jenkins.vault.credentials.common;

import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.util.Secret;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link VaultPKICredentialsImpl}.
 *
 * <p>These tests verify the private key parsing logic and value-object behaviour without
 * requiring a running Vault instance.  The {@code buildKeyStore} integration path (which requires
 * a real X.509 certificate) is exercised at the IT-test level.</p>
 */
public class VaultPKICredentialsImplTest {

    // ---- parsePrivateKey – PKCS#8 RSA (default Vault output) -----------------

    @Test
    public void parsePrivateKey_pkcs8Rsa_returnsRsaKey() throws Exception {
        KeyPair kp = generateRsaKeyPair();
        String pem = pkcs8Pem(kp.getPrivate());

        PrivateKey parsed = VaultPKICredentialsImpl.parsePrivateKey(pem);

        assertNotNull(parsed);
        assertEquals("RSA", parsed.getAlgorithm());
    }

    // ---- parsePrivateKey – PKCS#1 RSA (legacy Vault / custom config) ----------

    @Test
    public void parsePrivateKey_genuinePkcs1Rsa_matchesPkcs8Encoding() throws Exception {
        PrivateKey fromPkcs1 = VaultPKICredentialsImpl.parsePrivateKey(fixture("leaf-key-pkcs1.pem"));
        PrivateKey fromPkcs8 = VaultPKICredentialsImpl.parsePrivateKey(fixture("leaf-key-pkcs8.pem"));

        assertEquals("RSA", fromPkcs1.getAlgorithm());
        assertArrayEquals("PKCS#1 and PKCS#8 encodings must yield the same key",
            fromPkcs8.getEncoded(), fromPkcs1.getEncoded());
    }

    // ---- parsePrivateKey – unsupported formats --------------------------------

    @Test
    public void parsePrivateKey_ecSec1Format_throwsDescriptiveException() {
        String pem = "-----BEGIN EC PRIVATE KEY-----\nZmFrZWtleWRhdGE=\n-----END EC PRIVATE KEY-----";

        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.parsePrivateKey(pem));

        assertTrue("Exception message should mention SEC1 or EC",
            ex.getMessage().contains("SEC1") || ex.getMessage().contains("EC"));
    }

    @Test
    public void parsePrivateKey_unknownPemType_throwsDescriptiveException() {
        String pem = "-----BEGIN UNKNOWN TYPE-----\nZmFrZWtleWRhdGE=\n-----END UNKNOWN TYPE-----";

        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.parsePrivateKey(pem));

        assertTrue("Exception message should mention 'Unrecognised'",
            ex.getMessage().contains("Unrecognised"));
    }

    // ---- IssuedCertificate value object ----------------------------------------

    @Test
    public void issuedCertificate_storesAllFieldsConsistently() {
        Instant renewAfter = Instant.now().plusSeconds(3540);
        VaultPKICertificateBundle bundle = new VaultPKICertificateBundle(
            "cert-pem", Secret.fromString("key-pem"), "ca-pem", "ca-chain-pem");
        VaultPKICredentialsImpl.IssuedCertificate issued =
            new VaultPKICredentialsImpl.IssuedCertificate(
                bundle, Secret.fromString("lease-abc-123"), renewAfter);

        assertEquals("cert-pem", issued.bundle.getCertificatePem());
        assertEquals("key-pem", issued.bundle.getPrivateKeyPem().getPlainText());
        assertEquals("ca-pem", issued.bundle.getIssuingCaPem());
        assertEquals("ca-chain-pem", issued.bundle.getCaChainPem());
        assertEquals("lease-abc-123", issued.leaseId.getPlainText());
        assertEquals(renewAfter, issued.renewAfter);
    }

    // ---- buildKeyStore – full intermediate/root chain --------------------------

    @Test
    public void buildKeyStore_intermediateChain_storesOrderedChainWithMatchingKey() throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore ks = VaultPKICredentialsImpl.buildKeyStore(fixture("leaf.pem"),
            fixture("leaf-key-pkcs8.pem"), fixture("ca-chain.pem"), password);

        assertTrue(ks.isKeyEntry("vault-pki"));
        Certificate[] chain = ks.getCertificateChain("vault-pki");
        assertEquals("leaf, intermediate and root expected", 3, chain.length);
        assertEquals(subject("leaf.pem"), ((X509Certificate) chain[0]).getSubjectX500Principal());
        assertEquals(subject("intermediate.pem"),
            ((X509Certificate) chain[1]).getSubjectX500Principal());
        assertEquals(subject("root.pem"), ((X509Certificate) chain[2]).getSubjectX500Principal());
        // each certificate must be signed by the next one in the chain
        chain[0].verify(chain[1].getPublicKey());
        chain[1].verify(chain[2].getPublicKey());
        chain[2].verify(chain[2].getPublicKey());

        // the stored private key must belong to the leaf certificate
        PrivateKey key = (PrivateKey) ks.getKey("vault-pki", password);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(new byte[]{1, 2, 3});
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(chain[0].getPublicKey());
        verifier.update(new byte[]{1, 2, 3});
        assertTrue("private key does not match the leaf certificate", verifier.verify(signature));
    }

    @Test
    public void buildKeyStore_rootOnlyChain_storesLeafAndIssuer() throws Exception {
        KeyStore ks = VaultPKICredentialsImpl.buildKeyStore(fixture("leaf.pem"),
            fixture("leaf-key-pkcs1.pem"), fixture("intermediate.pem"), "changeit".toCharArray());

        assertEquals(2, ks.getCertificateChain("vault-pki").length);
    }

    // ---- computeRenewAfter -------------------------------------------------------

    @Test
    public void computeRenewAfter_regularLifetime_renewsOneMinuteBeforeExpiry() {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant notAfter = issuedAt.plus(Duration.ofHours(1));

        assertEquals(notAfter.minusSeconds(60),
            VaultPKICredentialsImpl.computeRenewAfter(issuedAt, notAfter));
    }

    @Test
    public void computeRenewAfter_shortLifetime_staysBetweenIssuanceAndExpiry() {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant notAfter = issuedAt.plusSeconds(40);

        Instant renewAfter = VaultPKICredentialsImpl.computeRenewAfter(issuedAt, notAfter);

        assertEquals(issuedAt.plusSeconds(20), renewAfter);
        assertTrue(renewAfter.isAfter(issuedAt));
        assertTrue(renewAfter.isBefore(notAfter));
    }

    @Test
    public void computeRenewAfter_alreadyExpired_renewsImmediately() {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");

        assertEquals(issuedAt,
            VaultPKICredentialsImpl.computeRenewAfter(issuedAt, issuedAt.minusSeconds(5)));
    }

    // ---- buildIssuePath ------------------------------------------------------------

    @Test
    public void buildIssuePath_validMountAndRole_buildsIssuePath() {
        assertEquals("pki-int/issue/jenkins",
            VaultPKICredentialsImpl.buildIssuePath("pki-int", "jenkins"));
        assertEquals("teams/a/pki_v2/issue/web.client",
            VaultPKICredentialsImpl.buildIssuePath("teams/a/pki_v2", "web.client"));
    }

    @Test
    public void buildIssuePath_traversalOrInjection_isRejected() {
        String[][] invalid = {
            {"pki/../sys", "role"}, {"..", "role"}, {"pki/", "role"}, {"/pki", "role"},
            {"pki", "../../sys/policy/x"}, {"pki", "a/b"}, {"pki", ".."}, {"pki", "r?x=1"},
            {"pki", "r#x"}, {"pki", "r%2e%2e"}, {"pki", ""}, {"", "role"}, {null, "role"},
            {"pki", null}
        };
        for (String[] c : invalid) {
            assertThrows("expected rejection of mount=" + c[0] + " role=" + c[1],
                VaultPluginException.class, () -> VaultPKICredentialsImpl.buildIssuePath(c[0], c[1]));
        }
    }

    // ---- keystore password -----------------------------------------------------------

    @Test
    public void getPassword_isStablePerCredentialInstance() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "id", "desc");

        assertEquals(cred.getPassword().getPlainText(), cred.getPassword().getPlainText());
        assertNotEquals(cred.getPassword().getPlainText(),
            new VaultPKICredentialsImpl(null, "id2", "desc").getPassword().getPlainText());
    }

    // ---- checkResponseStatus ---------------------------------------------------

    @Test
    public void checkResponseStatus_success_doesNotThrow() {
        VaultPKICredentialsImpl.checkResponseStatus(response(200, "{\"data\":{}}"), "pki/issue/r");
    }

    @Test
    public void checkResponseStatus_vaultError_includesVaultMessage() {
        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.checkResponseStatus(
                response(400, "{\"errors\":[\"unknown role: nope\"]}"), "pki/issue/nope"));

        assertTrue(ex.getMessage(), ex.getMessage().contains("HTTP 400"));
        assertTrue(ex.getMessage(), ex.getMessage().contains("unknown role: nope"));
    }

    @Test
    public void checkResponseStatus_nonJsonBody_reportsStatusOnly() {
        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.checkResponseStatus(
                response(503, "<html>unavailable</html>"), "pki/issue/r"));

        assertTrue(ex.getMessage(), ex.getMessage().contains("HTTP 503"));
    }

    // ---- VaultPKICredentialsImpl field defaults --------------------------------

    @Test
    public void getPkiMount_returnsDefaultWhenNotSet() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        assertEquals(VaultPKICredentialsImpl.DEFAULT_PKI_MOUNT, cred.getPkiMount());
    }

    @Test
    public void getTtl_returnsDefaultWhenNotSet() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        assertEquals(VaultPKICredentialsImpl.DEFAULT_TTL, cred.getTtl());
    }

    @Test
    public void issueCertificate_blankRole_throwsDescriptiveException() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        cred.setCommonName("jenkins.example.com");
        // pkiRole is blank

        VaultPluginException ex = assertThrows(VaultPluginException.class, cred::getKeyStore);
        assertTrue("Exception message should mention pkiRole",
            ex.getMessage().contains("pkiRole"));
    }

    @Test
    public void issueCertificate_blankCommonName_throwsDescriptiveException() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        cred.setPkiRole("jenkins");
        // commonName is blank

        VaultPluginException ex = assertThrows(VaultPluginException.class, cred::getKeyStore);
        assertTrue("Exception message should mention commonName",
            ex.getMessage().contains("commonName"));
    }

    // ---- helpers ---------------------------------------------------------------

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /**
     * Encodes a private key in PKCS#8 PEM format, as Vault PKI returns by default.
     */
    private String pkcs8Pem(PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
            + "\n-----END PRIVATE KEY-----";
    }

    private static LogicalResponse response(int status, String body) {
        RestResponse rest = new RestResponse(status, "application/json",
            body.getBytes(StandardCharsets.UTF_8));
        return new LogicalResponse(rest, 0, Logical.logicalOperations.writeV1);
    }

    private static String fixture(String name) throws Exception {
        try (InputStream in = VaultPKICredentialsImplTest.class.getResourceAsStream("pki/" + name)) {
            assertNotNull("missing test fixture " + name, in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static X500Principal subject(String name) throws Exception {
        return ((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(fixture(name).getBytes(StandardCharsets.UTF_8))))
            .getSubjectX500Principal();
    }
}
