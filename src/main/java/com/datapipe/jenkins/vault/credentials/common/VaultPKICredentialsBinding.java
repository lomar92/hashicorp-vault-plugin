package com.datapipe.jenkins.vault.credentials.common;

import com.datapipe.jenkins.vault.WindowsFilePermissionHelper;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import jenkins.MasterToSlaveFileCallable;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.UnbindableDir;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import static org.apache.commons.lang3.StringUtils.defaultIfBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * Credential binding for {@link VaultPKICredentials} that exposes the issued certificate,
 * private key, and CA certificate as PEM files in the build workspace.
 *
 * <h2>Pipeline usage</h2>
 * <pre>{@code
 * withCredentials([vaultPKI(credentialsId: 'my-pki-cred',
 *                           certPemVariable: 'CERT_PEM',
 *                           privateKeyPemVariable: 'KEY_PEM',
 *                           caPemVariable: 'CA_PEM')]) {
 *     // Each variable holds a path to a temporary PEM file in the workspace.
 *     sh 'curl --cert $CERT_PEM --key $KEY_PEM --cacert $CA_PEM https://my-service'
 *     sh 'openssl verify -CAfile $CA_PEM $CERT_PEM'
 * }
 * }</pre>
 *
 * <p><strong>Security note:</strong> PEM files are written to a temporary directory that is
 * automatically deleted at the end of the {@code withCredentials} block.  The private key file
 * is created with {@code 0400} permissions (owner read-only) on POSIX systems and restricted to
 * the file owner on Windows; the binding fails if this cannot be enforced.  Avoid printing
 * the contents of {@code $KEY_PEM} to the build log.</p>
 */
public class VaultPKICredentialsBinding extends MultiBinding<VaultPKICredentials> {

    public static final String DEFAULT_CERT_PEM_VARIABLE = "VAULT_PKI_CERT";
    public static final String DEFAULT_KEY_PEM_VARIABLE = "VAULT_PKI_KEY";
    public static final String DEFAULT_CA_PEM_VARIABLE = "VAULT_PKI_CA";

    private String certPemVariable;
    // Holds the name of the environment variable that receives the key file path, not a secret.
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    private String privateKeyPemVariable;
    private String caPemVariable;

    @DataBoundConstructor
    public VaultPKICredentialsBinding(String credentialsId) {
        super(credentialsId);
        this.certPemVariable = DEFAULT_CERT_PEM_VARIABLE;
        this.privateKeyPemVariable = DEFAULT_KEY_PEM_VARIABLE;
        this.caPemVariable = DEFAULT_CA_PEM_VARIABLE;
    }

    @DataBoundSetter
    public void setCertPemVariable(@Nullable String certPemVariable) {
        this.certPemVariable = defaultIfBlank(certPemVariable, DEFAULT_CERT_PEM_VARIABLE);
    }

    @DataBoundSetter
    public void setPrivateKeyPemVariable(@Nullable String privateKeyPemVariable) {
        this.privateKeyPemVariable = defaultIfBlank(privateKeyPemVariable, DEFAULT_KEY_PEM_VARIABLE);
    }

    @DataBoundSetter
    public void setCaPemVariable(@Nullable String caPemVariable) {
        this.caPemVariable = defaultIfBlank(caPemVariable, DEFAULT_CA_PEM_VARIABLE);
    }

    public String getCertPemVariable() {
        return certPemVariable;
    }

    public String getPrivateKeyPemVariable() {
        return privateKeyPemVariable;
    }

    public String getCaPemVariable() {
        return caPemVariable;
    }

    @Override
    protected Class<VaultPKICredentials> type() {
        return VaultPKICredentials.class;
    }

    /**
     * Issues the PKI certificate once and writes the PEM components to temporary files in the
     * workspace.  The {@link UnbindableDir} ensures the files are deleted when the
     * {@code withCredentials} block exits.
     */
    @Override
    public MultiEnvironment bind(@NonNull Run<?, ?> build, FilePath workspace, Launcher launcher,
        TaskListener listener) throws IOException, InterruptedException {

        VaultPKICredentials credentials = getCredentials(build);

        // One snapshot of a single issuance: certificate, key and CA chain always belong together.
        // The CA chain (intermediate + root) lets openssl verify and mTLS clients validate the full
        // path without installing the root CA separately.
        VaultPKICertificateBundle bundle = credentials.getCertificateBundle();

        listener.getLogger().println("[VaultPKI] Writing PKI certificate PEM files to workspace");

        UnbindableDir tmpDir = UnbindableDir.create(workspace);

        Map<String, String> envMap = new HashMap<>();

        if (isNotBlank(certPemVariable)) {
            FilePath certFile = tmpDir.getDirPath().child("vault-pki-cert.pem");
            certFile.write(bundle.getCertificatePem(), "UTF-8");
            envMap.put(certPemVariable, certFile.getRemote());
        }

        if (isNotBlank(privateKeyPemVariable)) {
            FilePath keyFile = tmpDir.getDirPath().child("vault-pki-key.pem");
            writePrivateKey(keyFile, bundle.getPrivateKeyPem().getPlainText(), launcher.isUnix());
            envMap.put(privateKeyPemVariable, keyFile.getRemote());
        }

        if (isNotBlank(caPemVariable)) {
            FilePath caFile = tmpDir.getDirPath().child("vault-pki-ca.pem");
            caFile.write(bundle.getCaChainPem(), "UTF-8");
            envMap.put(caPemVariable, caFile.getRemote());
        }

        return new MultiEnvironment(envMap, tmpDir.getUnbinder());
    }

    /**
     * Writes the private key so that only the build user can read it.  The empty file is
     * restricted first ({@code 0600} on POSIX, owner-only ACL on Windows), so the key is never
     * readable by others, not even briefly; on POSIX it is made read-only ({@code 0400})
     * afterwards.  Any failure aborts the binding instead of leaving the key readable with
     * default permissions.
     */
    private static void writePrivateKey(FilePath keyFile, String keyPem, boolean unix)
        throws IOException, InterruptedException {
        keyFile.write("", "UTF-8");
        if (unix) {
            keyFile.chmod(0600);
            keyFile.write(keyPem, "UTF-8");
            keyFile.chmod(0400);
        } else {
            keyFile.act(new RestrictToOwnerOnWindows());
            keyFile.write(keyPem, "UTF-8");
        }
    }

    /** Applies {@link WindowsFilePermissionHelper#fixSshKeyOnWindows} on the agent owning the file. */
    private static final class RestrictToOwnerOnWindows extends MasterToSlaveFileCallable<Void> {
        private static final long serialVersionUID = 1L;

        @Override
        public Void invoke(File f, VirtualChannel channel) {
            WindowsFilePermissionHelper.fixSshKeyOnWindows(f.toPath());
            return null;
        }
    }

    @Override
    public Set<String> variables() {
        Set<String> vars = new HashSet<>();
        if (isNotBlank(certPemVariable)) {
            vars.add(certPemVariable);
        }
        if (isNotBlank(privateKeyPemVariable)) {
            vars.add(privateKeyPemVariable);
        }
        if (isNotBlank(caPemVariable)) {
            vars.add(caPemVariable);
        }
        return vars;
    }

    @Symbol("vaultPKI")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultPKICredentials> {

        @Override
        protected Class<VaultPKICredentials> type() {
            return VaultPKICredentials.class;
        }

        @Override
        public String getDisplayName() {
            return "Vault PKI Certificate (PEM files)";
        }

        public String getDefaultCertPemVariable() {
            return DEFAULT_CERT_PEM_VARIABLE;
        }

        public String getDefaultKeyPemVariable() {
            return DEFAULT_KEY_PEM_VARIABLE;
        }

        public String getDefaultCaPemVariable() {
            return DEFAULT_CA_PEM_VARIABLE;
        }
    }
}
