package rs.paxy;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

public class SmartCardSigner {

    public SmartCardSigner(String file, String signedFile, String pin)
            throws Exception {

        String configName = "pkcs11.cfg";
        Provider prototype = Security.getProvider("SunPKCS11");
        Provider provider1 = prototype.configure(configName);
        Security.addProvider(provider1);

        KeyStore smartCardKeyStore = null;

        try {
            smartCardKeyStore = KeyStore.getInstance("PKCS11");
        } catch (KeyStoreException e) {
            JOptionPane.showMessageDialog(null,
                    "SmartCard or Crypto modul is not present or installed.",
                    "Crypto module error!", JOptionPane.ERROR_MESSAGE);
            throw new Exception(
                    "SmartCard or Crypto modul is not present or installed.");
        }
        try {
            if (pin == null) {
                JPasswordField pf = new JPasswordField();
                int okCxl = JOptionPane.showConfirmDialog(null, pf, "Enter PIN",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.PLAIN_MESSAGE);

                if (okCxl == JOptionPane.OK_OPTION) {
                    pin = new String(pf.getPassword());
                } else
                    return;
            }
            smartCardKeyStore.load(null, pin.toCharArray());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null,
                    "Wrong PIN number. After few wrong PIN attempt modul will bolck any more attempts.",
                    "Crypto module error!", JOptionPane.ERROR_MESSAGE);
            throw new Exception(
                    "Wrong PIN number. After few wrong PIN attempt modul will bolck any more attempts.");
        }

        Enumeration aliasesEnum = smartCardKeyStore.aliases();
        String alias = (String) aliasesEnum.nextElement();

        X509Certificate cert = (X509Certificate) smartCardKeyStore
                .getCertificate(alias);
        System.out.println("Certificate loaded.");
        PrivateKey privateKey = (PrivateKey) smartCardKeyStore.getKey(alias,
                null);
        System.out.println("Private key functions loaded.");

        System.out.println("Signing PDF file.");

        Certificate[] chain = smartCardKeyStore.getCertificateChain(alias);

        sign(file, signedFile, chain, privateKey, DigestAlgorithms.SHA256,
                provider1.getName(), PdfSigner.CryptoStandard.CMS, null, null);

        System.out.println("PDF file signed.");
        JOptionPane.showMessageDialog(null, "PDF file signed.");

    }

    public void sign(String src, String dest, Certificate[] chain,
            PrivateKey pk, String digestAlgorithm, String provider,
            PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest),
                false);

        // Visible signature disabled
        /*
         * // Creating the appearance PdfSignatureAppearance appearance =
         * signer.getSignatureAppearance()
         * .setReason(reason).setLocation(location) .setReuseAppearance(false);
         * Rectangle rect = new Rectangle(36, 648, 200, 100);
         * appearance.setPageRect(rect).setPageNumber(1);
         */
        signer.setFieldName("sig");
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm,
                provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1)
            return;
        File input = new File(args[0]);
        if (!input.exists()) throw new Exception(
                "Invalid path to input file: "+args[0]);
        String path = input.getAbsoluteFile().getParent();
        String name = input.getName();
        if (!name.contains(".pdf")) throw new Exception(
                "PaxyPDFSigner supports only PDF input files.");
        String signedFile = path + "/" + name.replace(".pdf", "-signed.pdf");

        new SmartCardSigner(input.getAbsolutePath(), signedFile, null);
    }

}
