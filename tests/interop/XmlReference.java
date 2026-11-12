import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.xml.parsers.*;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import kz.gov.pki.provider.utils.XMLUtil;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.*;

// Development-only reference for XML signing with XPath and for co-signing: knca_provider_util 0.8.8
// XMLUtil (the code behind Common Utils 0.3.4 signXml/signXmls) on a synthetic key, with the key
// selection dialog skipped. Classpath: kalkancrypt, kalkancrypt_xmldsig and knca_provider_util from
// ncalayer.zip.
//   sign <key.p12> <password> <xml-file> <tbsElementXPath|-> <signatureParentElementXPath|->
//   official <xml-file> [signatureParentElementXPath]  — XMLUtil.verifyXmlSignature as NCALayer ships it
//   each <xml-file>  — every ds:Signature checked on its own (Santuario), one line per signature
public class XmlReference {
  static Document parse(String path) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    return factory.newDocumentBuilder().parse(new File(path));
  }

  public static void main(String[] args) throws Exception {
    Security.addProvider(new KalkanProvider());
    KncaXS.loadXMLSecurity();
    Provider provider = Security.getProvider("KALKAN");
    switch (args[0]) {
      case "sign" -> {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KALKAN");
        try (InputStream in = Files.newInputStream(Path.of(args[1]))) { keyStore.load(in, args[2].toCharArray()); }
        String alias = Collections.list(keyStore.aliases()).get(0);
        String xml = Files.readString(Path.of(args[3]), StandardCharsets.UTF_8);
        String tbs = args[4].equals("-") ? null : args[4], parent = args[5].equals("-") ? null : args[5];
        System.out.print(XMLUtil.createXmlSignature(xml, keyStore, alias, args[2].toCharArray(), tbs, parent, provider));
      }
      case "official" -> {
        XMLUtil.verifyXmlSignature(parse(args[1]), args.length > 2 ? args[2] : null, provider);
        System.out.println("OFFICIAL VALID");
      }
      case "each" -> {
        Document document = parse(args[1]);
        NodeList all = document.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
          Element element = (Element) all.item(i);
          if (element.hasAttribute("Id")) element.setIdAttribute("Id", true);
        }
        NodeList signatures = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        for (int i = 0; i < signatures.getLength(); i++) {
          XMLSignature signature = new XMLSignature((Element) signatures.item(i), "");
          X509Certificate cert = signature.getKeyInfo().getX509Certificate();
          boolean valid;
          try { valid = signature.checkSignatureValue(cert); } catch (Exception e) { valid = false; }
          System.out.println("SIGNATURE " + i + " " + (valid ? "VALID" : "INVALID") + " " + cert.getSubjectX500Principal().getName());
        }
      }
      default -> throw new IllegalArgumentException(args[0]);
    }
  }
}
