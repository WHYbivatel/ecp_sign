import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.io.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.gov.pki.kalkan.jce.provider.X509CertificateObject;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import org.apache.xml.security.signature.XMLSignature;

public class Verify {
 public static void main(String[] args) throws Exception {
  Security.addProvider(new KalkanProvider());
  if (args[0].equals("cms")) {
   byte[] data=Files.readAllBytes(Path.of(args[1]));
   CMSSignedData cms=args.length>2 ? new CMSSignedData(new CMSProcessableByteArray(Files.readAllBytes(Path.of(args[2]))),data) : new CMSSignedData(data);
   Collection signers=cms.getSignerInfos().getSigners();
   if(signers.size()!=1) throw new Exception("Unexpected signer count");
   SignerInformation signer=(SignerInformation)signers.iterator().next();
   java.security.cert.CertStore certificates=cms.getCertificatesAndCRLs("Collection","KALKAN");
   Collection certs=certificates.getCertificates(signer.getSID());
   System.out.println("Matching certificates: "+certs.size());
   if(certs.size()!=1 || !signer.verify((java.security.cert.X509Certificate)certs.iterator().next(),"KALKAN")) throw new Exception("CMS INVALID");
   if(signer.getUnsignedAttributes()!=null) {
    kz.gov.pki.kalkan.asn1.cms.Attribute attr=signer.getUnsignedAttributes().get(new kz.gov.pki.kalkan.asn1.DERObjectIdentifier("1.2.840.113549.1.9.16.2.14"));
    if(attr!=null) {
     kz.gov.pki.kalkan.tsp.TimeStampToken token=new kz.gov.pki.kalkan.tsp.TimeStampToken(kz.gov.pki.kalkan.asn1.cms.ContentInfo.getInstance(attr.getAttrValues().getObjectAt(0)));
     Collection tsaCerts=token.getCertificatesAndCRLs("Collection","KALKAN").getCertificates(token.getSID());
     if(tsaCerts.size()!=1) throw new Exception("TSA certificate ambiguous");
     token.validate((java.security.cert.X509Certificate)tsaCerts.iterator().next(),"KALKAN");
     byte[] imprint=MessageDigest.getInstance(token.getTimeStampInfo().getMessageImprintAlgOID(),"KALKAN").digest(signer.getSignature());
     if(!Arrays.equals(imprint,token.getTimeStampInfo().getMessageImprintDigest())) throw new Exception("Timestamp imprint mismatch");
     System.out.println("KALKAN TIMESTAMP VALID");
    }
   }
   System.out.println("KALKAN CMS VALID");
  } else {
   KncaXS.loadXMLSecurity();
   DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);
   f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
   Document d=f.newDocumentBuilder().parse(new File(args[1]));
   Element e=(Element)d.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","Signature").item(0);
   XMLSignature signature=new XMLSignature(e,"");
   java.security.cert.X509Certificate cert=signature.getKeyInfo().getX509Certificate();
   if(!signature.checkSignatureValue(cert)) throw new Exception("XML INVALID");
   System.out.println("KALKAN XML VALID");
  }
 }
}
