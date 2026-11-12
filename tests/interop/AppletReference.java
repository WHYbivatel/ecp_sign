import java.awt.Window;
import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import javax.swing.*;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.knca.applet.Applet;
import kz.gov.pki.knca.applet.filechooser.gui.FileChooser;
import org.json.*;

// Development-only reference run of NCALayer's legacy Applet module (knca_applet 0.4.10, Kalkan 0.7.8)
// for the NUC password page: browseKeyStore with NCALayer's own file dialog, then changePassword with
// the returned path. dispatch() mirrors KNCAAppletActivator: method by name and argument count, the
// ResultWrapper serialized by JSONObject.wrap. Needs a display (xvfb-run). Passwords come from
// TEGIN_TEST_P12_PASSWORD and TEGIN_TEST_NEW_PASSWORD and are never printed; the selected path is masked.
// Usage: AppletReference <container to change> <untouched copy of the original>
public class AppletReference {
  static Applet applet;

  static String dispatch(String jsonString) {
    try {
      JSONObject request = new JSONObject(jsonString);
      String name = request.getString("method");
      JSONArray args = request.optJSONArray("args");
      int count = args != null ? args.length() : 0;
      Method method = null;
      for (Method candidate : applet.getClass().getDeclaredMethods())
        if (candidate.getName().equals(name) && candidate.getParameterTypes().length == count) { method = candidate; break; }
      if (method == null) throw new NoSuchMethodException();
      Object[] values = new Object[count];
      for (int i = 0; i < count; i++) values[i] = args.isNull(i) ? null : args.get(i);
      return JSONObject.wrap(method.invoke(applet, values)).toString();
    } catch (Exception e) {
      for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) System.err.println("cause: " + cause.getClass().getName() + " at " + (cause.getStackTrace().length > 0 ? cause.getStackTrace()[0] : "?"));
      return new JSONStringer().object().key("errorCode").value(e + ". Method: ").endObject().toString();
    }
  }

  static FileChooser waitForChooser(Thread call, String[] answer) throws Exception {
    for (int attempt = 0; attempt < 200; attempt++) {
      if (!call.isAlive()) throw new Exception("browseKeyStore returned without a dialog: " + answer[0]);
      for (Window window : Window.getWindows()) {
        if (!window.isShowing()) continue;
        FileChooser found = find(window);
        if (found != null) return found;
      }
      Thread.sleep(50);
    }
    throw new Exception("NCALayer file dialog did not open");
  }
  static FileChooser find(java.awt.Container container) {
    for (java.awt.Component child : container.getComponents()) {
      if (child instanceof FileChooser) return (FileChooser) child;
      if (child instanceof java.awt.Container) { FileChooser nested = find((java.awt.Container) child); if (nested != null) return nested; }
    }
    return null;
  }

  // Calls browseKeyStore on a worker thread and answers NCALayer's modal dialog like a user would.
  static String browse(File select) throws Exception {
    String[] answer = new String[1];
    String request = new JSONObject().put("method", "browseKeyStore").put("args", new JSONArray().put("PKCS12").put("P12").put(select.getParent())).toString();
    Thread call = new Thread(() -> answer[0] = dispatch(request));
    call.start();
    FileChooser chooser = waitForChooser(call, answer);
    SwingUtilities.invokeAndWait(() -> { if (select.exists()) { chooser.setSelectedFile(select); chooser.approveSelection(); } else chooser.cancelSelection(); });
    call.join(20000);
    return answer[0];
  }

  static String change(String path, String oldPassword, String newPassword) {
    return dispatch(new JSONObject().put("method", "changePassword").put("args", new JSONArray().put("PKCS12").put(path).put(oldPassword).put(newPassword)).toString());
  }

  static KeyStore load(Path path, String password) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12", "KALKAN");
    try (InputStream in = Files.newInputStream(path)) { store.load(in, password.toCharArray()); }
    return store;
  }
  // Every key entry of a has the same private key and certificate chain in b.
  static boolean sameContents(KeyStore a, String passwordA, KeyStore b, String passwordB) throws Exception {
    List<String> keysA = new ArrayList<>(), keysB = new ArrayList<>();
    for (String alias : Collections.list(a.aliases())) if (a.isKeyEntry(alias)) keysA.add(Base64.getEncoder().encodeToString(a.getKey(alias, passwordA.toCharArray()).getEncoded()) + chain(a, alias));
    for (String alias : Collections.list(b.aliases())) if (b.isKeyEntry(alias)) keysB.add(Base64.getEncoder().encodeToString(b.getKey(alias, passwordB.toCharArray()).getEncoded()) + chain(b, alias));
    Collections.sort(keysA); Collections.sort(keysB);
    return !keysA.isEmpty() && keysA.equals(keysB);
  }
  static String chain(KeyStore store, String alias) throws Exception {
    StringBuilder text = new StringBuilder();
    Certificate[] certificates = store.getCertificateChain(alias);
    if (certificates == null) certificates = new Certificate[] { store.getCertificate(alias) };
    for (Certificate certificate : certificates) text.append('|').append(Base64.getEncoder().encodeToString(certificate.getEncoded()));
    return text.toString();
  }

  public static void main(String[] args) throws Exception {
    Security.addProvider(new KalkanProvider());
    applet = new Applet(new KalkanProvider());
    String oldPassword = System.getenv("TEGIN_TEST_P12_PASSWORD"), newPassword = System.getenv("TEGIN_TEST_NEW_PASSWORD");
    File container = new File(args[0]);
    Path original = Paths.get(args[1]);
    String mask = container.getPath();
    JSONObject report = new JSONObject();

    String browsed = browse(container);
    report.put("browseKeyStore", new JSONObject(browsed.replace(JSONObject.quote(mask), "\"<selected file>\"")));
    report.put("browseKeyStoreCancel", new JSONObject(browse(new File(container.getParent(), "missing-on-purpose.p12"))));
    String path = new JSONObject(browsed).optString("result");
    if (!mask.equals(path)) throw new Exception("browseKeyStore did not return the selected path");

    byte[] before = Files.readAllBytes(container.toPath());
    report.put("changePasswordWrongOld", new JSONObject(change(path, oldPassword + "x", newPassword)));
    report.put("changePasswordWeakNew", new JSONObject(change(path, oldPassword, "onlyletters")));
    report.put("unchangedAfterRefusals", Arrays.equals(before, Files.readAllBytes(container.toPath())));
    report.put("changePassword", new JSONObject(change(path, oldPassword, newPassword)));
    report.put("fileOverwrittenInPlace", !Arrays.equals(before, Files.readAllBytes(container.toPath())));

    KeyStore changed = load(container.toPath(), newPassword);
    report.put("opensWithNewPassword", true);
    boolean oldRejected;
    try { load(container.toPath(), oldPassword); oldRejected = false; } catch (Exception e) { oldRejected = true; }
    report.put("oldPasswordRejected", oldRejected);
    report.put("sameKeyAndCertificates", sameContents(load(original, oldPassword), oldPassword, changed, newPassword));
    System.out.println(report.toString(1));
  }
}
