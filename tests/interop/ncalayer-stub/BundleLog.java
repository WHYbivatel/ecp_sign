package kz.gov.pki.knca.applet.osgi;

// Development-only stand-in for knca_applet's OSGi log, whose static initializer needs a bundle
// context. Put it before knca_applet on the classpath of AppletReference; Applet code stays official.
public enum BundleLog {
  LOG;

  public void discoverLogService() {}
  public void info(String msg) { System.err.println("[applet] " + msg); }
  public void debug(String msg) { System.err.println("[applet] " + msg); }
  public void error(String msg, Throwable e) { System.err.println("[applet] " + msg + " " + e); }
  public void log(int level, String msg) { System.err.println("[applet] " + msg); }
  public void log(int level, String msg, Throwable e) { System.err.println("[applet] " + msg + " " + e); }
}
