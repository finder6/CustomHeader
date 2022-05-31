package burp.execjs;

import burp.BurpExtender;
import burp.IBurpExtender;
import burp.execjs.engine.RhinoEngine;
import java.nio.charset.StandardCharsets;

public class ExecJSPayloadProcessor {
    private BurpExtender parent;
    private final IJsEngine jsEngine;

    public ExecJSPayloadProcessor(final IBurpExtender newParent, String CryptoJsCode, String MethodName) {
        this.parent = (BurpExtender) newParent;
        this.jsEngine = new RhinoEngine();
        this.jsEngine.setParent(parent);
        try {
            this.jsEngine.setConfig(CryptoJsCode, MethodName);
        } catch (Exception e) {
            this.parent.callbacks.issueAlert(e.toString());
            this.parent.stderr.println();
            e.printStackTrace(this.parent.stderr);
        }
    }

    public byte[] processPayload(byte[] currentPayload) {
        try {
            byte[] result = jsEngine.eval(new String(currentPayload, StandardCharsets.UTF_8)).getBytes("UTF-8");
            return result;
        } catch (Exception e) {
            this.parent.callbacks.issueAlert(e.toString());
            this.parent.stderr.println();
            e.printStackTrace(this.parent.stderr);
            return null;
        }
    }
}
