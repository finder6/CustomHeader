package burp.execjs;

import burp.BurpExtender;
import burp.IBurpExtender;

public interface IJsEngine {
    void setParent(BurpExtender parent);
    String eval(String param) throws Exception;
    void setConfig(String cryptoJsCode, String methodName) throws Exception;
}