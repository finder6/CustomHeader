package CH;
import burp.*;
import burp.execjs.ExecJSPayloadProcessor;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;


public class CustomHeader implements IBurpExtender, ITab, IProxyListener, IHttpListener, ISessionHandlingAction {
    public static IBurpExtenderCallbacks callbacks;
    private JScrollPane MainPanelTab;
    private CustomHeaderGUI panel;
    private PrintWriter mStdOut;
    public PrintWriter stderr;
    private IExtensionHelpers helpers;
    private ExecJSPayloadProcessor jsProcessor;
    
    /**
     * 
     * Implement IBurpExtender
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        CustomHeader.callbacks = callbacks;
        callbacks.registerSessionHandlingAction(this);
        callbacks.setExtensionName("Custom Header");
        mStdOut = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        helpers = callbacks.getHelpers();
        // 初始化js引擎
        File file = new File("D:\\security_weapons\\tool\\burp_plugins\\CustomHeader\\sign.js");
        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            StringBuffer sb = new StringBuffer();
            String st = null;
            while ((st = reader.readLine()) != null) {
                sb.append(st).append("\n");
            }
            jsProcessor = new ExecJSPayloadProcessor(this, sb.toString(), "requestSign");
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }
        SwingUtilities.invokeLater(() -> {
            panel = new CustomHeaderGUI(this);
            MainPanelTab = new JScrollPane(panel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.addSuiteTab(this);
            callbacks.printOutput("- Custom Header v1.0");
            callbacks.printOutput("- Created by finder6");

        });

    }
   
   
    @Override
    public String getActionName() {
        return "Custom Header";
    }
    
    public void ConfigHeader(List header){header.toString();}
    @Override
    public void processHttpMessage(int toolFlag,
                                   boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo)
    {
        if (messageIsRequest) {
            IRequestInfo infoReq = helpers.analyzeRequest(messageInfo.getRequest());
            byte[] bodyReq  = Arrays.copyOfRange(messageInfo.getRequest(), infoReq.getBodyOffset(), messageInfo.getRequest().length);
            String POSTbodyReq = new String(bodyReq);
            List<String> headers = infoReq.getHeaders();
            if(panel.getMethod().contains(infoReq.getMethod())){
                if (panel.getDebug() == true) mStdOut.println("[+] Request Method: " + infoReq.getMethod());
                try{
                    panel.getHeader().forEach((n) -> {
                        if(n.length()>0) headers.add(n);
                    });
                }catch(NullPointerException e){
                    mStdOut.println("[!] ERROR : Header Not Save ! Please Click Save Button !");
                }
                // 校验头sign处理
                String sign = null;
                for(Iterator<String> iter = headers.listIterator(); iter.hasNext(); ) {
                    String n = iter.next();
                    if(n.startsWith("Sign:")) {
                        if (panel.getDebug() == true) mStdOut.println("[+] Process request sign");
                        sign = new String(jsProcessor.processPayload(bodyReq));
                        iter.remove();
                        break;
                    }
                }
                if(sign != null) {
                    headers.add("Sign: " + sign);
                }
            }
            if (panel.getDebug() == true) mStdOut.println("[+] Request Header: " + headers.toString());
            messageInfo.setRequest(helpers.buildHttpMessage(headers, POSTbodyReq.getBytes()));
        }

    }
    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {

    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

    }

    @Override
    public String getTabCaption() {
        return "Custom Header";
    }

    @Override
    public Component getUiComponent() {
        return MainPanelTab;
    }
}
