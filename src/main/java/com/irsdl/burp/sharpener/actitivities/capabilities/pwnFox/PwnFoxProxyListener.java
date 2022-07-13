// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.actitivities.capabilities.pwnFox;

import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.generic.HTTPMessageHelper;

public class PwnFoxProxyListener implements IProxyListener {
    SharpenerSharedParameters sharedParameters;

    public PwnFoxProxyListener(SharpenerSharedParameters sharedParameters){
        this.sharedParameters = sharedParameters;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest) return;
        var messageInfo = message.getMessageInfo();

        if (messageInfo != null) {
            boolean pwnFoxSupportCapability = sharedParameters.preferences.safeGetSetting("pwnFoxSupportCapability", false);

            if (pwnFoxSupportCapability) {
                // From https://github.com/yeswehack/PwnFox/pull/8/commits/27bdb409ec7727f021f739abf50bbb9eb6c26e85
                var requestInfo = sharedParameters.callbacks.getHelpers().analyzeRequest(messageInfo);
                var body = messageInfo.getRequest();
                var bodyAndHeader = HTTPMessageHelper.getHeaderAndBody(body, requestInfo.getBodyOffset());
                var headerList = HTTPMessageHelper.getHeadersListFromHeader(bodyAndHeader.get(0));
                var pwnFoxColor = HTTPMessageHelper.getFirstHeaderValueByNameFromHeaders(headerList, "X-PwnFox-Color", false);
                if (!pwnFoxColor.isEmpty()) {
                    var cleanHeaders = HTTPMessageHelper.removeHeadersByName(headerList, "X-PwnFox-Color");
                    messageInfo.setHighlight(pwnFoxColor);
                    messageInfo.setRequest(sharedParameters.callbacks.getHelpers().buildHttpMessage(cleanHeaders, bodyAndHeader.get(1)));
                }
            }
        }
    }
}
