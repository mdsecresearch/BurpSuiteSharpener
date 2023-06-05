// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.capabilities.pwnFox;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;

public class PwnFoxProxyRequestHandler implements ProxyRequestHandler {
    SharpenerSharedParameters sharedParameters;

    public PwnFoxProxyRequestHandler(SharpenerSharedParameters sharedParameters){
        this.sharedParameters = sharedParameters;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        var headerList = interceptedRequest.headers();
        if (headerList != null) {
            boolean pwnFoxSupportCapability = sharedParameters.preferences.safeGetSetting("pwnFoxSupportCapability", false);
            if (pwnFoxSupportCapability) {
                for(var item : headerList){
                    if(item.name().equalsIgnoreCase("x-pwnfox-color")) {
                        var pwnFoxColor = item.value();
                        if (!pwnFoxColor.isEmpty()) {
                            interceptedRequest.annotations().setHighlightColor(HighlightColor.highlightColor(pwnFoxColor));
                        }
                        return ProxyRequestReceivedAction.continueWith(interceptedRequest.withRemovedHeader("X-PwnFox-Color"));
                    }
                }
            }
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

}
