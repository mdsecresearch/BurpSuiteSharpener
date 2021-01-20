// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.subtabs;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

public class SubTabClickHandler extends MouseAdapter {

    Consumer<MouseEvent> mouseEventConsumer;

    public SubTabClickHandler(Consumer<MouseEvent> consumer) {
        this.mouseEventConsumer = consumer;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        this.mouseEventConsumer.accept(e);
    }
}
