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
        //this.mouseEventConsumer.accept(e);
    }

    @Override
    public void mousePressed(MouseEvent e) {
        //
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        // we can use mousePressed or mouseReleased instead of mouseClicked to detect a click when tabs were wrapped
        // mouseReleased has been used to show the menu in the right place when tabs were wrapped
        this.mouseEventConsumer.accept(e);
    }

    @Override
    public void mouseEntered(MouseEvent e) {
        //
    }

    @Override
    public void mouseExited(MouseEvent e) {
        //
    }
}
