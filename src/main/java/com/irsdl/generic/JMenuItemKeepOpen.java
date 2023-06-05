// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)

package com.irsdl.generic;

import javax.swing.*;
import java.awt.event.MouseEvent;

public class JMenuItemKeepOpen extends JMenuItem {

    public JMenuItemKeepOpen(String text) {
        super(text);
    }

    @Override
    protected void processMouseEvent(MouseEvent evt) {
        if (evt.getID() == MouseEvent.MOUSE_RELEASED && contains(evt.getPoint())) {
            doClick();
            setArmed(true);
        } else {
            super.processMouseEvent(evt);
        }
    }

}
