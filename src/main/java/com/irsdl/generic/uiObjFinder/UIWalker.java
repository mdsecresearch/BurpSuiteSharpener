// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic.uiObjFinder;

import javax.swing.*;
import java.awt.*;

public class UIWalker {
    public static Component FindUIObjectInComponents(Component rootUIObject, int maxDepth, UISpecObject uiSpecObject){
        Component foundObject = null;
        JComponent rootUIJComponent = null;
        if(rootUIObject instanceof JComponent){
            rootUIJComponent = (JComponent) rootUIObject;
        }else if(rootUIObject.getComponentAt(0,0) instanceof JComponent){
            rootUIJComponent = (JComponent) rootUIObject.getComponentAt(0,0);
        }

        if(rootUIJComponent!=null){
            if(uiSpecObject.isCompatible(rootUIJComponent)){
                foundObject = rootUIJComponent;
            }else {
                foundObject = FindUIObjectInComponents(rootUIJComponent, maxDepth, 0, uiSpecObject);
            }
        }

        return foundObject;
    }

    private static Component FindUIObjectInComponents(JComponent rootUIJComponent, int maxDepth, int currentDepth, UISpecObject uiSpecObject){
        Component foundObject = null;
        for(Component component:rootUIJComponent.getComponents()){
            if(uiSpecObject.isCompatible(component)){
                foundObject = component;
                break;
            }else if(currentDepth < maxDepth && component instanceof JComponent){
                foundObject = FindUIObjectInComponents((JComponent) component, maxDepth, currentDepth+1, uiSpecObject);
                if(foundObject!=null)
                    break;
            }
        }
        return foundObject;
    }
}
