// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic.uiObjFinder;

import javax.swing.*;
import java.awt.*;

public class UIWalker {
    public static JComponent GetCurrentJComponent(Component rootUIObject){
        JComponent rootUIJComponent = null;
        if(rootUIObject instanceof JComponent){
            rootUIJComponent = (JComponent) rootUIObject;
        }else if(rootUIObject.getComponentAt(0,0) instanceof JComponent){
            rootUIJComponent = (JComponent) rootUIObject.getComponentAt(0,0);
        }
        return rootUIJComponent;
    }
    public static Component FindUIObjectInSubComponents(Component rootUIObject, int maxDepth, UISpecObject uiSpecObject){
        Component foundObject = null;
        JComponent rootUIJComponent = GetCurrentJComponent(rootUIObject);

        if(rootUIJComponent!=null){
            if(uiSpecObject.isCompatible(rootUIJComponent)){
                foundObject = rootUIJComponent;
            }else {
                foundObject = FindUIObjectInSubComponents(rootUIJComponent, maxDepth, 0, uiSpecObject);
            }
        }

        return foundObject;
    }

    private static Component FindUIObjectInSubComponents(JComponent rootUIJComponent, int maxDepth, int currentDepth, UISpecObject uiSpecObject){
        Component foundObject = null;
        for(Component subComponent:rootUIJComponent.getComponents()){
            if(uiSpecObject.isCompatible(subComponent)){
                foundObject = subComponent;
                break;
            }else if(currentDepth < maxDepth && subComponent instanceof JComponent){
                foundObject = FindUIObjectInSubComponents((JComponent) subComponent, maxDepth, currentDepth+1, uiSpecObject);
                if(foundObject!=null)
                    break;
            }
        }
        return foundObject;
    }

    public static Component FindUIObjectInParentComponents(Component rootUIObject, int maxDepth, UISpecObject uiSpecObject){
        Component foundObject = null;
        JComponent rootUIJComponent = GetCurrentJComponent(rootUIObject);

        if(rootUIJComponent!=null){
            if(uiSpecObject.isCompatible(rootUIJComponent)){
                foundObject = rootUIJComponent;
            }else {
                foundObject = FindUIObjectInParentComponents(rootUIJComponent, maxDepth, 0, uiSpecObject);
            }
        }

        return foundObject;
    }

    private static Component FindUIObjectInParentComponents(JComponent rootUIJComponent, int maxDepth, int currentDepth, UISpecObject uiSpecObject){
        Component foundObject = null;
        if(rootUIJComponent.getParent() instanceof JComponent){
            JComponent parentComponent = (JComponent) rootUIJComponent.getParent();
            if(uiSpecObject.isCompatible(parentComponent)){
                foundObject = parentComponent;
            }else if(currentDepth < maxDepth && parentComponent instanceof JComponent){
                foundObject = FindUIObjectInParentComponents(parentComponent, maxDepth, currentDepth+1, uiSpecObject);
            }
        }
        return foundObject;
    }

    public static Component FindUIObjectInNeighbourComponents(Component rootUIObject, UISpecObject uiSpecObject){
        Component foundObject = null;
        JComponent rootUIJComponent = GetCurrentJComponent(rootUIObject);

        if(rootUIJComponent!=null){
            if(uiSpecObject.isCompatible(rootUIJComponent)){
                foundObject = rootUIJComponent;
            }else {
                foundObject = FindUIObjectInNeighbourComponents(rootUIJComponent, uiSpecObject);
            }
        }

        return foundObject;
    }

    private static Component FindUIObjectInNeighbourComponents(JComponent rootUIJComponent, UISpecObject uiSpecObject){
        Component foundObject = null;
        if(rootUIJComponent.getParent() instanceof JComponent){
            JComponent parentComponent = (JComponent) rootUIJComponent.getParent();
            foundObject = FindUIObjectInSubComponents(rootUIJComponent, 1, uiSpecObject);
        }
        return foundObject;
    }

}
