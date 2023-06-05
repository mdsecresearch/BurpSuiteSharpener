// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)

package com.irsdl.generic.uiObjFinder;

import javax.swing.*;
import java.awt.*;

public class UIWalker {
    public static JComponent GetCurrentJComponent(Component rootUIObject) {
        JComponent rootUIJComponent = null;
        if (rootUIObject instanceof JComponent) {
            rootUIJComponent = (JComponent) rootUIObject;
        } else if (rootUIObject.getComponentAt(0, 0) instanceof JComponent) {
            rootUIJComponent = (JComponent) rootUIObject.getComponentAt(0, 0);
        }
        return rootUIJComponent;
    }

    public static Component FindUIObjectInSubComponents(Component rootUIObject, int maxDepth, UiSpecObject uiSpecObject) {
        Component foundObject = null;
        JComponent rootUIJComponent = GetCurrentJComponent(rootUIObject);

        if (rootUIJComponent != null) {
            if (uiSpecObject.isCompatible(rootUIJComponent)) {
                foundObject = rootUIJComponent;
            } else {
                foundObject = FindUIObjectInSubComponents(rootUIJComponent, maxDepth, 0, uiSpecObject);
            }
        }

        return foundObject;
    }

    private static Component FindUIObjectInSubComponents(JComponent rootUIJComponent, int maxDepth, int currentDepth, UiSpecObject uiSpecObject) {
        Component foundObject = null;
        for (Component subComponent : rootUIJComponent.getComponents()) {
            if (uiSpecObject.isCompatible(subComponent)) {
                foundObject = subComponent;
                break;
            } else if (currentDepth < maxDepth && subComponent instanceof JComponent) {
                foundObject = FindUIObjectInSubComponents((JComponent) subComponent, maxDepth, currentDepth + 1, uiSpecObject);
                if (foundObject != null)
                    break;
            }
        }
        return foundObject;
    }

    public static Component FindUIObjectInParentComponents(Component rootUIObject, int maxDepth, UiSpecObject uiSpecObject) {
        Component foundObject = null;
        JComponent rootUIJComponent = GetCurrentJComponent(rootUIObject);

        if (rootUIJComponent != null) {
            if (uiSpecObject.isCompatible(rootUIJComponent)) {
                foundObject = rootUIJComponent;
            } else {
                foundObject = FindUIObjectInParentComponents(rootUIJComponent, maxDepth, 0, uiSpecObject);
            }
        }

        return foundObject;
    }

    private static Component FindUIObjectInParentComponents(JComponent rootUIJComponent, int maxDepth, int currentDepth, UiSpecObject uiSpecObject) {
        Component foundObject = null;
        if (rootUIJComponent.getParent() instanceof JComponent parentComponent) {
            if (uiSpecObject.isCompatible(parentComponent)) {
                foundObject = parentComponent;
            } else if (currentDepth < maxDepth && parentComponent instanceof JComponent) {
                foundObject = FindUIObjectInParentComponents(parentComponent, maxDepth, currentDepth + 1, uiSpecObject);
            }
        }
        return foundObject;
    }

    public static Component FindUIObjectInNeighbourComponents(Component rootUIObject, UiSpecObject uiSpecObject) {
        Component foundObject = null;
        JComponent rootUIJComponent = GetCurrentJComponent(rootUIObject);

        if (rootUIJComponent != null) {
            if (uiSpecObject.isCompatible(rootUIJComponent)) {
                foundObject = rootUIJComponent;
            } else {
                foundObject = FindUIObjectInNeighbourComponents(rootUIJComponent, uiSpecObject);
            }
        }

        return foundObject;
    }

    private static Component FindUIObjectInNeighbourComponents(JComponent rootUIJComponent, UiSpecObject uiSpecObject) {
        Component foundObject = null;
        if (rootUIJComponent.getParent() instanceof JComponent parentComponent) {
            foundObject = FindUIObjectInSubComponents(parentComponent, 1, uiSpecObject);
        }
        return foundObject;
    }

    public static Component FindUIObjectInComponents(Component[] arrayOfComponents, UiSpecObject uiSpecObject) {
        Component foundObject = null;
        for(Component currentComponent:arrayOfComponents){
            if (uiSpecObject.isCompatible(currentComponent)) {
                foundObject = currentComponent;
                break;
            }
        }
        return foundObject;
    }

}
