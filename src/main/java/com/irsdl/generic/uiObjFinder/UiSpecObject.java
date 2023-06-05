// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)

package com.irsdl.generic.uiObjFinder;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Type;

public class UiSpecObject {
    private boolean _isJComponent = false;
    private Type _objectType = null;
    private Type _parentObjectType = null;
    private Boolean _isShowing = null;
    private String _frameTitle = null;
    private String _name = null;
    private boolean _isPartialName = false;
    private boolean _isCaseSensitiveName = true;
    private Integer _minWidth = null;
    private Integer _maxWidth = null;
    private Integer _minHeight = null;
    private Integer _maxHeight = null;
    private Color _backgroundColor = null;
    private Integer _minJComponentCount = null;
    private Integer _maxJComponentCount = null;

    public UiSpecObject() {
    }

    public UiSpecObject(Class type) {
        set_objectType(type);
    }

    public boolean isCompatible(Component component) {
        if (component == null) {
            return false;
        }

        if (get_minJComponentCount() != null || get_maxJComponentCount() != null) {
            set_isJComponent(true);
        }

        if (get_isJComponent() && !(component instanceof JComponent)) {
            return false;
        }

        if (get_frameTitle() != null && !(component instanceof JFrame)) {
            return false;
        } else if (get_frameTitle() != null && component instanceof JFrame && !((JFrame) component).getTitle().equals(get_frameTitle())) {
            return false;
        }

        if (get_objectType() != null && !((Class<?>) get_objectType()).isAssignableFrom(component.getClass())) {
            return false;
        }

        if (get_parentObjectType() != null && !((Class<?>) get_parentObjectType()).isAssignableFrom(component.getParent().getClass())) {
            return false;
        }

        if (is_isShowing() != null && component.isShowing() != is_isShowing()) {
            return false;
        }

        if (get_name() != null) {
            String componentName = component.getName();

            if (componentName == null)
                return false;

            if (!get_isCaseSensitiveName()) {
                componentName = componentName.toLowerCase();
            }

            if (!get_isPartialName()) {
                if (!componentName.equals(get_name())) {
                    return false;
                }
            } else {
                if (!componentName.contains(get_name())) {
                    return false;
                }
            }
        }

        if (get_minWidth() != null && component.getWidth() < get_minWidth()) {
            return false;
        }

        if (get_minHeight() != null && component.getHeight() < get_minHeight()) {
            return false;
        }

        if (get_maxWidth() != null && component.getWidth() > get_maxWidth()) {
            return false;
        }

        if (get_maxHeight() != null && component.getHeight() > get_maxHeight()) {
            return false;
        }

        if (get_backgroundColor() != null && !component.getBackground().equals(get_backgroundColor())) {
            return false;
        }

        if (get_minJComponentCount() != null && ((JComponent) component).getComponentCount() < get_minJComponentCount()) {
            return false;
        }

        return get_maxJComponentCount() == null || ((JComponent) component).getComponentCount() <= get_maxJComponentCount();
    }

    public boolean get_isJComponent() {
        return _isJComponent;
    }

    public void set_isJComponent(boolean _isJComponent) {
        this._isJComponent = _isJComponent;
    }

    public Type get_objectType() {
        return _objectType;
    }

    public void set_objectType(Type _objectType) {
        this._objectType = _objectType;
    }

    public Type get_parentObjectType() {
        return _parentObjectType;
    }

    public void set_parentObjectType(Type _parentObjectType) {
        this._parentObjectType = _parentObjectType;
    }

    public Boolean is_isShowing() {
        return _isShowing;
    }

    public void set_isShowing(boolean _isShowing) {
        this._isShowing = _isShowing;
    }

    public String get_frameTitle() {
        return _frameTitle;
    }

    public void set_frameTitle(String _frameTitle) {
        this._frameTitle = _frameTitle;
    }

    public String get_name() {
        return _name;
    }

    public void set_name(String _name) {
        this._name = _name;
    }

    public boolean get_isPartialName() {
        return _isPartialName;
    }

    public void set_isPartialName(boolean _isPartialName) {
        this._isPartialName = _isPartialName;
    }

    public boolean get_isCaseSensitiveName() {
        return _isCaseSensitiveName;
    }

    public void set_isCaseSensitiveName(boolean _isCaseSensitiveName) {
        this._isCaseSensitiveName = _isCaseSensitiveName;
    }

    public Integer get_minWidth() {
        return _minWidth;
    }

    public void set_minWidth(int _minWidth) {
        this._minWidth = _minWidth;
    }

    public Integer get_maxWidth() {
        return _maxWidth;
    }

    public void set_maxWidth(int _maxWidth) {
        this._maxWidth = _maxWidth;
    }

    public Integer get_minHeight() {
        return _minHeight;
    }

    public void set_minHeight(int _minHeight) {
        this._minHeight = _minHeight;
    }

    public Integer get_maxHeight() {
        return _maxHeight;
    }

    public void set_maxHeight(int _maxHeight) {
        this._maxHeight = _maxHeight;
    }

    public Color get_backgroundColor() {
        return _backgroundColor;
    }

    public void set_backgroundColor(Color _backgroundColor) {
        this._backgroundColor = _backgroundColor;
    }

    public Integer get_minJComponentCount() {
        return _minJComponentCount;
    }

    public void set_minJComponentCount(int _minJComponentCount) {
        this._minJComponentCount = _minJComponentCount;
    }

    public Integer get_maxJComponentCount() {
        return _maxJComponentCount;
    }

    public void set_maxJComponentCount(int _maxJComponentCount) {
        this._maxJComponentCount = _maxJComponentCount;
    }
}
