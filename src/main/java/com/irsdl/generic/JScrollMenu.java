// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)

// from https://stackoverflow.com/questions/9288350/adding-vertical-scroll-to-a-jpopupmenu

package com.irsdl.generic;

import javax.swing.*;
import javax.swing.plaf.MenuItemUI;
import javax.swing.plaf.PopupMenuUI;
import java.awt.*;


public class JScrollMenu extends JMenu {
    // Covers the one in the JMenu because the method that creates it in JMenu is private
    /**
     * The popup menu portion of the menu.
     */
    private JPopupMenu popupMenu;


    /**
     * Constructs a new <code>JMenu</code> with no text.
     */
    public JScrollMenu() {
        this("");
    }

    /**
     * Constructs a new <code>JMenu</code> with the supplied string as its text.
     *
     * @param s the text for the menu label
     */
    public JScrollMenu(String s) {
        super(s);
    }

    /**
     * Constructs a menu whose properties are taken from the <code>Action</code> supplied.
     *
     * @param a an <code>Action</code>
     */
    public JScrollMenu(Action a) {
        this();
        setAction(a);
    }


    /**
     * Lazily creates the popup menu. This method will create the popup using the <code>JScrollPopupMenu</code> class.
     */
    protected void ensurePopupMenuCreatedHere() {
        if (popupMenu == null) {
            this.popupMenu = new JScrollPopupMenu();
            popupMenu.setLightWeightPopupEnabled(false);
            popupListener = createWinListener(popupMenu);
            popupMenu.setInvoker(this);
        }
    }

    //////////////////////////////
//// All of these methods are necessary because ensurePopupMenuCreated() is private in JMenu
//////////////////////////////
    @Override
    public void updateUI() {
        setUI((MenuItemUI) UIManager.getUI(this));

        if (popupMenu != null) {
            popupMenu.setUI((PopupMenuUI) UIManager.getUI(popupMenu));
        }
    }


    @Override
    public boolean isPopupMenuVisible() {
        ensurePopupMenuCreatedHere();
        return popupMenu.isVisible();
    }


    @Override
    public void setMenuLocation(int x, int y) {
        super.setMenuLocation(x, y);
        if (popupMenu != null) {
            popupMenu.setLocation(x, y);
        }
    }

    @Override
    public JMenuItem add(JMenuItem menuItem) {
        ensurePopupMenuCreatedHere();
        return popupMenu.add(menuItem);
    }

    @Override
    public Component add(Component c) {
        ensurePopupMenuCreatedHere();
        popupMenu.add(c);
        return c;
    }

    @Override
    public Component add(Component c, int index) {
        ensurePopupMenuCreatedHere();
        popupMenu.add(c, index);
        return c;
    }


    @Override
    public void addSeparator() {
        ensurePopupMenuCreatedHere();
        popupMenu.addSeparator();
    }

    @Override
    public void insert(String s, int pos) {
        if (pos < 0) {
            throw new IllegalArgumentException("index less than zero.");
        }

        ensurePopupMenuCreatedHere();
        popupMenu.insert(new JMenuItem(s), pos);
    }

    @Override
    public JMenuItem insert(JMenuItem mi, int pos) {
        if (pos < 0) {
            throw new IllegalArgumentException("index less than zero.");
        }
        ensurePopupMenuCreatedHere();
        popupMenu.insert(mi, pos);
        return mi;
    }

    @Override
    public JMenuItem insert(Action a, int pos) {
        if (pos < 0) {
            throw new IllegalArgumentException("index less than zero.");
        }

        ensurePopupMenuCreatedHere();
        JMenuItem mi = new JMenuItem(a);
        mi.setHorizontalTextPosition(SwingConstants.TRAILING);
        mi.setVerticalTextPosition(SwingConstants.CENTER);
        popupMenu.insert(mi, pos);
        return mi;
    }

    @Override
    public void insertSeparator(int index) {
        if (index < 0) {
            throw new IllegalArgumentException("index less than zero.");
        }

        ensurePopupMenuCreatedHere();
        popupMenu.insert(new JPopupMenu.Separator(), index);
    }


    @Override
    public void remove(JMenuItem item) {
        if (popupMenu != null) {
            popupMenu.remove(item);
        }
    }

    @Override
    public void remove(int pos) {
        if (pos < 0) {
            throw new IllegalArgumentException("index less than zero.");
        }
        if (pos > getItemCount()) {
            throw new IllegalArgumentException("index greater than the number of items.");
        }
        if (popupMenu != null) {
            popupMenu.remove(pos);
        }
    }

    @Override
    public void remove(Component c) {
        if (popupMenu != null) {
            popupMenu.remove(c);
        }
    }

    @Override
    public void removeAll() {
        if (popupMenu != null) {
            popupMenu.removeAll();
        }
    }

    @Override
    public int getMenuComponentCount() {
        return (popupMenu == null) ? 0 : popupMenu.getComponentCount();
    }

    @Override
    public Component getMenuComponent(int n) {
        return (popupMenu == null) ? null : popupMenu.getComponent(n);
    }

    @Override
    public Component[] getMenuComponents() {
        return (popupMenu == null) ? new Component[0] : popupMenu.getComponents();
    }

    @Override
    public JPopupMenu getPopupMenu() {
        ensurePopupMenuCreatedHere();
        return popupMenu;
    }

    @Override
    public MenuElement[] getSubElements() {
        return popupMenu == null ? new MenuElement[0] : new MenuElement[]{popupMenu};
    }


    @Override
    public void applyComponentOrientation(ComponentOrientation o) {
        super.applyComponentOrientation(o);

        if (popupMenu != null) {
            int nComponents = getMenuComponentCount();
            for (int i = 0; i < nComponents; ++i) {
                getMenuComponent(i).applyComponentOrientation(o);
            }
            popupMenu.setComponentOrientation(o);
        }
    }

    @Override
    public void setComponentOrientation(ComponentOrientation o) {
        super.setComponentOrientation(o);
        if (popupMenu != null) {
            popupMenu.setComponentOrientation(o);
        }
    }
}