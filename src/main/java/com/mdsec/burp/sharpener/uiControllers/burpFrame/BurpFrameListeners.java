// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.burpFrame;

import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class BurpFrameListeners implements ComponentListener {
    private final SharpenerSharedParameters sharedParameters;

    private final HashMap<String, String> burpFrameShortcutMappings = new HashMap<>() {{
        put("control alt C", "MoveToCenter");
    }};

    private Lock recenterLock = new ReentrantLock();
    private Lock resizedFrameLock = new ReentrantLock();
    private Lock movedFrameLock = new ReentrantLock();
    private boolean isRecenterInProgress = false;
    private boolean isResizedFrameCheckInProgress = false;
    private boolean isMovedFrameCheckInProgress = false;
    public BurpFrameListeners(SharpenerSharedParameters sharedParameters){
        this.sharedParameters = sharedParameters;
        addBurpFrameListener(sharedParameters.get_mainFrameUsingMontoya());
        boolean detectOffScreenPosition = sharedParameters.preferences.safeGetBooleanSetting("detectOffScreenPosition");
        if(detectOffScreenPosition && !isRecenterInProgress){
            checkAndCenterOffScreen(sharedParameters.get_mainFrameUsingMontoya() , 0.1, true);
        }
    }

    public void addBurpFrameListener(JFrame jframe) {
        sharedParameters.printDebugMessage("addBurpFrameListener");
        try{
            jframe.addComponentListener(this);
            clearInputMap(jframe.getRootPane());

            burpFrameShortcutMappings.forEach((k, v) -> jframe.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                    KeyStroke.getKeyStroke(k), v));

            jframe.getRootPane().getActionMap().put("MoveToCenter", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    UIHelper.moveFrameToCenter(jframe);
                }
            });
        }catch(Exception e){
            sharedParameters.printDebugMessage("Error in BurpFrameListeners.addBurpFrameListener");
        }

    }

    public void removeBurpFrameListener(JFrame jframe) {
        sharedParameters.printDebugMessage("removeBurpFrameListener");
        try{
            jframe.removeComponentListener(this);
            clearInputMap(jframe.getRootPane());
        }catch (Exception e) {
            sharedParameters.printDebugMessage("Error in BurpFrameListeners.removeBurpFrameListener");
        }
    }

    @Override
    public void componentResized(ComponentEvent e) {
        if(!isResizedFrameCheckInProgress){
            try {
                if(resizedFrameLock == null)
                    resizedFrameLock = new ReentrantLock();

                if (resizedFrameLock.tryLock(5, TimeUnit.SECONDS)) {
                    try{
                        isResizedFrameCheckInProgress = true;
                        new java.util.Timer().schedule(
                                new java.util.TimerTask() {
                                    @Override
                                    public void run() {
                                        try{
                                            Dimension newSize = e.getComponent().getBounds().getSize();
                                            Point newLocation = e.getComponent().getBounds().getLocation();
                                            sharedParameters.preferences.safeSetSetting("lastApplicationSize", newSize);
                                            sharedParameters.preferences.safeSetSetting("lastApplicationPosition", newLocation);
                                            boolean detectOffScreenPosition = sharedParameters.preferences.safeGetBooleanSetting("detectOffScreenPosition");
                                            if(detectOffScreenPosition && !isRecenterInProgress){
                                                checkAndCenterOffScreen(sharedParameters.get_mainFrameUsingMontoya(), 0.8, false);
                                            }
                                        }catch(Exception e){
                                            sharedParameters.printDebugMessage("Error in BurpFrameListeners.componentResized");
                                        }finally {
                                            isResizedFrameCheckInProgress = false;

                                        }
                                    }
                                },
                                2000 // 2 seconds delay to decrease the amount of checking process
                        );
                    }finally {
                        resizedFrameLock.unlock();
                    }
                }
            }catch(Exception err){
                isResizedFrameCheckInProgress = false;
            }
        }
    }

    @Override
    public void componentMoved(ComponentEvent e) {
        if(!isMovedFrameCheckInProgress) {
            try {
                if(movedFrameLock == null)
                    movedFrameLock = new ReentrantLock();

                if (movedFrameLock.tryLock(5, TimeUnit.SECONDS)) {
                    try{
                        isMovedFrameCheckInProgress = true;
                        new java.util.Timer().schedule(
                                new java.util.TimerTask() {
                                    @Override
                                    public void run() {
                                        try {
                                            Dimension newSize = e.getComponent().getBounds().getSize();
                                            Point newLocation = e.getComponent().getBounds().getLocation();
                                            sharedParameters.preferences.safeSetSetting("lastApplicationSize", newSize);
                                            sharedParameters.preferences.safeSetSetting("lastApplicationPosition", newLocation);
                                            boolean detectOffScreenPosition = sharedParameters.preferences.safeGetBooleanSetting("detectOffScreenPosition");
                                            if (detectOffScreenPosition && !isRecenterInProgress) {
                                                checkAndCenterOffScreen(sharedParameters.get_mainFrameUsingMontoya(), 0.8, false);
                                            }
                                        }catch(Exception e){
                                            sharedParameters.printDebugMessage("Error in BurpFrameListeners.componentMoved");
                                        }finally {
                                            isMovedFrameCheckInProgress = false;
                                        }

                                    }
                                },
                                1000 // 1 second delay to decrease the amount of checking process
                        );
                    }finally {
                        movedFrameLock.unlock();
                    }
                }
            }catch(Exception err){
                isMovedFrameCheckInProgress = false;
            }
        }
    }

    @Override
    public void componentShown(ComponentEvent e) {

    }

    @Override
    public void componentHidden(ComponentEvent e) {

    }

    public void checkAndCenterOffScreen(JFrame jframe, double offScreenMargin, boolean isChoice){
        if(!isRecenterInProgress) {
            try {
                if(recenterLock == null)
                    recenterLock = new ReentrantLock();

                if (recenterLock.tryLock(5, TimeUnit.SECONDS)) {
                    try{
                        isRecenterInProgress = true;
                        new java.util.Timer().schedule(
                                new java.util.TimerTask() {
                                    @Override
                                    public void run() {
                                        if (jframe != null && UIHelper.isFrameOutOffScreen(jframe, offScreenMargin)) {
                                            if(isChoice){
                                                int response = UIHelper.askConfirmMessage(sharedParameters.extensionName + ": Off Screen Window", "Burp Suite is "+(int) (offScreenMargin*100) +"% outside the screen, do you want to bring it to the center?", new String[]{"Yes", "No"}, null);
                                                if (response == 0) {
                                                    UIHelper.moveFrameToCenter(jframe);
                                                }
                                            }else{
                                                UIHelper.showWarningMessage(sharedParameters.extensionName + ": Burp Suite was at least "+(int) (offScreenMargin*100) +"% outside the screen, therefore, it's been moved to the center!", null);
                                                UIHelper.moveFrameToCenter(jframe);
                                            }
                                        }
                                        isRecenterInProgress = false;
                                    }
                                },
                                1000 // 1 second delay to decrease the amount of checking process
                        );
                    }finally {
                        recenterLock.unlock();
                    }
                }
            }catch(Exception err){
                isRecenterInProgress = false;
            }
        }
    }

    private void clearInputMap(JComponent jc) {
        try{
            burpFrameShortcutMappings.forEach((k, v) -> jc.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                    KeyStroke.getKeyStroke(k), "none"));
        }catch(Exception e){
            sharedParameters.printDebugMessage("Error in BurpFrameListeners.clearInputMap");
        }

    }
}
