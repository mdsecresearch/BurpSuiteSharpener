// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.generic;

import com.irsdl.generic.ImageHelper;

import javax.swing.*;
import java.awt.*;

public class BurpTitleAndIcon {
    public static void resetTitleAndIcon(BurpExtensionSharedParameters sharedParams) {
        setTitle(sharedParams, sharedParams.get_originalBurpTitle());
        setIcon(sharedParams, sharedParams.get_originalBurpIcon());
    }

    public static void changeTitleAndIcon(BurpExtensionSharedParameters sharedParams, String title, Image img) {
        setTitle(sharedParams, title);
        setIcon(sharedParams, img);
    }

    public static void setTitle(BurpExtensionSharedParameters sharedParameters, String title) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    sharedParameters.get_mainFrame().setTitle(title);
                    sharedParameters.printDebugMessages("Burp Suite title was changed to: " + title);
                }).start();
            }
        });
    }

    public static void setIcon(BurpExtensionSharedParameters sharedParameters, Image img) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    for (Window window : Window.getWindows()) {
                        window.setIconImage(img);
                    }
                    //sharedParameters.get_mainFrame().setIconImage(img);
                    sharedParameters.printDebugMessages("Burp Suite icon has been updated");
                }).start();
            }
        });

    }

    public static void setIcon(BurpExtensionSharedParameters sharedParams, String imgPath) {
        Image loadedImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageFile(imgPath), 48);
        if (loadedImg != null) {
            setIcon(sharedParams, loadedImg);
        } else {
            sharedParams.printlnError("Image could not be loaded to be used as the Burp Suite icon: " + imgPath);
        }
    }
}
