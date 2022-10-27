// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.generic;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.List;

public class BurpExtensionSharedParameters {
    public String version = "0.0"; // we need to keep this a double number to make sure check for update can work
    public String extensionName = "MyExtension";
    public String extensionURL = "https://github.com/user/proj";
    public String extensionIssueTracker = "https://github.com/user/proj/issues";
    public Integer debugLevel = null;
    public IBurpExtender burpExtender;
    public Class extensionClass = null; // this is useful when trying to load a resource such as an image
    public PrintWriter stdout = null;
    public PrintWriter stderr = null;
    public IBurpExtenderCallbacks callbacks = null;
    public ExtendedPreferences preferences; // to use the ability of this project: https://github.com/CoreyD97/BurpExtenderUtilities
    public Boolean unloadWithoutSave = false; // this is useful if we need to exit without save in some situation
    public Boolean isBurpPro = false;
    public double burpMajorVersion = 0.0;
    public double burpMinorVersion = 0.0;

    // these are the parameters which are used per extension but needs to be shared - like registers
    public boolean addedIconListener = false;

    public boolean isDarkMode = false; // Sometimes extensions need to see whether Burp uses dark or light mode

    public boolean isScopeChangeDecisionOngoing = false; // this is useful to not ask the scope question more than once at the time

    // params with custom getter or setter - the `setUIParametersFromExtensionTab` method should be used to set them
    private JFrame _mainFrame = null; // This is Burp Suite's main jFrame
    private JMenuBar _mainMenuBar = null; // This is Burp Suite's main menu bar
    private JTabbedPane _rootTabbedPane = null; // this is where Burp Suite main tools' tabs are
    private JPanel _extensionJPanel = null; // panel that extension adds to burp using callbacks.addSuiteTab(BurpExtender.this);
    private String _originalBurpTitle = ""; // Burp Suite's original frame title
    private Image _originalBurpIcon = null; // Burp Suite's original frame icon
    private Boolean _isUILoaded = false; // Burp Suite's original frame icon


    public BurpExtensionSharedParameters(String version, String extensionName, String extensionURL, String extensionIssueTracker, IBurpExtender burpExtenderObj, IBurpExtenderCallbacks callbacks) {
        this.version = version;
        this.extensionName = extensionName;
        this.extensionURL = extensionURL;
        this.extensionIssueTracker = extensionIssueTracker;
        this.extensionClass = burpExtenderObj.getClass();
        this.callbacks = callbacks;
        this.burpExtender = burpExtenderObj;

        // obtain our output stream
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // getting Burp Suite version
        try {
            if (callbacks.getBurpVersion()[0].contains("Professional"))
                this.isBurpPro = true;

            if (callbacks.getBurpVersion().length > 1) {
                this.burpMajorVersion = Double.parseDouble(callbacks.getBurpVersion()[1]);
            }

            if (callbacks.getBurpVersion().length > 2) {
                this.burpMinorVersion = Double.parseDouble(callbacks.getBurpVersion()[2]);
            }

        } catch (Exception e) {
            printlnError(e.getMessage());
        }

        // initialize custom preferences - see https://github.com/CoreyD97/BurpExtenderUtilities/blob/master/src/test/java/extension/PreferencesTest.java
        this.preferences = new ExtendedPreferences(extensionName, new DefaultGsonProvider(), callbacks);
        this.preferences.sharedParameters = this;
        // registering and getting the isDebug setting
        try {
            preferences.registerSetting("debugLevel", Integer.TYPE, 0, Preferences.Visibility.GLOBAL);
        } catch (Exception e) {
            // already registered!
            printlnError(e.getMessage());
        }
        debugLevel = preferences.getSetting("debugLevel");
    }

    public void setUIParametersFromExtensionTab(JPanel extensionJPanel, int waitSeconds) {
        boolean foundUI = false;
        int attemptsRemaining = waitSeconds * 10;

        while (!foundUI && attemptsRemaining > 0) {
            try {
                if (extensionJPanel != null) {
                    set_extensionJPanel(extensionJPanel);
                }

                if (get_rootTabbedPane() != null) {
                    isDarkMode = BurpUITools.isDarkMode(get_rootTabbedPane());
                    foundUI = true;
                } else
                    throw new Exception("no ui");

                printDebugMessage("UI parameters have been loaded successfully");

            } catch (Exception e) {
                attemptsRemaining--;
                try {
                    Thread.sleep(100); // 100 * `waitSeconds` * 10 = `waitSeconds` seconds
                } catch (InterruptedException ignored) {
                }
            }
        }

        if (!foundUI) {
            printlnError(extensionName + " extension UI elements could not be added. Please try again.");
            printDebugMessage("Perhaps unload the extension at this point");
        } else {
            _originalBurpTitle = get_mainFrame().getTitle();
            _originalBurpIcon = get_mainFrame().getIconImage();

            printDebugMessage("Original title and icon has been set");
        }
        _isUILoaded = foundUI;
    }


    public void printDebugMessage(String message, String note, boolean alreadyPrinted) {
        if (debugLevel > 0) {
            String strDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
            String fullMessage = "\r\nDEBUG->\r\n\t";
            if (!note.isBlank())
                fullMessage += "Note: " + note + " - Timestamp: " + strDate + "\r\n\tMessage: " + message;
            else
                fullMessage += "Timestamp: " + strDate + "\r\n\tMessage: " + message;
            System.out.println(fullMessage);
            if (!alreadyPrinted) {
                this.stdout.println(fullMessage);
            }
        }
    }

    public void printDebugMessage(String message) {
        if (debugLevel > 0) {
            StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
            String methods = "";
            if (debugLevel > 1) {
                methods += "\t\t";
                // very verbose
                for (int i = 2; i < stackTraceElements.length; i++) {
                    methods += stackTraceElements[i] + " <- ";
                }
            }

            printDebugMessage(message, methods, false);
        }
    }

    public void printlnError(String message) {
        this.stderr.println(message);
        printDebugMessage(message, "printlnError", true);
    }

    public void printError(String message) {
        this.stderr.print(message);
        printDebugMessage(message, "printError", true);
    }

    public void printlnOutput(String message) {
        this.stdout.println(message);
        printDebugMessage(message, "printlnOutput", true);
    }

    public void printOutput(String message) {
        this.stdout.print(message);
        printDebugMessage(message, "printOutput", true);
    }

    public void resetAllSettings() {
        // A bug in resetting settings in BurpExtenderUtilities should be fixed so we will give it another chance instead of using this method
        // preferences.resetAllSettings();

        HashMap<String, Preferences.Visibility> registeredSettings = preferences.getRegisteredSettings();
        for (String item : registeredSettings.keySet()) {
            if (preferences.getSettingType(item) == String.class)
                preferences.setSetting(item, "");
            else
                preferences.setSetting(item, null);
        }

    }

    public JFrame get_mainFrame() {
        return _mainFrame;
    }

    private void set_mainFrame(JFrame mainFrame) {
        this._mainFrame = mainFrame;
        JMenuBar mainMenuBar = mainFrame.getJMenuBar();
        if (!mainMenuBar.equals(get_mainMenuBar())) {
            set_mainMenuBar(mainMenuBar);
        }
    }

    public JMenuBar get_mainMenuBar() {
        return _mainMenuBar;
    }

    private void set_mainMenuBar(JMenuBar mainMenuBar) {
        this._mainMenuBar = mainMenuBar;
    }

    public JPanel get_extensionJPanel() {
        return _extensionJPanel;
    }

    private void set_extensionJPanel(JPanel extensionJPanel) throws Exception {
        this._extensionJPanel = extensionJPanel;
        // Get the main burp frame
        JFrame burpFrame = getBurpFrame();
        JRootPane rootPane = burpFrame.getRootPane();
        set_rootTabbedPane((JTabbedPane) rootPane.getContentPane().getComponent(0));
    }

    private JFrame getBurpFrame() throws Exception {
        // Get all frames
        Frame[] allFrames = JFrame.getFrames();
        // Filter the stream find the main burp window frame, and convert to a list
        List<Frame> filteredFrames = Arrays.stream(allFrames).filter(f ->
                f.getTitle().startsWith("Burp Suite") && f.isVisible()
        ).collect(Collectors.toList());
        //  If size is 1, we have the main burp frame. Otherwise fails
        if (filteredFrames.size() == 1) {
            return (JFrame) filteredFrames.get(0);
        } else {
            throw new Exception("Expected one burp pane, but found " + filteredFrames.size());
        }
    }

    public JTabbedPane get_rootTabbedPane() {
        return _rootTabbedPane;
    }

    private void set_rootTabbedPane(JTabbedPane rootTabbedPane) {
        this._rootTabbedPane = rootTabbedPane;
        JFrame mainFrame = (JFrame) rootTabbedPane.getRootPane().getParent();
        if (!mainFrame.equals(get_mainFrame())) {
            set_mainFrame(mainFrame);
        }
    }

    public String get_originalBurpTitle() {
        return _originalBurpTitle;
    }

    public Image get_originalBurpIcon() {
        return _originalBurpIcon;
    }

    public boolean get_isUILoaded() {
        return _isUILoaded;
    }
}
