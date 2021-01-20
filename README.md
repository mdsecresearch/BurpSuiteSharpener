# BurpSuiteSharpener
This changes the style of Burp Suite's Repeater tabs to help the testers. 

These features have been added by traversing the Java UI objects and manipulating them along the way. Therefore, it might not be as good as other built-in features, but that's the only thing we have at the moment to change the tab colours or their style :-)

# Installation and Usage
* Download the jar file from the [release](https://github.com/irsdl/BurpSuiteSharpener/releases) section
* Add it to Burp Suite using the Extender tab
* You can use the following key combinations:

| Combination | Description |	
| --- | --- |	
|Middle Click|		Show Context Menu|	
|Middle Click + CTRL|	Increase the Font Size + Bold|	
|Middle Click + CTRL + SHIFT|	Decrease the Font Size + Bold|	
|Middle Click + SHIFT|	Big + Red + Bold|

**Images**

![Darcula](https://github.com/irsdl/BurpSuiteSharpener/blob/master/images/darcula.png)

![Nimbus](https://github.com/irsdl/BurpSuiteSharpener/blob/master/images/nimbus.png)

**Thanks to**

The simple idea behind changing a repeater tab colour came originally from a private extension written by Bruno Demarche a few years before this extension. That extension changed the text colour of a repeater tab when a comment was added to a request.


**Limitations**
* It has been tested against v2.0.x but should work fine against v1.7.x (hopefully)

Please feel free to report bugs or suggest features
