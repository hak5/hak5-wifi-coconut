Wi-Fi Coconut Win64

** Requirements **

You MUST INSTALL THE ZADIG USB DRIVERS BEFORE CONNECTING YOUR WI-FI COCONUT
or THERE IS A RISK OF HARDWARE DAMAGE.

** Installing **

    1.  Download Zadig from https://zadig.akeo.ie
    2.  Run the Zadig tool
    3.  From the menus, select Device->Create New Device
    4.  Enter "RT2800" in the name field (the large field next to the 
        checkbox named "Edit")
    5.  Under USB ID enter:
        148F  5370
        Leave the third field next to USB ID blank.
    6.  Click "Install Driver".  Zadig may appear to hang - just wait!
        Zadig will then install the USB drivers required for raw
        access to the radio.

    NOTE:  Installing the Zadig drivers for the rt2800 family of Wi-Fi cards 
    will disable any other Wi-Fi cards using this chipset.  These Wi-Fi cards 
    are USB ONLY and this will typically not affect the built-in Wi-Fi card 
    on your system, however if your device ONLY HAS USB for Wi-Fi you should
    MAKE SURE IT DOES NOT USE THE rt2800 CHIPSET.

    IF YOU ARE UNSURE, we recommend TAKING A SYSTEM SNAPSHOT before installing
    the Zadig drivers!
    

** Running **

    1.  Plug in coconut
    2.  Open a terminal, navigate to coconut download
    3.  Run .\wifi_coconut.exe --help for info
    
    Useful commands:
    
    .\wifi_coconut.exe --diagnostics-only
    .\wifi_coconut.exe foo.pcap
    .\wifi_coconut.exe --diagnostics foo.pcap

** Controlling LEDs **

    By default the Wi-Fi Coconut enables all LEDs.  LEDs blink when there is traffic on
    the corresponding channel.

    The Wi-Fi Coconut can be used in "stealth mode" by disabling LEDs entirely:

        .\wifi_coconut.exe --disable-leds foo.pcap

    The LEDs can be inverted, so that they are normally off and blink only when there is
    traffic:

        .\wifi_coconut.exe --invert-leds foo.pcap

    If blinking LEDs causes a health issue or is annoying, LED blinking can be disabled
    with:

        .\wifi_coconut.exe --disable-blinking 

    The LEDs will still light up as the radio is enabled, but will not strobe.


