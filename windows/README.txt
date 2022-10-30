Wi-Fi Coconut Win64

** Requirements **

You MUST INSTALL THE ZADIG USB DRIVERS to use this tool with your Wi-Fi Coconut!

For more information about the install process for Windows, please see the online 
WiFi Coconut documentation:

https://docs.hak5.org/wifi-coconut/software-and-drivers/installing-on-windows

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


