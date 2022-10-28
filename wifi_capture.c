/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 LLC
 *
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
#include <sys/time.h>
#include <unistd.h>
#else
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#define usleep(x) Sleep((x) < 1000 ? 1 : (x) / 1000)
#endif

#include "kernel/cfg80211.h"
#include "kernel/endian.h"
#include "kernel/ieee80211.h"
#include "kernel/ieee80211_radiotap.h"

#include <libusb.h>

#include "userspace/userspace.h"

struct wifi_test_context {
    /*
     * USB context
     */
    struct userspace_wifi_context *context;

	/*
	 * Device we plan to open
	*/
	struct userspace_wifi_probe_dev* probedev;
   
    /*
     * The device we're operating on
     */
    struct userspace_wifi_dev *dev;

    /*
     * Runtime options
     */
    bool disable_leds;
    bool disable_blink;
    bool invert_leds;
    bool no_radiotap;
    bool quiet;
    bool diagnostics_mode;
    bool diagnostics_only;
	int device_number;
    int channel;

    /*
     * pcap logging
     */
    bool enable_pcap_log;
    FILE *dump_filep;
    int num_packets;
    pthread_mutex_t pcap_mutex;
};

int open_wifi_device(struct wifi_test_context *test_context) {
    int r;
	
	r = userspace_wifi_device_open(test_context->context, test_context->probedev, &test_context->dev);

	if (r != 0) {
		printf("Failed to open device: %d %s\n", r, strerror(r));
		return -1;
	}

	userspace_wifi_device_set_channel(test_context->context,
		test_context->dev,
		test_context->channel,
		NL80211_CHAN_WIDTH_20_NOHT);

	if (test_context->disable_leds)
		userspace_wifi_device_set_led(test_context->context, test_context->dev, false);
	else
		userspace_wifi_device_set_led(test_context->context, test_context->dev, true);

	if (!test_context->disable_blink)
		userspace_wifi_device_enable_led_control(test_context->context, test_context->dev);

    return 0;
}

int start_wifi_capture(struct wifi_test_context* test_context) {
	/*
	 * If LEDs are inverted, turn off LEDs once we've enumerated all the radios.
	 */
	if (test_context->invert_leds)
		userspace_wifi_device_set_led(test_context->context, test_context->dev, false);

	userspace_wifi_device_start_capture(test_context->context, test_context->dev);

	return 0;
}

#define DLT_IEEE802_11	105	/* IEEE 802.11 wireless */
#define DLT_IEEE802_11_RADIO	127	/* 802.11 plus radiotap radio header */

int open_pcap(const char *file, struct wifi_test_context *test_context) {
    struct {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
    } pcap_hdr_t;

    pcap_hdr_t.magic_number = 0xa1b2c3d4;
    pcap_hdr_t.version_major = 2;
    pcap_hdr_t.version_minor = 4;
    pcap_hdr_t.thiszone = 0;
    pcap_hdr_t.sigfigs = 0;
    pcap_hdr_t.snaplen = 8192;

    test_context->enable_pcap_log = true;
    pthread_mutex_init(&test_context->pcap_mutex, NULL);

    if (test_context->no_radiotap)
        pcap_hdr_t.network = DLT_IEEE802_11;
    else
        pcap_hdr_t.network = DLT_IEEE802_11_RADIO;

    if (strcmp(file, "-") == 0)
        test_context->dump_filep = stdout;
    else
        test_context->dump_filep = fopen(file, "wb");

    if (test_context->dump_filep == NULL) {
        fprintf(stderr, "ERROR: Could not open dump: %d %s\n", errno, strerror(errno));
        return -1;
    }

    fwrite(&pcap_hdr_t, sizeof(pcap_hdr_t), 1, test_context->dump_filep);

    return 1;
}

int pcap_rx_packet(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        struct userspace_wifi_rx_signal *signal,
        unsigned char *data, unsigned int len) {

    struct wifi_test_context *test_context = (struct wifi_test_context *) context->local_data;

    typedef struct {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
    } pcaprec_hdr_t;

    pcaprec_hdr_t pcap_hdr;

    struct timeval tv;

    typedef struct { 
        uint16_t version;
        uint16_t length;
        uint32_t bitmap;
        uint8_t flags;
        uint8_t pad0;
        uint16_t channel_freq;
        uint16_t channel_flags;
        uint8_t antsignal;

    } _rtap_hdr;

    _rtap_hdr rtap_hdr = {
        .version = 0,
        .length = htole16(sizeof(_rtap_hdr)),
        .bitmap = htole32((1 << IEEE80211_RADIOTAP_FLAGS) | 
                (1 << IEEE80211_RADIOTAP_CHANNEL) |
                (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)),
        .flags = 0,
        .channel_freq = htole16(ieee80211_channel_to_frequency(signal->channel, signal->band)),
        .channel_flags = 0,
        .antsignal = (u8) signal->signal,
    };

    if (!signal->crc_valid)
        rtap_hdr.flags |= IEEE80211_RADIOTAP_F_BADFCS;

    if (signal->short_gi)
        rtap_hdr.flags |= IEEE80211_RADIOTAP_F_SHORTGI;

    if (signal->band == NL80211_BAND_2GHZ)
        rtap_hdr.channel_flags |= IEEE80211_CHAN_2GHZ;
    else if (signal->band == NL80211_BAND_5GHZ)
        rtap_hdr.channel_flags |= IEEE80211_CHAN_5GHZ;

    /*
     * Only blink if we're told to blink.
     * Default LED state is "not inverted" (so on).
     * If we're inverted, we let the timer override, so active LEDs stay
     * ON longer as the timer gets extended; this looks better.
     */
    if (!test_context->disable_blink)
        userspace_wifi_device_blink_led(context, dev, 100000, !test_context->invert_leds, test_context->invert_leds);

    if (test_context->diagnostics_mode) {
		fprintf(stderr, "PACKET %u %u %d %02x %02x %02x %02x %02x %02x ...\n",
			len, signal->channel, signal->signal, data[0], data[1], data[2], data[3], data[4], data[5]);
    }

    if (!test_context->enable_pcap_log)
        return 1;

    gettimeofday(&tv, NULL);

    pcap_hdr.ts_sec = tv.tv_sec;
    pcap_hdr.ts_usec = tv.tv_usec;

    pthread_mutex_lock(&test_context->pcap_mutex);

    if (test_context->no_radiotap)  {
        pcap_hdr.incl_len = pcap_hdr.orig_len = len;
        fwrite(&pcap_hdr, sizeof(pcaprec_hdr_t), 1, test_context->dump_filep);
        fwrite(data, len, 1, test_context->dump_filep);
    } else {
        pcap_hdr.incl_len = pcap_hdr.orig_len = sizeof(_rtap_hdr) + len;
        fwrite(&pcap_hdr, sizeof(pcaprec_hdr_t), 1, test_context->dump_filep);
        fwrite(&rtap_hdr, sizeof(_rtap_hdr), 1, test_context->dump_filep);
        fwrite(data, len, 1, test_context->dump_filep);
    }

    test_context->num_packets++;

    if (!test_context->quiet && test_context->num_packets % 100 == 0)
        fprintf(stderr, "Got %d packets\n", test_context->num_packets);

    pthread_mutex_unlock(&test_context->pcap_mutex);

    return 1;
}

void print_device_list(struct userspace_wifi_probe_dev* devs) {
	int dev_num = 0;
    int i;

	while (devs != NULL) {
		fprintf(stderr, "DEVICE %d: Driver %s USB ID %x %x ",
			dev_num, devs->driver_name, devs->device_id_match->idVendor, devs->device_id_match->idProduct);

        for (i = 0; i < devs->usb_bus_path_len; i++) {
            fprintf(stderr, "/%u", devs->usb_bus_path[i]);
        }

        fprintf(stderr, "\n");

		dev_num++;
		devs = devs->next;
	}
}

struct userspace_wifi_probe_dev* find_device_by_number(int device_number, struct userspace_wifi_probe_dev* devs) {
	int dev_num = 0;

	if (devs == NULL)
		return NULL;

	if (device_number < 0)
		return devs;

	while (devs != NULL) {
		if (dev_num == device_number)
			return devs;
		dev_num++;
		devs = devs->next;
	}

	return NULL;
}

void print_usage(char *argv) {
    printf("Userspace Wifi Test\n");
    printf("Usage: %s [options] [output file]\n", argv);
    printf("Options:\n");
    printf(" --list                List devices and exit\n"
           " --device=X            If you have multiple supported Wi-Fi devices, specify\n"
           "                       which one to use\n"
           " --channel=X           Set Wi-Fi Channel (1-14)\n"
           " --plain-dot11         Log plain 802.11 packets instead of radiotap\n"
           "                       formatted packets with signal and channel\n"
           " --disable-leds        Go fully dark; don't enable any LEDs\n"
           " --invert-leds         Normally we enable all the LEDs\n"
           "                       and blink during traffic; Invert only lights\n"
           "                       when there is traffic.\n"
           " --disable-blinking    Disable blinking the LEDs on traffic\n"
           " --quiet               Disable most output\n"
           " --diagnostics         Diagnostic statistics mode\n"
           " --diagnostics-only    Enable diagnostics-only mode, disable pcap\n");
}

int main(int argc, char *argv[]) {
#define OPT_HELP        'h'
#define OPT_LIST        2
#define OPT_DEVNO       3
#define OPT_PLAINDOT11  5
#define OPT_DISABLELED  6
#define OPT_INVERTLED   7
#define OPT_DISABLEBLNK 8
#define OPT_QUIET       9
#define OPT_DIAG        10
#define OPT_DIAGONLY    11
#define OPT_CHANNEL     12
    static struct option longopt[] = {
        { "help", no_argument, 0, OPT_HELP },
        { "list", no_argument, 0, OPT_LIST },
        { "device", required_argument, 0, OPT_DEVNO },
        { "plain-dot11", no_argument, 0, OPT_PLAINDOT11 },
        { "disable-leds", no_argument, 0, OPT_DISABLELED },
        { "invert-leds", no_argument, 0, OPT_INVERTLED },
        { "disable-blinking", no_argument, 0, OPT_DISABLEBLNK },
        { "quiet", no_argument, 0, OPT_QUIET },
        { "diagnostics", no_argument, 0, OPT_DIAG },
        { "diagnostics-only", no_argument, 0, OPT_DIAGONLY },
        { "channel", required_argument, 0, OPT_CHANNEL },
        { 0, 0, 0, 0 }
    };
    int option_idx = 0;
    optind = 0;
    opterr = 0;
    int r;

    bool list_only = false;
    char *pcap_fname = NULL;

    struct userspace_wifi_context *context;
    struct userspace_wifi_probe_dev *probed;
    int probed_count;

    struct wifi_test_context test_context;

    memset(&test_context, 0, sizeof(struct wifi_test_context));

    test_context.device_number = -1;
    test_context.channel = 1;

    while ((r = getopt_long(argc, argv, "h", longopt, &option_idx)) != -1) {
        switch (r) {
            case OPT_HELP:
                /* help */
                print_usage(argv[0]);
                exit(0);
                break;
            case OPT_LIST:
                list_only = true;
                break;
            case OPT_DISABLELED:
                test_context.disable_leds = true;
                break;
            case OPT_INVERTLED:
                test_context.invert_leds = true;
                break;
            case OPT_DISABLEBLNK:
                test_context.disable_blink = true;
                break;
            case OPT_QUIET:
                test_context.quiet = true;
                break;
            case OPT_DEVNO:
                if (sscanf(optarg, "%u", &test_context.device_number) != 1) {
                    print_usage(argv[0]);
                    fprintf(stderr, "\n");
                    fprintf(stderr, "Expected a number for --device, such as --device=5\n");
                    exit(1);
                }
                break;
            case OPT_PLAINDOT11:
                test_context.no_radiotap = true;
                break;
            case OPT_DIAG:
                test_context.diagnostics_mode = true;
                break;
            case OPT_DIAGONLY:
                test_context.diagnostics_only = true;
                test_context.diagnostics_mode = true;
                break;
            case OPT_CHANNEL:
                if (sscanf(optarg, "%u", &test_context.channel) != 1) {
                    print_usage(argv[0]);
                    fprintf(stderr, "\nExpected a number for --channel, such as --channel=6\n");
                    exit(1);
                }

                if (test_context.channel < 1 || test_context.channel > 14) {
                    print_usage(argv[0]);
                    fprintf(stderr, "\nExpected a channel between 1 and 14\n");
                    exit(1);
                }
                break;
        }
    }

    if (!list_only && !test_context.diagnostics_only && optind >= argc) {
        print_usage(argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "FATAL:  Expected pcap file name\n");
        exit(1);
    } else if (!test_context.diagnostics_only && !list_only) {
        pcap_fname = strdup(argv[optind]);
    }

    /*
     * If LEDs are disabled, blinking is disabled
     */
    if (test_context.disable_leds)
        test_context.disable_blink = true;

    r = userspace_wifi_init(&context);

    if (r != 0) {
        fprintf(stderr, "FATAL:  Failed to initialize USB subsystem, %d\n", r);
        exit(1);
    }

    context->local_data = &test_context;
    test_context.context = context;

    probed_count = userspace_wifi_probe(context, &probed);

    if (probed_count == 0) {
#ifdef _WIN32
        fprintf(stderr, "ERROR:  No compatible USB Wi-Fi cards found.  Make sure you have a supported Wi-Fi device "
                "and that you have installed the required drivers via Zadig!\n");
#elif defined(__APPLE__)
        /*
         * Whine about root
         */
        if (getuid() != 0) {
            fprintf(stderr, "ERROR:  No compatible USB Wi-Fi devices found.  Not running as root.  Root is often required for "
                    "raw USB access if you are not the primary user.\n");
        } else {
            fprintf(stderr, "ERROR:  No compatible USB Wi-Fi devices found.\n");
        }
#else
        if (getuid() != 0) {
            fprintf(stderr, "ERROR:  No compatible USB Wi-Fi devices found.  Not running as root.  Root is typically required for "
                    "raw USB access; if you see no USB devices, try running as root\n");
        } else {
            fprintf(stderr, "ERROR  No compatible USB Wi-Fi devices found.\n");
        }
#endif
        exit(1);
    }

	if (!test_context.quiet)
		print_device_list(probed);

    if (list_only)
        goto end;

    /* Look for the device we were asked for */
    test_context.probedev = find_device_by_number(test_context.device_number, probed);

    userspace_wifi_set_packet_cb(context, &pcap_rx_packet);

    if (!test_context.diagnostics_only && !list_only) {
        r = open_pcap(pcap_fname, &test_context);
        if (r < 0) {
            fprintf(stderr, "FATAL:  Could not open pcap\n");
            exit(1);
        }
    }

    open_wifi_device(&test_context);

    /*
     * Activate capture
     */
    if (!test_context.quiet)
        fprintf(stderr, "Activating capture...\n");
    start_wifi_capture(&test_context);

    while (1) {
        sleep(1);
    }

end:
/*  This makes win32 sad right now; not sure why
    userspace_wifi_free_probe(probed);
    userspace_wifi_free(context);
*/
    return 0;
}
