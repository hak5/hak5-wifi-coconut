/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 LLC
 *
 */

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
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

#ifdef __APPLE__
#include <sys/types.h>
#include <pwd.h>
#include <uuid/uuid.h>
#endif

#include "kernel/cfg80211.h"
#include "kernel/endian.h"
#include "kernel/ieee80211.h"
#include "kernel/ieee80211_radiotap.h"

#include <libusb.h>

#include "userspace/userspace.h"
#include "wifi_coconut/wifi_coconut.h"

/*
 * Global tool context
 */
struct coconut_tool_context {
    /*
     * Reference to the coconut context from wifi_coconut.h
     */
    struct wifi_coconut_context *coconut_context;

    /*
     * Tool-specific options
     */
    bool wait_for_coconut;
    bool interactive;
    bool no_radiotap;
    bool diagnostics_mode;
    bool list_only;

    /*
     * Pcap file we log to
     */
    char *pcap_fname;

    /*
     * If we're doing log rotation...
     */
    unsigned int log_rotation_interval;
    unsigned int log_rotation_number;

    /*
     * pcap logging runtime
     */
    bool enable_pcap_log;
    FILE *dump_filep;
    int num_packets;
    pthread_mutex_t pcap_mutex;

    /*
     * Interactive and non-interactive UI cb states
     */
    int interactive_spinner_pos;
    bool warned_nodevs;
    bool warned_partial;
};

/*
 * It's easiest to implement pcap ourselves rather than
 * include libpcap and add another dependency
 */

#define DLT_IEEE802_11	105	/* IEEE 802.11 wireless */
#define DLT_IEEE802_11_RADIO	127	/* 802.11 plus radiotap radio header */

int open_coconut_pcap(struct coconut_tool_context *tool_context) {
    struct {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
    } pcap_hdr_t;

    if (tool_context->pcap_fname == NULL)
        return 0;

    pcap_hdr_t.magic_number = 0xa1b2c3d4;
    pcap_hdr_t.version_major = 2;
    pcap_hdr_t.version_minor = 4;
    pcap_hdr_t.thiszone = 0;
    pcap_hdr_t.sigfigs = 0;
    pcap_hdr_t.snaplen = 8192;

    tool_context->enable_pcap_log = true;
    pthread_mutex_init(&tool_context->pcap_mutex, NULL);

    if (tool_context->no_radiotap)
        pcap_hdr_t.network = DLT_IEEE802_11;
    else
        pcap_hdr_t.network = DLT_IEEE802_11_RADIO;

    if (strcmp(tool_context->pcap_fname, "-") == 0)
        tool_context->dump_filep = stdout;
    else
        tool_context->dump_filep = fopen(tool_context->pcap_fname, "wb");

    if (tool_context->dump_filep == NULL) {
        fprintf(stderr, "ERROR: Could not open dump: %d %s\n", errno, strerror(errno));
        return -1;
    }

    fwrite(&pcap_hdr_t, sizeof(pcap_hdr_t), 1, tool_context->dump_filep);

    if (!tool_context->coconut_context->quiet && tool_context->dump_filep != stdout) {
        fprintf(stderr, "Opened PCAP file '%s'\n", tool_context->pcap_fname);
    }

    return 1;
}

void ANSI_PREP() {
#ifdef _WIN32
    HANDLE *console;
    DWORD mode;

    console = GetStdHandle(STD_OUTPUT_HANDLE);

    if (console == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "ERROR:  Failed to get the windows console handle.\n");
        exit(1);
    }

    GetConsoleMode(console, &mode);

    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    /* mode |= DISABLE_NEWLINE_AUTO_RETURN; */

    SetConsoleMode(console, mode);
#endif
}

void ANSI_CLEAR() {
    printf("\x1b[2J");
}

void ANSI_MOVE(unsigned int x, unsigned int y) {
    printf("\x1b[%u;%uH", x, y);
}

void ANSI_CLEAR_LINE() {
    printf("\x1b[K");
}

void ANSI_UNDERLINE() {
    printf("\x1b[4m");
}

void ANSI_NORMAL() {
    printf("\x1b[0m");
}

void scale_bar(int v, int min_v, int max_v, int width, char *buf) {
    int p;
    int scale_v = width * ((float) (v - min_v) / (float) (max_v - min_v));

    if (scale_v < 0)
        scale_v = 0;

    for (p = 0; p < width; p++) {
        if (p < scale_v)
            buf[p] = '#';
        else
            buf[p] = '-';
    }

    buf[width] = '\0';
}

void find_max_value(int *arr, unsigned int len, int *max, int *pos) {
    *max = 0;
    *pos = 0;

    for (unsigned int x = 0; x < len; x++)  {
        if (arr[x] > *max) {
            *max = arr[x];
            *pos = x;
        }
    }
}

#define coconut_logo_height     6
void print_coconut() {
    ANSI_MOVE(1, 0);
    printf("        /''//''\\   _       ___ _______    ______                  Hak 5      __");
    ANSI_MOVE(2, 0);
    printf("        __//_     | |     / (_) ____(_)  / ____/___  _________  ____  __  __/ /_");
    ANSI_MOVE(3, 0);
    printf("       /() () \\   | | /| / / / /_  / /  / /   / __ \\/ ___/ __ \\/ __ \\/ / / / __/");
    ANSI_MOVE(4, 0);
    printf("       \\ ()   /   | |/ |/ / / __/ / /  / /___/ /_/ / /__/ /_/ / / / / /_/ / /_  ");
    ANSI_MOVE(5, 0);
    printf("        `-..-'    |__/|__/_/_/   /_/   \\____/\\____/\\___/\\____/_/ /_/\\__,_/\\__/  ");
}

#ifdef _WIN32
/* Simulate a very very basic glibc getline() */
void win32_getline(char **buffer, size_t max_len) {
    size_t i = 0;
    char c;
    *buffer = (char *) malloc(max_len);

    while (i < max_len - 1) {
        c = getchar();

        if (c == '\n' || c == '\r') {
            (*buffer)[i] = 0;
            return;
        }

        (*buffer)[i++] = c;
    }
}
#endif

#ifdef __APPLE__
/* Really ugly hacky function to modify the provided path to have a prepended
 * documents directory on MacOS
 */
int prepend_documents_dir(char *path, size_t max) {
    char *tmp = strdup(path);
    struct passwd *pwd;

    const char *home_dir = getenv("HOME");
    if (home_dir == NULL) {
        pwd = getpwuid(getuid());

        if (pwd) {
            snprintf(path, max, "%s/Documents/%s", pwd->pw_dir, tmp);
            free(tmp);
            return 0;
        } else {
            free(tmp);
            return -1;
        }
    } else {
        snprintf(path, max, "%s/Documents/%s", home_dir, tmp);
        free(tmp);
        return 0;
    }

    free(tmp);
    return -1;
}
#endif

int interactive_pcap_name(struct coconut_tool_context *tool_context, int xpos) {
    const char *prompt1 = "PCAP file name (or leave blank for no pcap logging)";
    const char *prompt2 = "File name:";

    char *line = NULL;
    size_t len;

    ANSI_MOVE(xpos, 0);
    printf("%s", prompt1);
    ANSI_MOVE(xpos + 1, 0);
    printf("%s", prompt2);
    ANSI_MOVE(xpos + 1, strlen(prompt2) + 2);
    ANSI_UNDERLINE();
    printf("______________________________");
    ANSI_MOVE(xpos + 1, strlen(prompt2) + 2);
    fflush(stdout);

#ifdef _WIN32
    win32_getline(&line, 1024);
    if (strlen(line) > 0)
        tool_context->pcap_fname = strdup(line);
#else
    len = 0;
    getline(&line, &len, stdin);

    if (strlen(line) > 1) {

#ifdef __APPLE__
        /* Hack the home dir into it */
        if (strstr(line, "/") == NULL) {
            char linebuf[2048];
            snprintf(linebuf, 2048, "%s", line);
            prepend_documents_dir(linebuf, 2048);

            free(line);
            line = strdup(linebuf);
        }
#endif

        tool_context->pcap_fname = strndup(line, strlen(line) - 1);
    }
#endif


    ANSI_NORMAL();
    ANSI_MOVE(xpos + 2, 0);

    free(line);

    return 1;
}

int interactive_coconut_cb(struct wifi_coconut_context *coconut_context,
        void *cbaux, int state, int dev, struct wifi_coconut *coconuts) {
    struct coconut_tool_context *tool_context = (struct coconut_tool_context *) cbaux;

    int v_base_offt = 0;

    const char *searching = "Searching for a Wi-Fi Coconut...";
    const char *opening = "Opening Wi-Fi Coconut...";
    const char *spinner = "|/-\\";

    int i, r;

    ANSI_CLEAR();
    ANSI_MOVE(0, 0);

    print_coconut();
    v_base_offt = coconut_logo_height;

    /*
     * Print the searching spinner while we're still looking.
     * Add warnings about needed root, etc if we need to.
     */
    if (state ==  WIFI_COCONUT_SEARCH_STATE_NO_RADIOS ||
            state == WIFI_COCONUT_SEARCH_STATE_NO_COCONUT) {

        ANSI_MOVE(v_base_offt + 1, 0);
        printf("%s", searching);

        ANSI_MOVE(v_base_offt + 1, strlen(searching) + 1);
        printf("  [ %c ]", spinner[tool_context->interactive_spinner_pos++ % strlen(spinner)]);
        ANSI_MOVE(v_base_offt + 2, 0);

        if (state == WIFI_COCONUT_SEARCH_STATE_NO_RADIOS) {
#if defined(__APPLE__)
            ANSI_MOVE(v_base_offt + 2, 0);
            printf("*** No Wi-Fi Coconut radios found.  Make sure your USB cable is plugged into the");
            ANSI_MOVE(v_base_offt + 3, 0);
            printf("    data port of the Wi-Fi Coconut.  IF YOU ARE RUNNING MACOS CATALINA, you may");
            ANSI_MOVE(v_base_offt + 4, 0);
            printf("    need to quit ALL APPS using USB, INCLUDING GOOGLE CHROME before plugging in");
            ANSI_MOVE(v_base_offt + 5, 0);
            printf("    your Wi-Fi Coconut.");
            ANSI_MOVE(v_base_offt + 6, 0);
#elif defined(_WIN32)
            ANSI_MOVE(v_base_offt + 2, 0);
            printf("*** No Wi-Fi Coconut radios found.  Make sure that you have installed the USB drivers");
            ANSI_MOVE(v_base_offt + 3, 0);
            printf("    via Zadig, and that your USB cable is plugged into the data port ");
            ANSI_MOVE(v_base_offt + 4, 0);
            printf("    of the Wi-Fi Coconut.");
            ANSI_MOVE(v_base_offt + 5, 0);
#else
            ANSI_MOVE(v_base_offt + 2, 0);
            if (getuid() != 0) {
                printf("*** No Wi-Fi Coconut radios found, and you ARE NOT RUNNING AS ROOT.  Root is");
                ANSI_MOVE(v_base_offt + 3, 0);
                printf("    REQUIRED for USB access.  Run the Wi-Fi Coconut tool via 'sudo'.");
                ANSI_MOVE(v_base_offt + 4, 0);
            } else {
                printf("*** No Wi-Fi Coconut radios found.  Make sure that your USB cable is plugged");
                ANSI_MOVE(v_base_offt + 3, 0);
                printf("    into the data port of the Wi-Fi Coconut.");
                ANSI_MOVE(v_base_offt + 4, 0);
            }
#endif
        } else if (state == WIFI_COCONUT_SEARCH_STATE_NO_COCONUT) {
#ifdef __APPLE__
            ANSI_MOVE(v_base_offt + 2, 0);
            printf("*** Some Wi-Fi USB devices found, but could not find a Wi-Fi Coconut");
            ANSI_MOVE(v_base_offt + 3, 0);
            printf("    IF YOU ARE RUNNING MACOS CATALINA, you may need to QUIT ALL OTHER");
            ANSI_MOVE(v_base_offt + 4, 0);
            printf("    APPS using USB, INCLUDING GOOGLE CHROME, before plugging in your");
            ANSI_MOVE(v_base_offt + 5, 0);
            printf("    Wi-Fi Coconut.");
            ANSI_MOVE(v_base_offt + 6, 0);
#else
            ANSI_MOVE(v_base_offt + 2, 0);
            printf("*** Some Wi-Fi USB devices found, but could not find a Wi-Fi Coconut");
            ANSI_MOVE(v_base_offt + 3, 0);
            printf("    Some systems may take 10-20 seconds to find all the USB devices.");
            ANSI_MOVE(v_base_offt + 4, 0);
            printf("    You may need to provide additional power via the second USB port");
            ANSI_MOVE(v_base_offt + 5, 0);
            printf("    on the Wi-Fi Coconut");
            ANSI_MOVE(v_base_offt + 6, 0);
#endif
        }

        fflush(stdout);
    }

    /* If we've just found a coconut, opened a device, failed a
     * device, or opened ALL the devices, print out the list of
     * open devices... */
    if (state == WIFI_COCONUT_SEARCH_STATE_FOUND ||
            state == WIFI_COCONUT_SEARCH_STATE_DEV_OPENED ||
            state == WIFI_COCONUT_SEARCH_STATE_DEV_ERROR ||
            state == WIFI_COCONUT_SEARCH_STATE_DONE) {
        ANSI_MOVE(v_base_offt + 1, strlen(searching) + 1);
        printf("  [ OK ]");

        fflush(stdout);

        /* Clear the errors */
        for (i = 0; i < 6; i++) {
            ANSI_MOVE(v_base_offt + i, 0);
            ANSI_CLEAR_LINE();
        }

        ANSI_MOVE(v_base_offt + 2, 0);
        printf("%s  [ .............. ]", opening);
        ANSI_MOVE(v_base_offt + 3, 0);
        fflush(stdout);

        for (i = 0; i < coconut_context->coconut->device_num; i++) {
            if (coconut_context->coconut->active_devices[i] != NULL) {
                ANSI_MOVE(v_base_offt + 2, strlen(opening) + 5 + i);
                printf("*");
            }
        }

        if (state == WIFI_COCONUT_SEARCH_STATE_DEV_ERROR) {
            ANSI_MOVE(v_base_offt + 2, strlen(opening) + 5 + dev);
            printf("X");
            ANSI_MOVE(v_base_offt + 3, 0);
            printf("Failed to open device %d\n", dev);
            fflush(stdout);
            return -1;
        }

        ANSI_MOVE(v_base_offt + 4, 0);

        fflush(stdout);
    }

    /*
     * If we're done, we printed out all the devices, prompt for pcap
     */
    if (state == WIFI_COCONUT_SEARCH_STATE_DONE) {
        /* Get the pcap name */
        interactive_pcap_name(tool_context, v_base_offt + 5);

        ANSI_MOVE(v_base_offt + 6, 0);

        /* Fire up the pcap */
        r = open_coconut_pcap(tool_context);

        if (r < 0) {
            ANSI_MOVE(v_base_offt + 7, 0);
            printf("ERROR:  Could not open PCAP log\n");
        }

        fflush(stdout);
        return 0;
    }

    return 0;
}

/* Non-interactive text-only search and open */
int noninteractive_coconut_cb(struct wifi_coconut_context *coconut_context,
        void *cbaux, int state, int dev, struct wifi_coconut *coconuts) {
    struct coconut_tool_context *tool_context = (struct coconut_tool_context *) cbaux;

    int r;

    if (state ==  WIFI_COCONUT_SEARCH_STATE_NO_RADIOS) {
        if (!tool_context->warned_nodevs) {
            if (!tool_context->wait_for_coconut) {
#if defined(__APPLE__)
                fprintf(stderr, "ERROR:  No Wi-Fi Coconut radios found.  Make sure your USB cable is plugged into the\n"
                                "        data port of the Wi-Fi Coconut.  If you are running MacOS Catalina, you may\n"
                                "        need to quit all other apps using USB, *including Google Chrome*, before \n"
                                "        plugging in your Wi-Fi Coconut\n");
#elif defined(_WIN32)
                fprintf(stderr, "ERROR:  No Wi-Fi Coconut radios found.  Make sure that you have installed the USB\n"
                                "        drivers via Zadig, and that your USB cable is plugged into the data port\n"
                                "        of the Wi-Fi Coconut.\n");
#else
                if (getuid() != 0) {
                    fprintf(stderr, "ERROR:  No Wi-Fi Coconut radios found, and you are not running as root.  Typically\n"
                            "        root is required for raw USB device access; try running the wifi_coconut\n"
                            "        tool under 'sudo'\n");
                } else {
                    fprintf(stderr, "ERROR:  No Wi-Fi Coconut radios found.  Make sure that your USB cable is plugged\n"
                                    "into the datsa port of the Wi-Fi Coconut.\n");
                }
#endif
                fprintf(stderr, "Use the '--wait' option to wait for a Wi-Fi Coconut to be connected.\n");
                return -1;
            } else {
                /* If we have no devices on linux and we're not running as root,
                 * blow up immediately */
#if !defined(__APPLE__) && !defined(_WIN32)
                if (getuid() != 0) {
                    fprintf(stderr, "ERROR:  No Wi-Fi Coconut radios found, and you are not running as root.  Typically\n"
                            "        root is required for raw USB device access; try running the wifi_coconut\n"
                            "        tool under 'sudo'\n");
                    return -1;
                }
#endif
                    fprintf(stderr, "Waiting for a Wi-Fi Coconut.  Make sure your USB cable is plugged into the \n"
                            "data port of the Wi-Fi Coconut.\n");
                }
            }

        tool_context->warned_nodevs = true;

    }

    if (state == WIFI_COCONUT_SEARCH_STATE_NO_COCONUT) {
        if (!tool_context->warned_partial) {
            if (!tool_context->wait_for_coconut) {
#ifdef __APPLE__
                fprintf(stderr, "ERROR:  Some Wi-Fi USB devices found, but could not find a Wi-Fi Coconut.\n"
                                "        If you are running MacOS Catalina, you may need to quit all other\n"
                                "        apps using USB, *including Google Chrome*, before plugging in your\n"
                                "        Wi-Fi Coconut.\n");

#elif defined(_WIN32)
                fprintf(stderr, "ERROR:  Some Wi-Fi USB devices found, but could not find a Wi-Fi Coconut.\n"
                                "        Try waiting 10 to 20 seconds after plugging in your Wi-Fi Coconut\n"
                                "        before running this tool.  Try supplying additional power to\n"
                                "        the Wi-Fi Coconut by plugging in the second USB port.\n");
#else
                fprintf(stderr, "ERROR:  Some Wi-Fi USB devices found, but could not find a Wi-Fi Coconut.\n"
                                "        Train waiting 10 to 20 seconds after plugging in your Wi-Fi Coconut\n"
                                "        before running this tool.  Try supplying additional power to the \n"
                                "        Wi-Fi Coconut by plugging in the second USB port.\n");
#endif
                fprintf(stderr, "Use the '--wait' option to wait for a Wi-Fi Coconut to be connected.\n");
                return -1;
            } else {
#ifdef __APPLE__
                fprintf(stderr, "Some Wi-Fi radios were found, but could not find a Wi-Fi Coconut.  Often\n"
                        "the USB system takes some time after plugging in a device to recognize all devices.\n"
                        "If you are running MacOS Catalina, you may need to quit all other apps using USB,\n"
                        "*including Google Chrome*, before plugging in the Wi-Fi Coconut.\n");
#else
                fprintf(stderr, "Some Wi-Fi radios were found, but could not find a Wi-Fi Coconut.  Often\n"
                        "the USB system takes some time after plugging in a device to recognize all devices.\n"
                        "If the Wi-Fi Coconut is still not found in 10-20 seconds, try supplying additional\n"
                        "power via the second USB port.\n");
#endif
            }

        }

        tool_context->warned_partial = true;
    }

    if (state == WIFI_COCONUT_SEARCH_STATE_LIST) {
        if (!coconut_context->quiet || tool_context->list_only) {
            print_wifi_coconuts(coconuts);

            if (tool_context->list_only)
                return -1;
        }
    }

    if (state == WIFI_COCONUT_SEARCH_STATE_MISMATCH) {
        if (!tool_context->wait_for_coconut) {
            fprintf(stderr, "ERROR:  Wi-Fi Coconut %d not found.  Plug in your device before running\n"
                    "        this tool or use interactive more or --wait-for-coconut\n",
                    coconut_context->coconut_number);
            return -1;
        }
    }

    if (state == WIFI_COCONUT_SEARCH_STATE_FOUND) {
        if (!coconut_context->quiet) {
            fprintf(stderr, "Found Wi-Fi Coconut %d\n", coconut_context->coconut->coconut_number);
        }
    }

    if (state == WIFI_COCONUT_SEARCH_STATE_DEV_OPENED) {
        if (!coconut_context->quiet)
            fprintf(stderr, "Opened coconut-%d radio %d\n", coconut_context->coconut->coconut_number, dev + 1);
    }

    if (state == WIFI_COCONUT_SEARCH_STATE_DEV_ERROR) {
        fprintf(stderr, "ERROR:  Failure opening coconut-%d radio %d\n", coconut_context->coconut->coconut_number, dev + 1);

        return -1;
    }

    if (state == WIFI_COCONUT_SEARCH_STATE_DONE) {
        /* Fire up the pcap */
        r = open_coconut_pcap(tool_context);

        if (r < 0) {
            fprintf(stderr, "ERROR:  Could not open pcap file!\n");
            return -1;
        }
    }

    return 0;
}

int coconut_pcap_rx_packet(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        struct userspace_wifi_rx_signal *signal,
        unsigned char *data, unsigned int len) {

    struct coconut_tool_context *tool_context =
        (struct coconut_tool_context *) context->local_data;
    struct wifi_coconut_context *coconut_context = tool_context->coconut_context;

    typedef struct {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
    } pcaprec_hdr_t;

    pcaprec_hdr_t pcap_hdr;

    struct timeval tv;

    time_t now;
    int i;

    int v_base_offt = 0;

    int total_pkts_sec;

    char diag_bar_packets[31];
    char diag_bar_data[31];

    int max_val_packets, max_pos_packets;
    int max_val_data, max_pos_data;

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
    if (!coconut_context->disable_blink)
        userspace_wifi_device_blink_led(context, dev, 100000, !coconut_context->invert_leds, coconut_context->invert_leds);

    if (tool_context->diagnostics_mode) {
        pthread_mutex_lock(&coconut_context->diagnostics.mutex);

        now = time(0);

        coconut_context->diagnostics.total_packets[dev->dev_id]++;
        coconut_context->diagnostics.total_data[dev->dev_id] += len;

        if (coconut_context->diagnostics.total_min_signal[dev->dev_id] == 0 ||
                coconut_context->diagnostics.total_min_signal[dev->dev_id] > signal->signal)
            coconut_context->diagnostics.total_min_signal[dev->dev_id] = signal->signal;

        if (coconut_context->diagnostics.total_max_signal[dev->dev_id] == 0 ||
                coconut_context->diagnostics.total_max_signal[dev->dev_id] < signal->signal)
            coconut_context->diagnostics.total_max_signal[dev->dev_id] = signal->signal;

        if (coconut_context->diagnostics.last_sec != now) {
            if (coconut_context->diagnostics.last_sec != 0) {
                total_pkts_sec = 0;

                ANSI_CLEAR();
                ANSI_MOVE(0, 0);

#ifndef _WIN32
                print_coconut();
                v_base_offt = coconut_logo_height;
#else
                v_base_offt = 0;
#endif

                find_max_value(coconut_context->diagnostics.sec_packets, 14, &max_val_packets, &max_pos_packets);
                find_max_value(coconut_context->diagnostics.sec_data, 14, &max_val_data, &max_pos_data);

                ANSI_MOVE(v_base_offt + 1, 0);
                printf("Ch   Pkts/s ------------------------------ Bytes/s ------------------------------  Sig\n");

                for (int x = 0; x < 14; x++) {
                    total_pkts_sec += coconut_context->diagnostics.sec_packets[x];

                    scale_bar(coconut_context->diagnostics.sec_packets[x], 0, max_val_packets, 30, diag_bar_packets);
                    scale_bar(coconut_context->diagnostics.sec_data[x], 0, max_val_data, 30, diag_bar_data);

                    ANSI_MOVE(v_base_offt + 2 + x, 0);
                    printf("%2d   %6d %s  %6d %s  %ddBm\n",
                            x + 1,
                            coconut_context->diagnostics.sec_packets[x],
                            diag_bar_packets,
                            coconut_context->diagnostics.sec_data[x],
                            diag_bar_data,
                            coconut_context->diagnostics.sec_max_signal[x]);
                }

                ANSI_MOVE(v_base_offt + 2 + 14, 0);
                printf("Curr %6d       Totl: %6d\n", total_pkts_sec, tool_context->num_packets);

                if (tool_context->pcap_fname != NULL) {
                    ANSI_MOVE(v_base_offt + 2 + 16, 0);
                    printf("Logging to: %s\n", tool_context->pcap_fname);
                    ANSI_MOVE(v_base_offt + 4 + 16, 0);
                } else {
                    ANSI_MOVE(v_base_offt + 4 + 14, 0);
                }

                fflush(stdout);
            }

            for (i = 0; i < 14; i++) {
                coconut_context->diagnostics.sec_packets[i] = 0;
                coconut_context->diagnostics.sec_data[i] = 0;
                coconut_context->diagnostics.sec_min_signal[i] = 0;
                coconut_context->diagnostics.sec_max_signal[i] = 0;
            }

            coconut_context->diagnostics.last_sec = now;
        }

        coconut_context->diagnostics.sec_packets[dev->dev_id]++;
        coconut_context->diagnostics.sec_data[dev->dev_id] += len;

        if (coconut_context->diagnostics.sec_min_signal[dev->dev_id] == 0 ||
                coconut_context->diagnostics.sec_min_signal[dev->dev_id] > signal->signal)
            coconut_context->diagnostics.sec_min_signal[dev->dev_id] = signal->signal;

        if (coconut_context->diagnostics.sec_max_signal[dev->dev_id] == 0 ||
                coconut_context->diagnostics.sec_max_signal[dev->dev_id] < signal->signal)
            coconut_context->diagnostics.sec_max_signal[dev->dev_id] = signal->signal;

        pthread_mutex_unlock(&coconut_context->diagnostics.mutex);
    }

    if (!tool_context->enable_pcap_log)
        return 1;

    if (!signal->crc_valid)
        return 1;

    gettimeofday(&tv, NULL);

    pcap_hdr.ts_sec = tv.tv_sec;
    pcap_hdr.ts_usec = tv.tv_usec;

    pthread_mutex_lock(&tool_context->pcap_mutex);

    if (tool_context->no_radiotap)  {
        pcap_hdr.incl_len = pcap_hdr.orig_len = len;
        fwrite(&pcap_hdr, sizeof(pcaprec_hdr_t), 1, tool_context->dump_filep);
        fwrite(data, len, 1, tool_context->dump_filep);
    } else {
        pcap_hdr.incl_len = pcap_hdr.orig_len = sizeof(_rtap_hdr) + len;
        fwrite(&pcap_hdr, sizeof(pcaprec_hdr_t), 1, tool_context->dump_filep);
        fwrite(&rtap_hdr, sizeof(_rtap_hdr), 1, tool_context->dump_filep);
        fwrite(data, len, 1, tool_context->dump_filep);
    }

    fflush(tool_context->dump_filep);

    tool_context->num_packets++;

    pthread_mutex_unlock(&tool_context->pcap_mutex);

    return 1;
}

void coconut_handle_error(const struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        const char *errstr, int errnum) {

    fprintf(stderr, "\n\nERROR ");

    if (dev != NULL)
        fprintf(stderr, "DEVICE %d ", userspace_wifi_device_get_id(context, dev));

    fprintf(stderr, "%s\n", errstr);

    exit(1);
}

void print_usage(char *argv) {
    printf("Wi-Fi Coconut\n");
    printf("Usage: %s [options]\n", argv);
    printf("By default, the %s tool opens in interactive mode.\n", argv);
    printf("Universal options:\n"
           " --disable-leds        Go fully dark; don't enable any LEDs\n"
           " --invert-leds         Normally a Wi-Fi Coconut enables all the LEDs\n"
           "                       and blinks during traffic; Invert only lights\n"
           "                       when there is traffic.\n"
           " --disable-blinking    Disable blinking the LEDs on traffic\n");
    /*
           " --ht40                Use radios 13 and 14 for HT40 1+ and 11- instead\n"
           "                       of international channels\n");
           */

    printf("Non-interactive modes:\n"
           " --no-display          Don't display channel UI while logging\n"
           " --wait                Wait for a coconut to be found\n"
           " --pcap=[fname]        Log packets to a pcap file.  If file is '-',\n"
           "                       a pcap file will be echoed to stdout so that it can\n"
           "                       be piped to other tools."
           " --wait-for-coconut    Wait for a coconut to be connected and identified\n"
           " --list-coconuts       List Wi-Fi Coconut devices and exit\n"
           " --coconut-device=X    If you have multiple Wi-Fi Coconuts, specify\n"
           "                       which one to use\n"
           " --enable-partial      Enable a Wi-Fi Coconut even if not all the\n"
           "                       radios have been identified.\n"
           " --plain-dot11         Log plain 802.11 packets instead of radiotap\n"
           "                       formatted packets with signal and channel\n"
           " --quiet               Disable most output\n");
}

int main(int argc, char *argv[]) {
#define OPT_HELP        'h'
#define OPT_LIST        2
#define OPT_DEVNO       3
#define OPT_PARTIAL     4
#define OPT_PLAINDOT11  5
#define OPT_DISABLELED  6
#define OPT_INVERTLED   7
#define OPT_DISABLEBLNK 8
#define OPT_QUIET       9
#define OPT_WAIT        12
#define OPT_PCAP        13
#define OPT_NO_DISPLAY  14
#define OPT_HT          15
    static struct option longopt[] = {
        { "help", no_argument, 0, OPT_HELP },
        { "list-coconuts", no_argument, 0, OPT_LIST },
        { "coconut-device", required_argument, 0, OPT_DEVNO },
        { "enable-partial", no_argument, 0, OPT_PARTIAL },
        { "plain-dot11", no_argument, 0, OPT_PLAINDOT11 },
        { "disable-leds", no_argument, 0, OPT_DISABLELED },
        { "invert-leds", no_argument, 0, OPT_INVERTLED },
        { "disable-blinking", no_argument, 0, OPT_DISABLEBLNK },
        { "quiet", no_argument, 0, OPT_QUIET },
        { "wait", no_argument, 0, OPT_WAIT },
        { "pcap", required_argument, 0, OPT_PCAP },
        { "no-display", no_argument, 0, OPT_NO_DISPLAY },
        { "ht40", no_argument, 0, OPT_HT },
        { 0, 0, 0, 0 }
    };
    int option_idx = 0;
    optind = 0;
    opterr = 0;
    int r;

    struct userspace_wifi_context *context;
    struct coconut_tool_context tool_context;
    struct wifi_coconut_context *coconut_context;

    memset(&tool_context, 0, sizeof(struct coconut_tool_context));

    tool_context.coconut_context = init_coconut_context();
    coconut_context = tool_context.coconut_context;

    coconut_context->coconut_number = -1;

    tool_context.interactive = true;
    tool_context.diagnostics_mode = true;

    while ((r = getopt_long(argc, argv, "h", longopt, &option_idx)) != -1) {
        switch (r) {
            case OPT_HELP:
                /* help */
                print_usage(argv[0]);
                exit(0);
                break;
            case OPT_LIST:
                tool_context.list_only = true;
                tool_context.interactive = false;
                tool_context.diagnostics_mode = false;
                break;
            case OPT_DISABLELED:
                coconut_context->disable_leds = true;
                break;
            case OPT_INVERTLED:
                coconut_context->invert_leds = true;
                break;
            case OPT_DISABLEBLNK:
                coconut_context->disable_blink = true;
                break;
            case OPT_QUIET:
                coconut_context->quiet = true;
                tool_context.diagnostics_mode = false;
                tool_context.interactive = false;
                break;
            case OPT_DEVNO:
                if (sscanf(optarg, "%u", &coconut_context->coconut_number) != 1) {
                    print_usage(argv[0]);
                    fprintf(stderr, "\n");
                    fprintf(stderr, "Expected a number for --coconut-device, such as --coconut_device=5\n");
                    exit(1);
                }
                break;
            case OPT_PLAINDOT11:
                tool_context.no_radiotap = true;
                break;
            case OPT_PCAP:
                tool_context.pcap_fname = strdup(optarg);
                tool_context.interactive = false;
                break;
            case OPT_WAIT:
                tool_context.wait_for_coconut = true;
                tool_context.interactive = false;
                break;
            case OPT_NO_DISPLAY:
                tool_context.interactive = false;
                tool_context.diagnostics_mode = false;
                break;
            case OPT_HT:
                coconut_context->ht40 = true;
                break;
        }
    }

    /*
     * If LEDs are disabled, blinking is disabled
     */
    if (coconut_context->disable_leds)
        coconut_context->disable_blink = true;

    r = userspace_wifi_init(&context);

    if (r != 0) {
        fprintf(stderr, "FATAL:  Failed to initialize USB subsystem, %d\n", r);
        exit(1);
    }

    context->local_data = &tool_context;
    coconut_context->context = context;

    userspace_wifi_set_error_cb(context, coconut_handle_error);

    /* Prep the console for win32 to do ANSI mode */
    ANSI_PREP();

    if (tool_context.interactive)
        r = coconut_search_and_open(coconut_context, true, -1,
                &interactive_coconut_cb, &tool_context);
    else
        r = coconut_search_and_open(coconut_context, tool_context.wait_for_coconut,
                coconut_context->coconut_number,
                &noninteractive_coconut_cb, &tool_context);

    if (r != WIFI_COCONUT_SEARCH_STATE_DONE || tool_context.list_only)
        exit(1);

    userspace_wifi_set_packet_cb(context, &coconut_pcap_rx_packet);

    /*
     * Activate capture
     */
    start_wifi_coconut_capture(coconut_context);

    while (1) {
        sleep(1);
    }

    userspace_wifi_free(context);
}
