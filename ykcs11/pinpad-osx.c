#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <malloc/malloc.h>

#include <CoreFoundation/CoreFoundation.h>

#include "pinpad-osx.h"

#define dprintf(fmt, args...) fprintf(stderr,"DEBUG %s:%3d: " fmt,__FILE__,__LINE__,##args)
// #define dprintf(fmt, args...) do {} while (0)

#define MAX_PIN_LEN 8

static inline void cleanup_cfrelease(void *var) {
	if (*(CFTypeRef *)var != NULL) {
		CFRelease(*(CFTypeRef *)var);
	}
}
#define AUTORELEASE __attribute__((cleanup(cleanup_cfrelease)))

typedef struct lenbuf {
	size_t len;
	char buf[];
} lenbuf;

static inline void clear_data(lenbuf **buf) {
	memset((*buf)->buf, 0, (*buf)->len);
}

#define securebuf lenbuf __attribute__((cleanup(clear_data))) *

#define alloca_buf(sz) ({lenbuf *buf = alloca(sz+sizeof(lenbuf)); if (buf) buf->len = sz; buf;})

static CFUserNotificationRef create_notification(const void** keys, const void** values, int n, CFTimeInterval timeout, CFOptionFlags flags) {
	SInt32 err;
	CFDictionaryRef cfNDict = CFDictionaryCreate(NULL, keys, values, n,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	CFUserNotificationRef cfNotif = CFUserNotificationCreate(NULL, timeout, flags, &err, cfNDict);
	return cfNotif;
}

static CFUserNotificationRef show_message(CFStringRef header, CFStringRef msg, CFTimeInterval timeout) {
	const void* keys[] = {
		kCFUserNotificationAlertHeaderKey,
		kCFUserNotificationAlertMessageKey,
		kCFUserNotificationDefaultButtonTitleKey,
	};
	const void* values[] = {
		header,
		msg,
		CFSTR(""),
	};
	CFOptionFlags flags = kCFUserNotificationNoteAlertLevel;
	return create_notification(keys, values, sizeof(keys)/sizeof(*keys), timeout, flags);
}
	

static int show_alert(CFStringRef msg, int waitForOk) {
	const void* keys[] = {
		kCFUserNotificationAlertHeaderKey,
		kCFUserNotificationAlertMessageKey,
	};
	const void* values[] = {
		CFSTR("YubiKey"),
		msg
	};
    
	CFUserNotificationRef AUTORELEASE cfNotif = create_notification(keys, values, sizeof(keys)/sizeof(*keys), 0, kCFUserNotificationNoteAlertLevel);
	if (waitForOk) {
		CFOptionFlags cfRes;
		CFUserNotificationReceiveResponse(cfNotif, 0, &cfRes);
	}
	return 0;
}

static int get_confirmation(CFStringRef msg) {
    const void* keys[] = {
        kCFUserNotificationAlertHeaderKey,
        kCFUserNotificationAlertMessageKey,
        kCFUserNotificationAlternateButtonTitleKey,
    };
    const void* values[] = {
        CFSTR("YubiKey"),
        msg,
        CFSTR("Cancel"),
    };
    
    CFUserNotificationRef AUTORELEASE cfNotif = create_notification(keys, values, sizeof(keys)/sizeof(*keys), 0, kCFUserNotificationNoteAlertLevel);

    CFOptionFlags cfRes;
    CFUserNotificationReceiveResponse(cfNotif, 0, &cfRes);
    return ((cfRes&0x3) == kCFUserNotificationDefaultResponse);
}

static char *get_pin(CFStringRef msg, CFStringRef prompt, lenbuf *buf) {
    const void* keys[] = {
        kCFUserNotificationAlertHeaderKey,
        kCFUserNotificationAlertMessageKey,
        kCFUserNotificationAlternateButtonTitleKey,
        kCFUserNotificationTextFieldTitlesKey,
    };
    const void* values[] = {
        CFSTR("YubiKey"),
        msg,
        CFSTR("Cancel"),
        prompt,
    };
    
    CFUserNotificationRef AUTORELEASE cfNotif = create_notification(keys, values, sizeof(keys)/sizeof(*keys), 0, kCFUserNotificationNoteAlertLevel|CFUserNotificationSecureTextField(0));

    CFOptionFlags cfRes;
    CFUserNotificationReceiveResponse(cfNotif, 0, &cfRes);
    if ((cfRes&3) != kCFUserNotificationDefaultResponse) {
        return NULL;
    }
    CFStringRef cfPin = CFUserNotificationGetResponseValue(cfNotif, kCFUserNotificationTextFieldValuesKey, 0);
    CFStringGetCString(cfPin, buf->buf, buf->len, kCFStringEncodingASCII);
    return buf->buf;
}

// static int osx_display_message(struct sc_reader *reader, const char *msg) {
//     CFStringRef AUTORELEASE cfMsg = CFStringCreateWithCStringNoCopy(NULL, msg, kCFStringEncodingUTF8, kCFAllocatorNull);
//     return show_alert(cfMsg, 0);
// }

char *osx_pinpad_get_pin() {
	CFStringRef AUTORELEASE cfPrompt = NULL, cfErrMsg = CFSTR("");
	cfPrompt = CFSTR("Enter PIN: ");
	securebuf pinbuf = alloca_buf(MAX_PIN_LEN);
	char *pin = NULL;
	do {
		pin = get_pin(cfErrMsg, cfPrompt, pinbuf);
		if (pin == NULL) {
			dprintf("User did not enter PIN");
			return NULL;
		}
		if (strlen(pin) < 6) {
			cfErrMsg = CFSTR("PIN too short (must be between 6 and 8 digits)");
		} else if (strlen(pin) > 8) {
			cfErrMsg = CFSTR("PIN too long (must be between 6 and 8 digits)");
		} else if (strspn(pin, "0123456789") != strlen(pin)) {
			cfErrMsg = CFSTR("PIN must be numeric.");
		} else {
			break;
		}
	} while (true);
	return strdup(pin);
}

static char *key_names[256] = {};
static int active_key = 0;

typedef struct touch_handler_info {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	const char *label;
} touch_handler_info_t;

static void *touch_handler(void *arg) {
	touch_handler_info_t *info = arg;
	struct timespec ts;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if (tv.tv_usec >= 500000) {
		ts.tv_sec = tv.tv_sec + 1;
		ts.tv_nsec = tv.tv_usec * 1000 - 500000000;
	} else {
		ts.tv_sec = tv.tv_sec + 0;
		ts.tv_nsec = tv.tv_usec * 1000 + 500000000;
	}
	dprintf("Starting touch handler thread, curtime %ld.%06d, timeout %ld.%09ld\n", tv.tv_sec, tv.tv_usec, ts.tv_sec, ts.tv_nsec);
	pthread_mutex_lock(&info->mutex);
	int retval;
	if ((retval = pthread_cond_timedwait(&info->cond, &info->mutex, &ts))) {
		dprintf("Touch token for key: %s (rv %d/%s)\n", info->label, retval, strerror(retval));
		CFStringRef AUTORELEASE header = info->label
			? CFStringCreateWithFormat(NULL, NULL, CFSTR("YubiKey: %s"), info->label)
			: CFStringCreateCopy(NULL, CFSTR("YubiKey"));
		CFStringRef message = info->label
			? CFSTR("Touch your YubiKey to use the above key...")
			: CFSTR("Touch your YubiKey...");

		CFUserNotificationRef AUTORELEASE touch_notification = show_message(header, message, 60);
		pthread_cond_wait(&info->cond, &info->mutex);
		dprintf("Cleaning up from touch handler\n");
		CFUserNotificationCancel(touch_notification);
	}
	pthread_mutex_unlock(&info->mutex);
	return NULL;
}

// static int (*orig_compute_signature)(struct sc_card *card, const u8 * data,
// 				 size_t data_len, u8 * out, size_t outlen);

ykpiv_rc osx_pinpad_sign_data(ykpiv_state *state, const unsigned char *sign_in,
                        size_t in_len, unsigned char *sign_out, size_t *out_len,
                        unsigned char algorithm, unsigned char key, const char *label) {

// static int osx_compute_signature(struct sc_card *card, const u8 * data, size_t data_len, u8 * out, size_t outlen) {
	// struct itimerval touch_timeout = {
	// 	.it_interval = 0,
	// 	.it_value = {
	// 		.tv_sec = 0,
	// 		.tv_usec = 500000,
	// 	},
	// };
	// struct itimerval old_timerval;
	touch_handler_info_t handler_info = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
		.label = label,
	};
	pthread_t thread;

	// dprintf("in osx_compute_signature, %p %p %d\n", card, data, (int)data_len);
	dprintf("in osx_pinpad_sign_data, 0x%02x\n", key);
	dprintf("active key: %s\n", label);
	pthread_create(&thread, NULL, touch_handler, &handler_info);
	// notification_allocator = create_zoned_allocator(4096);
	// void *old_sighandler = signal(SIGALRM, touch_handler);
	// setitimer(ITIMER_REAL, &touch_timeout, &old_timerval);
	ykpiv_rc retval = ykpiv_sign_data(state, sign_in, in_len, sign_out, out_len, algorithm, key);
	// dprintf("finished osx_compute_signature, %p %p %d\n", card, data, (int)data_len);
	pthread_mutex_lock(&handler_info.mutex);
	pthread_cond_signal(&handler_info.cond);
	pthread_mutex_unlock(&handler_info.mutex);
	pthread_join(thread, NULL);
	dprintf("touch thread joined\n");
	// sleep(2);
	// signal(SIGALRM, old_sighandler);
	// setitimer(ITIMER_REAL, &old_timerval, NULL);
	// finish_touch_handler();
	// destroy_zoned_allocator(notification_allocator);
	// notification_allocator = NULL;
	return retval;
}

// static int (*orig_set_security_env)(struct sc_card *card,
// 			        const struct sc_security_env *env, int se_num);
// static int osx_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num) {
// 	dprintf("in osx_set_security_env, %p %p %d\n", card, env, se_num);
// 	dprintf("senv key: 0x%016llx/%d\n", *(unsigned long long *)env->key_ref, (int)env->key_ref_len);
// 	unsigned int keyref = *(unsigned long long *)env->key_ref;
// 	if (keyref < 256) {
// 		active_key = keyref;
// 		dprintf("key label: %s\n", key_names[keyref]);
// 	} else {
// 		active_key = 0;
// 	}
// 	return orig_set_security_env(card, env, se_num);
// }

// int pinpad_init(sc_pkcs15_card_t *p15card, struct sc_aid *aid, const keyinfo_t *keys, int nkeys) {
// 	// show_alert(CFSTR("Pinpad initialized"), 1);
// 	/*
//     if (get_confirmation(CFSTR("Test PIN get?"))) {
//         char *pin = get_pin(CFSTR("Testing PIN entry."),CFSTR("PIN:"));
//         CFStringRef AUTORELEASE pinres = CFStringCreateWithFormat(NULL, NULL, CFSTR("PIN: %s"), pin);
//         show_alert(pinres, 0);
//     }
// 	 */
//     p15card->card->reader->capabilities |= SC_READER_CAP_PIN_PAD;
//     p15card->card->caps |= SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH;
//     p15card->card->reader->driver->ops->display_message = &osx_display_message;
//     p15card->card->reader->driver->ops->perform_verify = &osx_pin_cmd;
// 	orig_compute_signature = p15card->card->ops->compute_signature;
// 	orig_set_security_env = p15card->card->ops->set_security_env;
// 	p15card->card->ops->compute_signature = &osx_compute_signature;
// 	p15card->card->ops->set_security_env = &osx_set_security_env;
//     if (p15card->card->reader->ops != p15card->card->reader->driver->ops) {
//         static struct sc_reader_operations ops;
//         memcpy(&ops, p15card->card->reader->ops, sizeof(ops));
//         ops.display_message = &osx_display_message;
//         ops.perform_verify = &osx_pin_cmd;
//         p15card->card->reader->ops = &ops;
//     }
// 	for (int k = 0; k < nkeys; k++) {
// 		int keyref = keys[k].key_reference;
// 		if (keyref && keyref < 256) {
// 			if (key_names[keyref]) {
// 				free(key_names[keyref]);
// 			}
// 			key_names[keyref] = strdup(keys[k].pubkey->label);
// 		}
// 	}
// 	return 0;
// }
