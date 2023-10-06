/*
** Copyright (c) 2023 Intuitibits LLC
** Author: Adrian Granados <adrian@intuitibits.com>
*/

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define VERSION "1.0"

#define NL80211_GENL_FAMILY_NAME "nl80211"
#define NL80211_GENL_GROUP_NAME "scan"

struct trigger_results {
  int done;
  int aborted;
};

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg) {
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}

static int no_seq_check(struct nl_msg *msg, void *arg) { return NL_OK; }

static int callback_trigger(struct nl_msg *msg, void *arg) {

  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct trigger_results *results = arg;

  if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
    results->done = 1;
    results->aborted = 1;
  } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
    results->done = 1;
    results->aborted = 0;
  } // else probably an uninteresting multicast message.

  return NL_SKIP;
}

int do_scan_trigger(struct nl_sock *socket, int if_index, int genl_id) {

  // Starts the scan and waits for it to finish.
  // Does not return until the scan is done or has been aborted.
  struct trigger_results results = {.done = 0, .aborted = 0};
  struct nl_msg *msg;
  struct nl_cb *cb;

  int err;
  int ret;
  int mcid = genl_ctrl_resolve_grp(socket, NL80211_GENL_FAMILY_NAME,
                                   NL80211_GENL_GROUP_NAME);
  nl_socket_add_membership(socket, mcid);

  // Allocate the message and callback handler.
  msg = nlmsg_alloc();
  if (!msg) {
    fprintf(stderr, "command failed: failed to allocate netlink message\n");
    return -ENOMEM;
  }

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    fprintf(stderr, "command failed: failed to allocate netlink callback\n");
    nlmsg_free(msg);
    return -ENOMEM;
  }

  // Setup the message and callback handlers.
  genlmsg_put(msg, 0, 0, genl_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);

  // Configure desired interface.
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

  // Configure callbacks.
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback_trigger, &results);
  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
  nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);

  // Send NL80211_CMD_TRIGGER_SCAN to start the scan.
  // The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on success or
  // NL80211_CMD_SCAN_ABORTED if another scan was started by another process.
  err = 1;
  ret = nl_send_auto(socket, msg); // Send the message.

  while (err > 0)
    ret = nl_recvmsgs(
        socket,
        cb); // First wait for ack_handler(). This helps with basic errors.
  if (ret < 0) {
    fprintf(stderr, "command failed: %s (%d)\n", nl_geterror(-ret), err);
    return err;
  }

  sleep(5);

  // Cleanup.
  nlmsg_free(msg);
  nl_cb_put(cb);
  nl_socket_drop_membership(socket, mcid);
  return 0;
}

void print_usage(const char *program_name)
{
  printf("Usage: %s [-h] [--version] <interface>\n", program_name);
  printf("Options:\n");
  printf("  -h, --help          Display this help message\n");
  printf("  --version           Show version\n");
}

int main(int argc, char *argv[]) {

  struct nl_sock *socket;
  int opt, err;
  int version_flag = 0;

  struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, &version_flag, 1},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
    switch (opt) {
      case 'h':
          // Display help message
          print_usage(basename(argv[0]));
          exit(EXIT_SUCCESS);
          break;
      case '?':
        // Handle unknown or missing options
        print_usage(basename(argv[0]));
        exit(EXIT_FAILURE);
        break;
    }
  }

  if (version_flag) {
    printf("%s version %s\n", basename(argv[0]), VERSION);
    exit(EXIT_SUCCESS);
  }

  // Process interface and filename arguments
  if (optind + 1 != argc) {
    print_usage(basename(argv[0]));
    exit(EXIT_FAILURE);
  }

  int if_index = if_nametoindex(argv[optind]);

  socket = nl_socket_alloc();
  if (!socket) {
    fprintf(stderr, "command failed: %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  err = genl_connect(socket);
  if (err < 0) {
    fprintf(stderr, "command failed: %s (%d)\n", nl_geterror(err), err);
    nl_socket_free(socket);
    return -1;
  }

  int genl_id = genl_ctrl_resolve(socket, NL80211_GENL_FAMILY_NAME);
  if (genl_id < 0) {
    fprintf(stderr, "command failed: %s (%d)\n", nl_geterror(genl_id), genl_id);
    nl_socket_free(socket);
    return -1;
  }

  while (1) {

    // Trigger scan and wait for it to finish
    int err = do_scan_trigger(socket, if_index, genl_id);

    if (err != 0) {
      // Errors -16 (-EBUSY), -25 (-ENOTTY), or -33 (-EDOM)
      // can happen for various reasons when doing a scan
      // but we can simply retry.
      if (err == -EBUSY || err == -ENOTTY || err == -EDOM) {
        sleep(2);
        continue;
      }

      // Other errors are not expected, so we quit.
      return err;
    }

    break;
  }

  return 0;
}
