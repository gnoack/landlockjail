// SPDX-License-Identifier: BSD-3-Clause
/*
 * A command-line utility for Landlock-based path restriction, based
 * on samples/landlock/sandboxer.c from the Linux kernel sources.
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 * Copyright © 2021 Günther Noack
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
		const struct landlock_ruleset_attr *const attr,
		const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
		const enum landlock_rule_type rule_type,
		const void *const rule_attr, const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
			rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
		const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE)

#define ACCESS_FS_ROUGHLY_READ (     \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM)

int populate_ruleset(int ruleset_fd, const char *path, __u64 allowed_access) {
  int ret = 0;
  int fd = open(path, O_PATH | O_CLOEXEC);
  struct landlock_path_beneath_attr path_beneath = {
    .parent_fd = fd,
    .allowed_access = allowed_access,
  };

  if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                        &path_beneath, 0)) {
    perror("failed to update ruleset");
    ret = 1;
    goto out;
  }

 out:
  close(fd);
  return ret;
}

int main(int argc, char *argv[], char **envp) {
  argc--; argv++;  // Skip program name.
  if (*argv && !strcmp(*argv, "-h")) {
    puts("Usage:");
    puts("  lljail [OPTIONS...] -- [ARGV...]");
    puts("");
    puts("Options:");
    puts("  -r PATH     permit only reading for the path");
    puts("  -rw PATH    permit reading and writing");
    puts("  -w PATH     permit only writing");
    puts("");
    puts("  In order to only give file (not directory) permissions,");
    puts("  you can pass two arguments, a literal 'file' and the path.");
    puts("  Example: lljail -r file /dev/random ... -- /bin/bash");
    puts("");
    puts("Example:");
    puts("  lljail -r /usr -r /bin -r /tmp -r /etc -r /root -- /bin/bash");
    return 0;
  }

  struct landlock_ruleset_attr ruleset_attr = {
    .handled_access_fs = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE,
  };
  int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
  if (ruleset_fd < 0) {
    switch (errno) {
    case ENOSYS:
      perror("Landlock is not supported by your kernel"); break;
    case EOPNOTSUPP:
      perror("Landlock is not enabled in your kernel"); break;
    default:
      perror("Unknown error"); break;
    }
    return 1;
  }

  for (; *argv && strcmp(*argv, "--"); argc--, argv++) {
    __u64 allowed_access = 0;
    if (!strcmp(*argv, "-r")) {
      allowed_access = ACCESS_FS_ROUGHLY_READ;
    } else if (!strcmp(*argv, "-rw")) {
      allowed_access = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
    } else if (!strcmp(*argv, "-w")) {
      allowed_access = ACCESS_FS_ROUGHLY_WRITE;
    } else {
      fprintf(stderr, "Unknown flag %s. Use -r, -rw or -w.\n", *argv);
      return 1;
    }

    argc--; argv++;
    if (!*argv) {
      perror("Missing filename after flag");
      return 1;
    }

    if (!strcmp(*argv, "file")) {
      allowed_access &= ACCESS_FILE;
      argc--; argv++;
      if (!*argv) {
        perror("Missing filename after flag");
        return 1;
      }
    }

    if (populate_ruleset(ruleset_fd, *argv, allowed_access)) {
      perror("Could not populate ruleset");
      return 1;
    }
  }

  if (!*argv || strcmp(*argv, "--")) {
    fprintf(stderr, "Needs -- before command\n");
    return 1;
  }
  argc--; argv++;

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("Failed to restrict privileges");
    return 1;
  }
  if (landlock_restrict_self(ruleset_fd, 0)) {
    perror("Failed to enforce ruleset");
    return 1;
  }
  close(ruleset_fd);

  // Execute.
  char *cmd_path = argv[0];
  char **cmd_argv = argv;
  execvpe(cmd_path, cmd_argv, envp);
  fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path,
          strerror(errno));
  fprintf(stderr, "Hint: access to the binary, the interpreter or "
          "shared libraries may be denied.\n");
  return 1;
}
