#define _GNU_SOURCE
#include <assert.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WHEEL_GROUP "wheel"

#ifdef NDEBUG
#define LOG(...) ((void) 0)
#define ERR(fmt, ...)                                                          \
	do {                                                                   \
		fprintf(stderr, fmt, ##__VA_ARGS__);                           \
		fputc('\n', stderr);                                           \
		exit(EXIT_FAILURE);                                            \
	} while (0)
#else
#define LOG(fmt, ...)                                                          \
	do {                                                                   \
		fprintf(stderr, "[DEBUG] %d | ", __LINE__);                    \
		fprintf(stderr, fmt, ##__VA_ARGS__);                           \
		fputc('\n', stderr);                                           \
	} while (0)
#define ERR(fmt, ...)                                                          \
	do {                                                                   \
		fprintf(stderr, "[ERROR] %d | ", __LINE__);                    \
		fprintf(stderr, fmt, ##__VA_ARGS__);                           \
		fputc('\n', stderr);                                           \
		exit(EXIT_FAILURE);                                            \
	} while (0)
#endif

bool in_wheel(uid_t ruid) {
	struct passwd *pw = getpwuid(ruid);
	struct group *gr = getgrnam(WHEEL_GROUP);
	for (int i = 0; gr->gr_mem[i]; i++) {
		const char *name = gr->gr_mem[i];
		if (strcmp(name, pw->pw_name) == 0) {
			return true;
		}
	}
	return false;
}

const char *get_editor(void) {
	const char *editors[] = {
		"SUDO_EDITOR", // sudo
		"DOAS_EDITOR", // doas
		"EDITOR",      "VISUAL", NULL,
	};
	for (int i = 0; editors[i]; i++) {
		const char *value = getenv(editors[i]);
		if (value && *value) {
			return value;
		}
	}
	return "vi";
}

const char *find_cmd_path(const char *cmd) {
	if (strchr(cmd, '/')) {
		return cmd;
	}

	char *path_env = strdup(getenv("PATH"));
	char *cmd_path = NULL;
	char *token = strtok(path_env, ":");
	char fullpath[PATH_MAX] = {0};
	while (token) {
		snprintf(fullpath, PATH_MAX, "%s/%s", token, cmd);
		if (access(fullpath, F_OK) == 0) {
			cmd_path = fullpath;
			break;
		}
		token = strtok(NULL, ":");
	}
	free(path_env);
	LOG("find cmd_path: %s -> %s", cmd, cmd_path);
	return cmd_path ? strdup(cmd_path) : cmd;
}

char **backupenv(void) {
	extern char **environ;
	int env_count = 0;
	while (environ[env_count]) {
		env_count++;
	};

	char **env_backup = calloc(env_count + 1, sizeof(char *));
	for (int i = 0; environ[i]; i++) {
		env_backup[i] = strdup(environ[i]);
	}
	assert(env_backup[env_count] == NULL);
	return env_backup;
}

void setrootenv(void) {
	const char *term = getenv("TERM");

	clearenv();
	// root user
	setenv("USER", "root", true);
	setenv("LOGNAME", "root", true);
	setenv("HOME", "/root", true);
	setenv("SHELL", "/bin/sh", true);
	// safe path
	setenv("PATH",
	       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/"
	       "sbin:/bin",
	       true);
	// others
	setenv("LANG", "C.UTF-8", true);
	if (term) {
		setenv("TERM", term, true);
	}
}

int setoptenv(int argc, char *argv[]) {
	int count = 0;

	for (int i = 1; i < argc; i++) {
		char *key = strdup(argv[i]);
		char *value = strchr(key, '=');
		if (!value) {
			free(key);
			break;
		}
		count++;
		*value = '\0';
		setenv(key, (value + 1), true);
		free(key);
	}

	return count;
}

int main(int argc, char *argv[]) {
	const char *editor = NULL;

	// parse FOO=bar
	optind += setoptenv(argc, argv);

	int opt;
	while ((opt = getopt(argc, argv, "ehv")) != -1) {
		switch (opt) {
		case 'e':
			editor = get_editor();
			break;
		case 'h':
		case 'v':
			exit(EXIT_SUCCESS);
			break;
		case '?':
		default:
			break;
		}
	}

	// args?
	if (optind == argc) {
		ERR("args?");
	}

	const char *cmd_path = find_cmd_path(argv[optind]);

	uid_t ruid, euid, suid;
	if (getresuid(&ruid, &euid, &suid) == -1) {
		perror("getresuid");
		exit(EXIT_FAILURE);
	}

	// root?
	if (euid != 0) {
		ERR("root?");
	}

	// suid?
	if (ruid == euid) {
		ERR("suid?");
	}

	// wheel?
	if (!in_wheel(ruid)) {
		ERR("wheel?");
	}

	char *const *old_env = backupenv();

	if (setuid(0) == -1) {
		perror("setuid");
		exit(EXIT_FAILURE);
	}
	if (setgid(0) == -1) {
		perror("setgid");
		exit(EXIT_FAILURE);
	}

	if (editor) {
		// TODO
	}

	setrootenv();
	setoptenv(argc, argv);

	// gogogo
	execvp(cmd_path, &argv[optind]);
	perror("execvp");
	exit(EXIT_FAILURE);
}
