#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef WHEEL_GROUP
#define WHEEL_GROUP "wheel"
#endif

#ifndef LAST_EDITOR
#define LAST_EDITOR "vi"
#endif

#ifndef SECURE_PATH
#define SECURE_PATH                                                            \
	"/usr/local/sbin:/usr/local/bin:"                                      \
	"/usr/sbin:/usr/bin:"                                                  \
	"/sbin:/bin"
#endif

#ifndef PROG_NAME
#define PROG_NAME "soda"
#endif

#ifndef PROG_VERSION
#define PROG_VERSION "0.0.0"
#endif

#define PROG_USAGE                                                             \
	"usage: " PROG_NAME " [NAME=VALUE] COMMAND [ARG]...\n"                 \
	"   or: " PROG_NAME " -e FILE...\n"

#define FMT(fmt, ...)                                                          \
	do {                                                                   \
		fprintf(stderr, PROG_NAME ": " fmt "\n", ##__VA_ARGS__);       \
	} while (0)
#define FMT_SYS(fmt, ...)                                                      \
	do {                                                                   \
		int _errno = errno;                                            \
		fprintf(stderr, PROG_NAME ": " fmt " (errno: %d - %s)\n",      \
			##__VA_ARGS__, _errno, strerror(_errno));              \
	} while (0)

#ifdef NDEBUG
#define LOG(fmt, ...) (void) 0
#define LOG_SYS(fmt, ...) (void) 0
#else
#define LOG(fmt, ...)                                                          \
	do {                                                                   \
		fprintf(stderr, PROG_NAME ": " fmt "\n", ##__VA_ARGS__);       \
	} while (0)
#define LOG_SYS(fmt, ...)                                                      \
	do {                                                                   \
		int _errno = errno;                                            \
		fprintf(stderr, PROG_NAME ": " fmt " (errno: %d - %s)\n",      \
			##__VA_ARGS__, _errno, strerror(_errno));              \
	} while (0)
#endif

struct edit_file {
	const char *old_path;
	char *tmp_path;
	int old_fd;
	int tmp_fd;
	struct stat stat;
};

uid_t ruid, euid, suid;
gid_t rgid, egid, sgid;

void check_user_group(void) {
	struct passwd *pw = getpwuid(ruid);
	if (!pw) {
		FMT_SYS("failed to get user info for UID %d", ruid);
		exit(EXIT_FAILURE);
	}
	struct group *gr = getgrnam(WHEEL_GROUP);
	if (!gr) {
		FMT_SYS("group " WHEEL_GROUP " not found");
		exit(EXIT_FAILURE);
	}
	for (int i = 0; gr->gr_mem[i]; i++) {
		const char *name = gr->gr_mem[i];
		if (strcmp(name, pw->pw_name) == 0) {
			return;
		}
	}
	FMT("failed to verify user in " WHEEL_GROUP " group");
	exit(EXIT_FAILURE);
}

char *find_exec_path(const char *exec) {
	if (strchr(exec, '/')) {
		return strdup(exec);
	}

	const char *user_path = getenv("PATH");
	char *full_path = strdup(user_path ? user_path : SECURE_PATH);
	char *exec_path = NULL;

	char buff_path[PATH_MAX] = {0};
	char *token = strtok(full_path, ":");
	while (token) {
		snprintf(buff_path, PATH_MAX, "%s/%s", token, exec);
		if (access(buff_path, F_OK) == 0) {
			exec_path = buff_path;
			break;
		}
		token = strtok(NULL, ":");
	}
	free(full_path);

	if (exec_path) {
		LOG("retrieve path for command %s: %s", exec, exec_path);
		return strdup(exec_path);
	} else {
		FMT("failed to retrieve path for command %s", exec);
		return NULL;
	}
}

const char *find_user_editor(void) {
	const char *items[] = {
		"EDITOR",
		"VISUAL",
		// others
		NULL,
	};
	const char *name = LAST_EDITOR;
	for (int i = 0; items[i]; i++) {
		const char *value = getenv(items[i]);
		if (value && *value) {
			name = value;
			break;
		}
	}

	LOG("using editor: %s", name);
	return name;
}

char **save_user_envp(void) {
	int env_count = 0;
	while (environ[env_count]) {
		env_count++;
	};

	char **env_backup = calloc(env_count + 1, sizeof(char *));
	for (int i = 0; environ[i]; i++) {
		env_backup[i] = strdup(environ[i]);
	}
	assert(env_backup[env_count] == NULL);

	LOG("save user environment (count: %d)", env_count);
	return env_backup;
}

void free_user_envp(char **envp) {
	if (!envp) {
		return;
	}
	for (int i = 0; envp[i]; i++) {
		free(envp[i]);
	}
	free(envp);
}

void init_root_envp(void) {
	const char *term = getenv("TERM");

	clearenv();
	// root user
	setenv("USER", "root", true);
	setenv("LOGNAME", "root", true);
	setenv("HOME", "/root", true);
	setenv("SHELL", "/bin/sh", true);
	// safe path
	setenv("PATH", SECURE_PATH, true);
	// others
	setenv("LANG", "C.UTF-8", true);
	if (term) {
		setenv("TERM", term, true);
	}
}

int set_opts_env(int argc, char *argv[]) {
	static bool parsed = false;

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
		if (!parsed) {
			LOG("parse argument: %s=%s", key, value);
		}
		free(key);
	}

	parsed = true;
	return count;
}

struct edit_file *make_copy(const char *path, const char *prefix) {
	if (!path) {
		return NULL;
	}
	// FIXME
	// memory alloction is not checked, including calloc and strdup
	struct edit_file *file = calloc(1, sizeof(*file));
	file->old_path = path;

	if (stat(file->old_path, &file->stat)) {
		FMT_SYS("failed to stat %s", file->old_path);
		goto stat_err;
	}
	if (!S_ISREG(file->stat.st_mode)) {
		FMT("not a regular file: %s", file->old_path);
		goto stat_err;
	}

	file->old_fd = open(file->old_path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
	if (file->old_fd == -1) {
		FMT_SYS("failed to open %s", file->old_path);
		goto open_err;
	}

	char *path_dup = strdup(path);
	const char *base = basename(path_dup);
	char buff_path[PATH_MAX] = {0};
	snprintf(buff_path, PATH_MAX, "%s/soda.XXXXXX%s", prefix, base);

	file->tmp_fd = mkostemps(buff_path, strlen(base), O_CLOEXEC);
	free(path_dup); // free it after using base

	if (file->tmp_fd == -1) {
		FMT_SYS("failed to mkstemps %s", buff_path);
		goto temp_err;
	}
	file->tmp_path = strdup(buff_path);

	off_t offset = 0;
	ssize_t sent = sendfile(file->tmp_fd, file->old_fd, &offset,
				file->stat.st_size);
	if (sent == -1) {
		FMT_SYS("failed to sendfile from %s to %s", file->old_path,
			file->tmp_path);
		goto send_err;
	}

	if (fchown(file->tmp_fd, ruid, rgid)) {
		// unreachable
		FMT_SYS("failed to fchown %s", file->tmp_path);
	}

	struct timespec times[2];
	// access time
	times[0].tv_sec = file->stat.st_atime;
	times[0].tv_nsec = 0;
	// modify time
	times[1].tv_sec = file->stat.st_mtime;
	times[1].tv_nsec = 0;
	if (futimens(file->tmp_fd, times)) {
		// unreachable
		FMT_SYS("failed to futimens %s", file->tmp_path);
	}

	return file;

send_err:
	close(file->tmp_fd);
	unlink(file->tmp_path);
	free(file->tmp_path);
temp_err:
	close(file->old_fd);
open_err:
stat_err:
	free(file);
	return NULL;
}

struct edit_file **fork_each_file(int argc, char *argv[]) {
	const char *prefix = "/tmp";

	struct edit_file **files = calloc(argc - optind + 1, sizeof(*files));

	int count = 0;
	for (int i = optind; i < argc; i++) {
		struct edit_file *file = make_copy(argv[i], prefix);
		if (!file) {
			LOG("fork file from %s (skip)", file->old_path);
			continue;
		}
		LOG("fork file from %s to %s", file->old_path, file->tmp_path);
		files[count++] = file;
	}

	assert(files[count] == NULL);
	if (count) {
		return files;
	} else {
		free(files);
		return NULL;
	}
}

bool copy_back(const struct edit_file *file) {
	struct stat tmp_stat;
	struct stat old_stat = file->stat;

	if (fstat(file->tmp_fd, &tmp_stat)) {
		// unreachable
		FMT_SYS("failed to fstat %s", file->tmp_path);
	}
	if (tmp_stat.st_mtime == old_stat.st_mtime) {
		FMT("unchanged %s", file->old_path);
		return true;
	}

	// necessary!
	if (lseek(file->old_fd, 0, SEEK_SET) == -1) {
		// unreachable
		FMT_SYS("failed to lseek %s", file->old_path);
		return false;
	}
	if (ftruncate(file->old_fd, 0)) {
		// unreachable
		FMT_SYS("failed to fstat %s", file->old_path);
		return false;
	}

	// copy
	off_t offset = 0;
	ssize_t sent = sendfile(file->old_fd, file->tmp_fd, &offset,
				file->stat.st_size);
	if (sent == -1) {
		FMT_SYS("failed to sendfile from %s to %s", file->tmp_path,
			file->old_path);
		return false;
	}
	LOG("copy %s back to %s", file->tmp_path, file->old_path);

	return true;
}

void save_each_file(struct edit_file **files) {
	for (int i = 0; files[i]; i++) {
		const struct edit_file *file = files[i];
		bool is_ok = copy_back(file);
		if (!is_ok) {
			FMT("backup retained at %s", file->tmp_path);
			continue;
		}

		LOG("delete temp file %s", file->tmp_path);
		if (unlink(file->tmp_path)) {
			FMT_SYS("failed to delete %s", file->tmp_path);
		}
	}
}

void free_each_file(struct edit_file **files) {
	for (int i = 0; files[i]; i++) {
		close(files[i]->tmp_fd);
		close(files[i]->old_fd);

		// fork + execvpe has COW
		free(files[i]->tmp_path);
	}

	free(files);
}

char **make_edit_argv(struct edit_file **files) {
	int count = 0;
	while (files[count]) {
		count++;
	}
	assert(count);

	char **argv = calloc(count + 2, sizeof(*argv));
	// argv[0] is editor
	for (int i = 0; i < count; i++) {
		argv[i + 1] = files[i]->tmp_path;
	}

	assert(argv[count + 1] == NULL);
	return argv;
}

int main(int argc, char *argv[]) {
	bool use_editor = false;

	// parse FOO=bar
	optind += set_opts_env(argc, argv);

	int opt;
	while ((opt = getopt(argc, argv, "ehv")) != -1) {
		switch (opt) {
		case 'e':
			use_editor = true;
			break;
		case 'h':
			printf(PROG_USAGE);
			exit(EXIT_SUCCESS);
		case 'v':
			printf(PROG_NAME " version " PROG_VERSION "\n");
			exit(EXIT_SUCCESS);
			break;
		case '?':
		default:
			printf(PROG_USAGE);
			exit(EXIT_FAILURE);
			break;
		}
	}

	// args?
	if (optind == argc) {
		printf(PROG_USAGE);
		exit(EXIT_FAILURE);
	}

	if (getresuid(&ruid, &euid, &suid) == -1) {
		FMT_SYS("failed to getresuid");
		exit(EXIT_FAILURE);
	}

	if (getresgid(&rgid, &egid, &sgid) == -1) {
		FMT_SYS("failed to getresgid");
		exit(EXIT_FAILURE);
	}

	// root?
	if (euid != 0) {
		FMT("operation requires root EUID");
		exit(EXIT_FAILURE);
	}

	// after initializing ruid
	check_user_group();

	char **user_envp = use_editor ? save_user_envp() : NULL;

	if (setuid(0) == -1) {
		FMT_SYS("failed to setuid root");
		free_user_envp(user_envp);
		exit(EXIT_FAILURE);
	}
	if (setgid(0) == -1) {
		FMT_SYS("failed to setgid root");
		free_user_envp(user_envp);
		exit(EXIT_FAILURE);
	}

	const char *editor_name = use_editor ? find_user_editor() : NULL;

	init_root_envp();
	set_opts_env(argc, argv);

	const char *exec_argv = use_editor ? editor_name : argv[optind];
	char *exec_path = find_exec_path(exec_argv);

	if (!exec_path) {
		FMT("command not found: %s", exec_argv);
		free_user_envp(user_envp);
		exit(EXIT_FAILURE);
	}

	if (!use_editor) {
		execvp(exec_path, &argv[optind]);
		// unreachable
		FMT_SYS("failed to execvp: %s", exec_path);
		free_user_envp(user_envp);
		exit(EXIT_FAILURE);
	}

	// mktemp, cp, chown, time
	struct edit_file **files = fork_each_file(argc, argv);
	if (!files) {
		FMT("no valid files, exiting");
		free_user_envp(user_envp);
		exit(EXIT_FAILURE);
	}

	char **edit_argv = make_edit_argv(files);
	edit_argv[0] = (char *) editor_name;

	// fork
	pid_t pid = fork();
	int wstatus;
	switch (pid) {
	case -1:
		FMT_SYS("failed to fork");
		exit(EXIT_FAILURE);
	case 0:
		setgid(rgid); // 1 st
		setuid(ruid); // 2 nd
		execvpe(exec_path, edit_argv, user_envp);
		// unreachable
		FMT_SYS("failed to execvpe: %s", exec_path);
		exit(EXIT_FAILURE);
	default:
		// FIXME
		// wait execvpe to follow COW?
		free(exec_path);
		free(edit_argv);
		free_user_envp(user_envp);
		LOG("waiting for editor exit...");
		// wait
		waitpid(pid, &wstatus, 0);
		save_each_file(files);
		free_each_file(files);
		exit(EXIT_SUCCESS);
	}
}
