#define _GNU_SOURCE
#include <assert.h>
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

#define WHEEL_GROUP "wheel"
#define LAST_EDITOR "vi"

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
		fprintf(stderr, "[DEBUG] %3d | ", __LINE__);                   \
		fprintf(stderr, fmt, ##__VA_ARGS__);                           \
		fputc('\n', stderr);                                           \
	} while (0)
#define ERR(fmt, ...)                                                          \
	do {                                                                   \
		fprintf(stderr, "[ERROR] %3d | ", __LINE__);                   \
		fprintf(stderr, fmt, ##__VA_ARGS__);                           \
		fputc('\n', stderr);                                           \
		exit(EXIT_FAILURE);                                            \
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

bool check_user_group(void) {
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

const char *find_exec_path(const char *exec) {
	if (strchr(exec, '/')) {
		return exec;
	}

	char *full_path = strdup(getenv("PATH"));
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

	LOG("find_exec_path: %s -> %s", exec, exec_path ? exec_path : "NULL");
	return exec_path ? strdup(exec_path) : NULL;
}

const char *find_editor(void) {
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

	LOG("find_editor: %s", name);
	return find_exec_path(name);
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

	LOG("save_user_envp: *%d", env_count);
	return env_backup;
}

void free_user_envp(char **envp) {
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
	setenv("PATH",
	       "/usr/local/sbin:/usr/local/bin:"
	       "/usr/sbin:/usr/bin:"
	       "/sbin:/bin",
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

struct edit_file *copy_tmp_file(const char *path, const char *prefix) {
	if (!path) {
		return NULL;
	}
	struct edit_file *file = calloc(1, sizeof(*file));
	file->old_path = path;

	if (stat(path, &file->stat)) {
		perror("stat");
		goto stat_err;
	}
	if (!S_ISREG(file->stat.st_mode)) {
		goto stat_err;
	}

	file->old_fd = open(path, O_RDONLY);
	if (file->old_fd == -1) {
		goto open_err;
	}

	char *fullpath = strdup(path);
	const char *base = basename(fullpath);
	char tmpname[PATH_MAX] = {0};
	snprintf(tmpname, PATH_MAX, "%s/sodo.XXXXXX%s", prefix, base);
	free(fullpath); // after base

	file->tmp_fd = mkstemps(tmpname, strlen(base));
	if (file->tmp_fd == -1) {
		perror("mkstemps");
		goto temp_err;
	}
	file->tmp_path = strdup(tmpname);

	ssize_t sent =
		sendfile(file->tmp_fd, file->old_fd, NULL, file->stat.st_size);
	if (sent == -1) {
		perror("sendfile");
		goto send_err;
	}

	lseek(file->old_fd, 0, SEEK_SET);
	lseek(file->tmp_fd, 0, SEEK_SET);

	fchown(file->tmp_fd, ruid, rgid);

	struct timespec times[2];
	// access time
	times[0].tv_sec = file->stat.st_atime;
	times[0].tv_nsec = 0;
	// modify time
	times[1].tv_sec = file->stat.st_mtime;
	times[1].tv_nsec = 0;
	futimens(file->tmp_fd, times);

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

struct edit_file **init_edit_files(int argc, char *argv[]) {
	const char *prefix = "/tmp";

	struct edit_file **files = calloc(argc - optind + 1, sizeof(*files));

	int count = 0;
	for (int i = optind; i < argc; i++) {
		struct edit_file *file = copy_tmp_file(argv[i], prefix);
		if (!file) {
			continue;
		}
		LOG("edit_file [%d] %s -> %s", count + 1, file->old_path,
		    file->tmp_path);
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

void move_edit_files(struct edit_file **files) {
	int rv = 0;
	for (int i = 0; files[i]; i++) {
		struct stat tmp_stat;
		struct stat old_stat = files[i]->stat;
		fstat(files[i]->tmp_fd, &tmp_stat);
		if (tmp_stat.st_mtime == old_stat.st_mtime) {
			LOG("move_edit_files: skip %s", files[i]->old_path);
			continue;
		}
		rv = rename(files[i]->tmp_path, files[i]->old_path);
		if (rv == -1) {
			perror("rename");
			continue;
		}
		// failed: copy
		rv = fchown(files[i]->tmp_fd, old_stat.st_uid, old_stat.st_gid);
		if (rv == -1) {
			perror("fchown");
			continue;
		}
		rv = fchmod(files[i]->tmp_fd, old_stat.st_mode);
		if (rv == -1) {
			perror("fchmod");
			continue;
		}
		// remove tmp_path
		close(files[i]->tmp_fd);
		close(files[i]->old_fd);
	}
}

char **make_edit_argv(struct edit_file **files) {
	int count = 0;
	while (files[count]) {
		count++;
	}
	assert(count);

	char **argv = calloc(count + 2, sizeof(*argv));
	// argv[0] = editor
	for (int i = 0; i < count; i++) {
		argv[i + 1] = files[i]->tmp_path;
	}

	assert(argv[count + 1] == NULL);
	return argv;
}

int main(int argc, char *argv[]) {
	const char *editor = NULL;

	// parse FOO=bar
	optind += setoptenv(argc, argv);

	int opt;
	while ((opt = getopt(argc, argv, "ehv")) != -1) {
		switch (opt) {
		case 'e':
			editor = find_editor();
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

	const char *exec_path = find_exec_path(argv[optind]);

	if (getresuid(&ruid, &euid, &suid) == -1) {
		perror("getresuid");
		exit(EXIT_FAILURE);
	}

	if (getresgid(&rgid, &egid, &sgid) == -1) {
		perror("getresgid");
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
	if (!check_user_group()) {
		ERR("wheel?");
	}

	char *const *old_env = save_user_envp();

	if (setuid(0) == -1) {
		perror("setuid");
		exit(EXIT_FAILURE);
	}
	if (setgid(0) == -1) {
		perror("setgid");
		exit(EXIT_FAILURE);
	}

	init_root_envp();
	setoptenv(argc, argv);

	if (!editor) {
		// gogogo
		execvp(exec_path, &argv[optind]);
		perror("execvp");
		exit(EXIT_FAILURE);
	}

	// mktemp, cp, chown, time
	struct edit_file **files = init_edit_files(argc, argv);
	if (!files) {
		ERR("file count = 0");
	}
	char **edit_argv = make_edit_argv(files);
	edit_argv[0] = (char *) editor;

	// fork
	pid_t pid = fork();
	int wstatus;
	switch (pid) {
	case -1:
		perror("fork");
		exit(EXIT_FAILURE);
	case 0:
		setgid(rgid); // 1 st
		setuid(ruid); // 2 nd
		execvpe(editor, edit_argv, old_env);
		perror(editor);
	// vim
	default:
		// wait
		waitpid(pid, &wstatus, 0);
		move_edit_files(files);
		exit(EXIT_SUCCESS);
	}
}
