// Program: filedir_mirror
// Author: Ian Lindquist
// Purpose: mirrors and ciphers the file contents in a mountpoint dir (argument 3) to a mirrored destination directory (argument 1) by XOR'ing using a user-provided integer key (argument 2) 
#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

//Define some globals
static char directory_destination[1024]; // Path to mirror directory 
static int encryption_key = 0;              // Integer key to use for XOR encryption
static char directory_source[1024];      // Path to the virtual root mount directory

//Encryption method using XOR to cipher data stream
void encrypt_stuff (const unsigned char* buffer,  unsigned char* xor_buffer, int enc_key, size_t bytes_size){
	for ( size_t j =0; j < bytes_size; j++){		
			xor_buffer[j] = buffer[j] ^ enc_key; //encrypt using XOR
		}
}
// Extracts the filename only then returns it
static const char* get_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    return filename ? (filename + 1) : path;	
}

// Maps the virtual FUSE path directly to the physical Linux root filesystem.
static void get_root_system_path(const char *fuse_path, char *real_path) {
    snprintf(real_path, 1024, "%s", fuse_path);
}

// Maps a FUSE path to the destination mirror path
static void get_dest_path(const char *fuse_path, char *real_path) {
    const char* filename = get_filename(fuse_path); //strip the directory using the helper function get_filename
    snprintf(real_path, 1024, "%.500s/%.500s", directory_destination, filename); //build the physical destination string, including the filename
}

// Skip looking inside the mount point or the mirror folder to prevent infinite recursion loop 
static int is_loop_path(const char *path) {
	if (strncmp(path, directory_source, strlen(directory_source)) == 0) return 1;
    if (strncmp(path, directory_destination, strlen(directory_destination)) == 0) return 1;
    return 0;
}
// Gets file attributes from the filepath using lstat and stores them in a struct
static int dest_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *) {
    if (is_loop_path(path)) return -ENOENT; // Safely hide our workspace directories from the loop
    char real_path[1024];
    get_root_system_path(path, real_path); 
    if (lstat(real_path, stbuf) == -1) return -errno; 
    return 0;
}
// Creates the file in the mirrored mount destination directory
static int dest_create(const char *path, mode_t mode, struct fuse_file_info *) {
	char real_path[1024];
    get_root_system_path(path, real_path);
    int file = open(real_path, O_WRONLY | O_CREAT, mode); //Try to open the file, error code if it can't
    if (file == -1) {
		return -errno;
	}
    close(file);
    return 0;
}

// Reads contents directly out of the real Linux root directories so commands such as 'ls' work
static int dest_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *, enum fuse_readdir_flags) {
    (void)offset;
    if (is_loop_path(path)) return 0; // Break the infinite recursion loop

    char real_path[1024];
    get_root_system_path(path, real_path);
    DIR *dp = opendir(real_path);
    if (dp == NULL) return -errno;
    
    // Extract the user folder names dynamically
    const char *runtime_mount_name = get_filename(directory_source);
    const char *runtime_mirror_name = get_filename(directory_destination);
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        // Skip adding the mount and mirror directories to the virtual list
        if (strcmp(de->d_name, runtime_mount_name) == 0 || strcmp(de->d_name, runtime_mirror_name) == 0) {
            continue;
        }
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buffer, de->d_name, &st, 0, 0)) break;
    }
    closedir(dp);
    return 0;
}
// Write and encrypt file to the mirror destination folder
static int dest_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *) {
    char real_path[1024];
    get_root_system_path(path, real_path); 
    int file = open(real_path, O_WRONLY); //open file write only, else error code
    if (file == -1) return -errno;
    int result = pwrite(file, buffer, size, offset);
	close(file);
	
	if (result > 0){
		char dest_path[1024];
		get_dest_path(path, dest_path);
		int encrypt_file = open(dest_path, O_WRONLY | O_CREAT, 0666);
        if (encrypt_file != -1) {
			unsigned char *ciphered = malloc(size); //allocate memory same size as incoming byte chunk
				if (ciphered) { 
					encrypt_stuff((const unsigned char*)buffer, ciphered, encryption_key, size); //encrypt the bytes
					pwrite(encrypt_file, ciphered, size, offset); //system call to write ciphered bytes to the destination file
					free(ciphered); //free the memory
				}
		close(encrypt_file);
		}
    }
	if (result == -1) return -errno;
	return result;
}

// Pass-through read so applications can view files inside the mount point
static int dest_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *) {
    char real_path[1024];
    get_root_system_path(path, real_path);
    int file = open(real_path, O_RDONLY);
    if (file == -1) return -errno;
	int result = pread(file, buffer, size, offset);
    close(file);
	if (result == -1) return -errno;
    return result;
}

static const struct fuse_operations mirror_oper = { //mapping of internal functions to kernal ops
    .getattr    = dest_getattr,
    .create     = dest_create,
    .write      = dest_write,
	.readdir	= dest_readdir,
	.read		= dest_read,
};


//main function
int main (int argc, char *argv[]){
    if (argc != 4) { 
        fprintf(stderr, "Usage: %s <destination_dir> <integer_key> <source_dir>\n", argv[0]); 
        return 1;
    }
    
    // Resolve absolute path for destination directory
    if (realpath(argv[1], directory_destination) == NULL) {
        perror("Error resolving destination path");
        return 1;
    }

    encryption_key = atoi(argv[2]);

    // Resolve absolute path for source (mount) directory
    if (realpath(argv[3], directory_source) == NULL) {
        perror("Error resolving source path");
        return 1;
    }

    char *fuse_argv[3];
    fuse_argv[0] = argv[0];
    fuse_argv[1] = directory_source;
    fuse_argv[2] = "-oallow_other"; 
    int fuse_argc = 3;
	
    return fuse_main(fuse_argc, fuse_argv, &mirror_oper, NULL);
}
