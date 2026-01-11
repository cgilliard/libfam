/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025 Christopher Gilliard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *******************************************************************************/

#include <dirent.h>
#include <libfam/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

i32 file_count = 0;
#define MAX_FILES 4096
i32 file_sizes[MAX_FILES];

void print_hex(const u8 *data, u64 size, FILE *out, const u8 *file,
	       const u8 *namespace) {
	u8 buf[strlen(file) + 100];

	snprintf(
	    buf, strlen(file) + 100,
	    "__attribute__((aligned(32))) const u8 %sxxdir_file_%i[] = {\n",
	    namespace, file_count);
	for (i32 i = 0; i < strlen(buf); i++)
		if (buf[i] == '.') buf[i] = '_';
	fprintf(out, "%s", buf);
	for (u64 i = 0; i < size; i++) {
		fprintf(out, "0x%02x, ", data[i]);
		if ((i + 1) % 16 == 0) {
			fprintf(out, "\n");
		} else {
			fprintf(out, " ");
		}
	}
	file_sizes[file_count] = size;
	fprintf(out, "0x00};\nconst u64 %sxxdir_file_size_%i = %zu;\n",
		namespace, file_count, size);
}

void proc_file(const u8 *file_path, const u8 *output_header, FILE *out,
	       const u8 *namespace) {
	FILE *file = fopen(file_path, "rb");
	if (file == NULL) {
		perror("Failed to open file");
		exit(-1);
	}

	// Determine the file size
	fseek(file, 0, SEEK_END);
	i64 file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	// Read the file into memory
	u8 *data = malloc(file_size);
	if (data == NULL) {
		perror("Failed to allocate memory");
		fclose(file);
		exit(-1);
	}
	fread(data, 1, file_size, file);
	fclose(file);

	// Print the hexadecimal representation
	print_hex(data, file_size, out, file_path, namespace);
	file_count++;

	// Clean up
	free(data);
}

i32 main(i32 argc, char **argv) {
	if (argc != 3 && argc != 4) {
		fprintf(stderr,
			"Usage: xxdir <resource_directory> <header name> "
			"<optional namespace>\n");
		exit(-1);
	}

	const u8 *dir_path = argv[1];
	const u8 *output_header = argv[2];

	u8 namespace[1000] = "";  // Initialize to empty string
	if (argc == 4) {
		if (argv[3] == NULL) {
			fprintf(stderr, "Error: argv[3] is NULL\n");
			exit(-1);
		}
		// Check length to prevent overflow (leave space for "_" and
		// null terminator)
		u64 len = strlen(argv[3]);
		if (len > 998) {  // 1000 - 1 for "_" - 1 for null terminator
			fprintf(stderr, "Error: namespace too long\n");
			exit(-1);
		}
		snprintf(namespace, sizeof(namespace), "%s_", argv[3]);
	}  // No else needed, namespace is already empty

	FILE *out = fopen(output_header, "w");
	if (out == NULL) {
		fprintf(stderr, "Could not open output file\n");
		exit(-1);
	}

	DIR *dir = opendir(dir_path);
	if (dir == NULL) {
		perror("Error opening directory");
		exit(-1);
	}

	u8 initial_text[2048];
	snprintf(initial_text, sizeof(initial_text),
		 "const u8 *%sxxdir_file_names[] = {", namespace);

	// add three bytes for the last strcat
	u8 *buf = malloc(sizeof(u8) * (strlen(initial_text) + 8));
	i32 cur_alloc = strlen(initial_text);
	strcpy(buf, initial_text);

	fprintf(out, "#include <libfam/types.h>\n");

	struct dirent *entry;
	printf("Creating binary header:\n");
	while ((entry = readdir(dir)) != NULL) {
		// Skip the "." and ".." entries
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		// Print the name of the file or directory
		printf("Including: %s\n", entry->d_name);
		u8 full_path[strlen(entry->d_name) + strlen(dir_path) + 100];
		strcpy(full_path, dir_path);
		strcat(full_path, "/");
		strcat(full_path, entry->d_name);

		proc_file(full_path, output_header, out, namespace);

		u8 *tmp = realloc(buf, cur_alloc + strlen(entry->d_name) + 30);
		if (tmp == NULL) {
			fprintf(stderr, "Alloc error!\n");
			exit(-1);
		}
		cur_alloc += strlen(entry->d_name) + 4;
		buf = tmp;
		strcat(buf, "\"");
		strcat(buf, entry->d_name);
		strcat(buf, "\", ");
	}

	// 7 bytes preallocated
	strcat(buf, "(void *)0};");
	// write the names to the file
	fprintf(out, "%s", buf);

	fprintf(out, "\nconst i32 %sxxdir_file_count=%i;\n", namespace,
		file_count);

	fprintf(out, "const u8 *%sxxdir_files[] = {", namespace);
	for (int i = 0; i < file_count; i++)
		fprintf(out, "%sxxdir_file_%i,", namespace, i);
	fprintf(out, "(void*)0};\n");
	fprintf(out, "const u64 %sxxdir_file_sizes[] = { ", namespace);
	for (i32 i = 0; i < file_count; i++)
		fprintf(out, "%i, ", file_sizes[i]);
	fprintf(out, "0};\n");

	free(buf);

	fclose(out);
	closedir(dir);

	printf("Binary header complete.\n");

	return 0;
}
