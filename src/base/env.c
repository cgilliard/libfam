/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025-2026 Christopher Gilliard
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

#include <libfam/env.h>
#include <libfam/errno.h>
#include <libfam/rbtree.h>
#include <libfam/string.h>
#include <libfam/syscall.h>
#include <libfam/types.h>
#include <libfam/utils.h>

#define MAX_ENV_VARS 1024

RbTree __env_tree = RBTREE_INIT;
typedef struct {
	RbTreeNode reserved;
	const u8 *key;
	const u8 *value;
	u64 key_len;
} EnvNode;

u8 **environ;
EnvNode __env_values[MAX_ENV_VARS];

STATIC i32 compare_env_keys(const EnvNode *v1, const EnvNode *v2) {
	i32 cmp;
	u64 min_len = v1->key_len < v2->key_len ? v1->key_len : v2->key_len;
	if ((cmp = strncmp(v1->key, v2->key, min_len))) return cmp;
	return v1->key_len < v2->key_len   ? -1
	       : v1->key_len > v2->key_len ? 1
					   : 0;
}

STATIC i32 env_rbtree_search(RbTreeNode *cur, const RbTreeNode *value,
			     RbTreeNodePair *retval) {
	while (cur) {
		const EnvNode *v1 = ((const EnvNode *)cur);
		const EnvNode *v2 = ((const EnvNode *)value);
		i32 v = compare_env_keys(v1, v2);
		if (!v) {
			retval->self = cur;
			break;
		} else if (v < 0) {
			retval->parent = cur;
			retval->is_right = true;
			cur = cur->right;
		} else {
			retval->parent = cur;
			retval->is_right = false;
			cur = cur->left;
		}
		retval->self = cur;
	}
	return 0;
}

char *getenv(const char *name) {
	u8 *ret = NULL;
	RbTreeNodePair pair = {0};
	EnvNode node;
	node.key = name;
	node.key_len = faststrlen(name);
	env_rbtree_search(__env_tree.root, (const RbTreeNode *)&node, &pair);
	if (pair.self) ret = (u8 *)((EnvNode *)pair.self)->value;
	return ret;
}

i32 init_environ(u8 **envp) {
#define RETURN_ERR(v)      \
	do {               \
		errno = v; \
		return -1; \
	} while (0);
	i32 i;
	for (i = 0; envp && i < MAX_ENV_VARS && envp[i]; i++) {
		u8 *itt = envp[i];
		i32 res;
		__env_values[i].key = envp[i];
		__env_values[i].key_len = 0;
		while (*itt && (*(itt++) != '=')) __env_values[i].key_len++;
		__env_values[i].value = itt;
		res = rbtree_put(&__env_tree, (RbTreeNode *)&__env_values[i],
				 env_rbtree_search);
		if (res < 0) RETURN_ERR(EDUPLICATE);
	}
	if (i == MAX_ENV_VARS && envp[i]) RETURN_ERR(EOVERFLOW);
	environ = envp;
	return 0;
}
