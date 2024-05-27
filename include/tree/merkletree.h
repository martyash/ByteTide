#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stddef.h>
#include <stdio.h>
#include <chk/pkgchk.h>

#define SHA256_HEXLEN (64)

typedef struct merkle_tree_node {
    //void* key;
    //void* value;
    char value[SHA256_HEXLEN];
    struct merkle_tree_node* left;
    struct merkle_tree_node* right;
    int is_leaf;
    char expected_hash[SHA256_HEXLEN + 1]; // actual hash from file
    char computed_hash[SHA256_HEXLEN + 1]; // expected has gone through hashing
}merkle_tree_node;


typedef struct merkle_tree {
    struct merkle_tree_node* nodes;
    size_t n_nodes;
}merkle_tree;

struct merkle_tree* create_merkle_tree(bpkg_obj* obj);
// call get_load

void get_computed_hash_for_chunk(FILE* f, uint32_t offset, size_t size, char* output_hash);

void populate_leaf_nodes_computed(FILE* f,merkle_tree* tree ,bpkg_obj* obj, int first_leaf_index);

void populate_leaf_nodes_expected(FILE* f,merkle_tree* tree ,bpkg_obj* obj, int first_leaf_index);

void populate_non_leaf_nodes_expected(merkle_tree* tree ,bpkg_obj* obj);
void populate_non_leaf_nodes_computed(merkle_tree* tree , int first_leaf_index);

// void compute_hash_non_leaf(merkle_tree tree, char* combined_hashes, char* computed_hash);


void merkle_tree_destroy(merkle_tree* tree);

void set_children(merkle_tree* tree);

void in_order_traversal(merkle_tree_node* node, int* count);
void in_order_with_query(merkle_tree_node* node, bpkg_query* qry, int* index);

#endif
