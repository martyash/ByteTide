#include <chk/pkgchk.h>
#include <tree/merkletree.h>
#include <crypt/sha256.h>
#define SHA256_BFLEN (1024)
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>


struct merkle_tree* create_merkle_tree(bpkg_obj* obj){
    // value will be hash string 
    // after hash hashes are exhausted assign chunk hashes to leaf nodes 
    // create the tree 
    merkle_tree* tree = malloc(sizeof(merkle_tree));
    if(!tree) return NULL;
    // get the height of the tree
    int height = ceil(log2(obj->n_chunks)) + 1; // Height of tree
    int total_nodes = (int)pow(2, height) - 1;
    // allocate continguous memory for the tree
    tree->nodes = malloc((total_nodes) * sizeof(merkle_tree_node));  
    tree->n_nodes = total_nodes;
    // get the first leaf index to populate 
    int first_leaf_index = (1 << (height - 1)) - 1;
    // open the file just once 
    char filepath[1024];
    sprintf(filepath, "resources/pkgs/%s", obj->file_name);
    FILE *f = fopen(filepath, "rb");
    if (f == NULL) {
    perror("Failed: ");   
    }
    if (!f) {
        free(tree->nodes);
        free(tree);
        return NULL;
    }
    // set assign each node its children
    set_children(tree); 
    populate_leaf_nodes_expected(f,tree,obj,first_leaf_index);
    populate_leaf_nodes_computed(f,tree,obj,first_leaf_index);
    //now start on non-leaf nodes from bottom upwards
    populate_non_leaf_nodes_expected(tree, obj);
    populate_non_leaf_nodes_computed(tree,first_leaf_index);
    fclose(f);
    return tree;
}



    
    
    void populate_leaf_nodes_expected(FILE* f,merkle_tree* tree ,bpkg_obj* obj,int first_leaf_index){
        for(int i = 0 ; i < obj->n_chunks; i++){
        // Zero out the expected and calculated hash array
        memset(tree->nodes[first_leaf_index + i].expected_hash, 0, HASH_SIZE + 1);
        // assign mk node expected hash   
        strcpy(tree->nodes[first_leaf_index + i].expected_hash, obj->chunks[i]->hash); // working good -- triple check
        tree->nodes->expected_hash[HASH_SIZE - 1] = '\0';
        tree->nodes[first_leaf_index + i].is_leaf = 1; // confirm it is a leaf node 
       
        }
    }

    void populate_leaf_nodes_computed(FILE* f,merkle_tree* tree ,bpkg_obj* obj,int first_leaf_index){
        char buf[SHA256_BFLEN];
        size_t nbytes = 0; 
        char final_hash[65] = {0};  // Ensure the hash string is initialized
        // int offset = 0;
        // int size = 0;  // This can be a constant if always 4096

        for (int i = 0; i < obj->n_chunks; i++) {
            fseek(f, obj->chunks[i]->offset, SEEK_SET);
            int size = obj->chunks[i]->size;

            memset(buf, 0, SHA256_BFLEN);  // Clear the buffer
            struct sha256_compute_data cdata;
            sha256_compute_data_init(&cdata);
            int total_read = 0;  // Reset total_read for the current chunk
            while (total_read < size && (nbytes = fread(buf, 1, SHA256_BFLEN, f)) > 0) {
                sha256_update(&cdata, buf, nbytes);  // Update hash with the bytes read
                total_read += nbytes;
            }
            sha256_finalize(&cdata);  // Finalize hash computation
            sha256_output_hex(&cdata, final_hash);  // Convert hash to hex string
            memset(tree->nodes[first_leaf_index + i].computed_hash, 0, HASH_SIZE + 1);
            // printf("Address of expected_hash: %p\n", (void*)&tree->nodes[first_leaf_index + i].expected_hash);
            strcpy(tree->nodes[first_leaf_index + i].computed_hash, final_hash);
            memset(tree->nodes[first_leaf_index + i].value, 0, HASH_SIZE + 1);
            strcpy(tree->nodes[first_leaf_index + i].value, final_hash);

            
        }
    }


    void populate_non_leaf_nodes_expected(merkle_tree* tree ,bpkg_obj* obj){
        for(int i = 0 ; i < obj->n_hashes ; i++){   
            memset(tree->nodes[i].expected_hash, 0, HASH_SIZE + 1);
            strcpy(tree->nodes[i].expected_hash, obj->hashes[i]);
            tree->nodes[i].is_leaf = 0;
        }
    }

    void populate_non_leaf_nodes_computed(merkle_tree* tree, int first_leaf_index){
        for(int i = first_leaf_index - 1 ; i >= 0 ; i--){
            char final_hash[65] = {0}; 
            char combined_hashes[SHA256_BFLEN] = {0};
            //int r_c_index = 2 * i + 2;
            merkle_tree_node node = tree->nodes[i];
            // Concatenate the hashes of the two children      
            sprintf(combined_hashes, "%s%s",node.left->computed_hash, node.right->computed_hash);
        // he/re we assign send c_h to undergo hashing and get assigned to non-leaf node c_hash
            // compute_hash_non_leaf(tree,combined_hashes, final_hash);
            struct sha256_compute_data chunk_data = {0};
            sha256_compute_data_init(&chunk_data);
            sha256_update(&chunk_data, combined_hashes, strlen(combined_hashes)); // new hash size h+h
            sha256_finalize(&chunk_data);
            sha256_output_hex(&chunk_data, final_hash);
            strcpy(tree->nodes[i].computed_hash, final_hash);
            
        }
    }

    
    void merkle_tree_destroy(merkle_tree* tree){
        if (tree == NULL) return;
        free(tree->nodes);  // free the array of nodes
        free(tree);  // Free the tree 
    }

    void set_children(merkle_tree* tree){

        for (int i = 0; i < tree->n_nodes; i++) {
            // we know its a perfect binary tree so we can use 2s to find index of children
            int left_i = (2 * i) + 1;
            int right_i = (2 * i) + 2;
            if (left_i < tree->n_nodes) {
                tree->nodes[i].left = &tree->nodes[left_i]; // set the pointer
            } else {
                tree->nodes[i].left = NULL; // when you reach leaf nodes
            }
            if (right_i < tree->n_nodes) {
                tree->nodes[i].right = &tree->nodes[right_i];
            } else {
                tree->nodes[i].right = NULL;
            }

            
        }

    }

    void in_order_traversal(merkle_tree_node* node, int* count){
        if(node){
            in_order_traversal(node->left, count);
            if(node->is_leaf){
                (*count)++;  
            }
            in_order_traversal(node->right, count);
        }
    }

    void in_order_with_query(merkle_tree_node* node, bpkg_query* qry, int* index){
        if (node) {
        in_order_with_query(node->left, qry, index);
        if(node->is_leaf){
            if(*index < qry->len){
                qry->hashes[*index] = strdup(node->expected_hash);
                (*index)++; 
            }
        }   
        in_order_with_query(node->right, qry, index);
        }
    }

    
