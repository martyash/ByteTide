#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <chk/pkgchk.h>
#include <crypt/sha256.h>
#include <tree/merkletree.h>
#include <string.h>
#include <sys/stat.h>
#include <math.h>
#define ONE_TIME_READ 1

// PART 1


/**
 * Loads the package for when a valid path is given
 */

    
struct bpkg_obj* bpkg_load(const char* path) {

    char true_path[1024];
    sprintf(true_path, "resources/pkgs/%s", path); // make real path as 'path' is just file name
    FILE* file = fopen(true_path, "rb");
    if (!file) return NULL;
    bpkg_obj* object = malloc(sizeof(bpkg_obj));
    char buffer[2048]; 
    // get identity  --- working
    char word[2048];
    uint32_t size;
    fgets(buffer,sizeof(buffer),file); // 1 line // send to buffer, read from file
    sscanf(buffer, "ident:%s\n",word);// read from buffer store in word
    strncpy(object->identifier, word, MAX_IDENT_LENGTH); // ident set
    object->identifier[MAX_IDENT_LENGTH - 1] = '\0'; // ensure proper null termination
    //printf("%s",object->identifier);
    memset(buffer, 0, sizeof(buffer)); // clear buffer
    memset(word, 0 , sizeof(word)); // clear word holder
    // get filename  --- working
    fgets(buffer,sizeof(buffer),file);
    sscanf(buffer, "filename:%s\n",word);
    strncpy(object->file_name, word, MAX_FILENAME_LENGTH);
    object->file_name[MAX_FILENAME_LENGTH - 1] = '\0';
    memset(buffer, 0, sizeof(buffer)); // clear buffer
    memset(word, 0 , sizeof(word)); // clear word holder
    // get file size  --- working 
    fgets(buffer,sizeof(buffer),file);
    sscanf(buffer, "size:%u\n",&size);
    object->size = size;
    //printf("%i", object->size);
    memset(buffer, 0, sizeof(buffer)); // clear buffer
    // get nhashes --- working 
    fgets(buffer,sizeof(buffer),file);
    sscanf(buffer, "nhashes:%u\n",&size);
    object->n_hashes = size;
    //printf("%i", object->n_hashes);
    // get hashes --- working 
    fgets(buffer,sizeof(buffer),file); // hashes:
    buffer[strcspn(buffer, "\n")] = '\0'; // remove newline 
    if (strcmp(buffer,"hashes:") == 0){
        // first allocate memory for pointer which points to 1st element of array of pointers
        object->hashes = malloc(object->n_hashes * sizeof(char*));

        for(int i = 0 ; i < (object->n_hashes);i++){
            object->hashes[i] = malloc(HASH_SIZE * sizeof(char));
            // if there is an allocation failure 
            if (object->hashes[i] == NULL) {
            for (int j = 0; j < i; j++) {
                free(object->hashes[j]);
            }
            free(object->hashes);
            }

            fgets(buffer,sizeof(buffer),file);
            sscanf(buffer, "%s\n",word); // properly with no empty spaces
            // store inside ith element 
            strncpy(object->hashes[i], word, HASH_SIZE); //destination,string u want to copy,no.of characters
            memset(buffer, 0, sizeof(buffer)); // clear buffer
            memset(word, 0 , sizeof(word)); // clear word holder
        }
        
    }
    // get nchunks --- working
    fgets(buffer,sizeof(buffer),file);
    sscanf(buffer, "nchunks:%u\n", &size);
    object->n_chunks = size;
    fgets(buffer,sizeof(buffer),file); // chunks:
    memset(buffer, 0, sizeof(buffer)); // clear buffer
    memset(word, 0 , sizeof(word)); // clear word holder
    // get chunks --- working
    // allocate memory for pointer to array of pointers 
    object->chunks = malloc(object->n_chunks * sizeof(chunk*));

    char delimiter[2] = ",";


    for(int chunk_index = 0 ; chunk_index < (object->n_chunks); chunk_index++){
        // allocate memory for the chunk
        object->chunks[chunk_index] = malloc(sizeof(chunk));

        fgets(buffer,sizeof(buffer),file);
        sscanf(buffer, "%s",word);
        char* token = strtok(word,delimiter);
        int i = 0;
        while(token != NULL){
            if(i == 0){
                //printf("This is stage %d %s\n",chunk_index,token);
                strncpy(object->chunks[chunk_index]->hash, token, HASH_SIZE);
            }
            if(i == 1){
                //printf("This is the offset %s\n",token);
                object->chunks[chunk_index]->offset = atoi(token);
            }if(i == 2){
                //printf("this is the byte size %s\n",token);
                object->chunks[chunk_index]->size = atoi(token);
            }
            token = strtok(NULL,delimiter);
            i++;
        }

    }
    fclose(file);
    return object;
}

/**
 * Checks to see if the referenced filename in the bpkg file
 * exists or not.
 * @param bpkg, constructed bpkg object
 * @return query_result, a single string should be
 *      printable in hashes with len sized to 1.
 * 		If the file exists, hashes[0] should contain "File Exists"
 *		If the file does not exist, hashes[0] should contain "File Created"
 */
struct bpkg_query bpkg_file_check(struct bpkg_obj* bpkg){

    // check obj->filename exists inside the directory
    bpkg_query file_check_query;
    // only 1 pointer needed 
    file_check_query.hashes = malloc(sizeof(char*)); // make pointer
    file_check_query.hashes[0] = malloc(20* sizeof(char)); // malloc space for a string
    file_check_query.len = 0;

    // sprintf (where to store, format, what to add)
    char file_location[1024];
    sprintf(file_location, "resources/pkgs/%s", bpkg->file_name);
    FILE* data_file = fopen(file_location, "rb+");
    if (!data_file){
        //create file of size bpkg->size
        file_check_query.hashes[0] = strdup("File Created"); // statically allocated
        file_check_query.len = 1;
        for (size_t i = 0 ; i < bpkg->size; i++){
            fputc(0, data_file);
        }
    }else{
        //hashes[0] should contain file exists
        file_check_query.hashes[0] = strdup("File Exists");
        file_check_query.len = 1;
        //struct stat st;
        // if (stat(file_location, &st) == 0 && st.st_size == bpkg->size) {
        //     printf("File is the correct size\n");
        // } else {
        //     printf("File size is incorrect\n");
        // }
    }
    fclose(data_file);
    // file is the correct size
    return file_check_query;
    
}

/**
 * Retrieves a list of all hashes within the package/tree
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_hashes(struct bpkg_obj* bpkg) {
    // this means all the hash hashes + chunk hashes
    // create query statically
    bpkg_query qry;
    // allocate memory for n pointers
    qry.hashes = malloc((bpkg->n_hashes + bpkg->n_chunks) * sizeof(char*));
   
    // allocate memory for each string/block 
    for (int i = 0; i < ((bpkg->n_hashes) + (bpkg->n_chunks)); i++) {
    qry.hashes[i] = malloc(HASH_SIZE * sizeof(char));  // Allocate memory for each hash
    }

    size_t index = 0;
    for(int i = 0 ; i < (bpkg->n_hashes); i++, index++){
        strncpy(qry.hashes[index], bpkg->hashes[i], HASH_SIZE);
    }
    for(int i = 0 ; i < (bpkg->n_chunks); i++,index++){
        strncpy(qry.hashes[index], bpkg->chunks[i]->hash, HASH_SIZE);
    }
    qry.len = bpkg->n_hashes + bpkg->n_chunks;
    
    
    return qry;
}

/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(struct bpkg_obj* bpkg) { 
    struct bpkg_query qry = { 0 };
    qry.hashes = NULL;
    qry.len = 0;
    merkle_tree* tree = create_merkle_tree(bpkg);
    int height = ceil(log2(tree->n_nodes + 1));
    int first_leaf_index = pow(2, height - 1) - 1;
    int total_count = 0;
    for(int i = first_leaf_index ; i < tree->n_nodes ; i++){      
        if(strcmp(tree->nodes[i].expected_hash , tree->nodes[i].computed_hash) == 0){
            total_count += 1;
        }
    }
    if (total_count > 0){
        qry.hashes = malloc(total_count * sizeof(char*));
    }
    qry.len = total_count;
    int index = 0;
    for(int i = first_leaf_index ; i < tree->n_nodes && index < total_count ; i++){      
        if(strcmp(tree->nodes[i].expected_hash , tree->nodes[i].computed_hash) == 0){
            qry.hashes[index++] = strdup(tree->nodes[i].computed_hash);
        }
    }


    merkle_tree_destroy(tree);
    return qry;
}


/**
 * Gets only the required/min hashes to represent the current completion state
 * Return the smallest set of hashes of completed branches to represent
 * the completion state of the file.
 *
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_min_completed_hashes(struct bpkg_obj* bpkg) {
    struct bpkg_query qry = {0};
    merkle_tree* tree = create_merkle_tree(bpkg);
    int* mark = calloc(tree->n_nodes, sizeof(int));

    int height = ceil(log2(tree->n_nodes + 1));
    int first_leaf_index = pow(2, height - 1) - 1;

    for (int i = first_leaf_index; i < tree->n_nodes; i++) {
        mark[i] = strcmp(tree->nodes[i].expected_hash, tree->nodes[i].computed_hash) == 0;
    }

    // completeness going upwards
    for (int i = first_leaf_index - 1; i >= 0; i--) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        if (left < tree->n_nodes && right < tree->n_nodes) {
            mark[i] = mark[left] && mark[right];
        }
    }

    // Count and collect the minimal set of hashes
    int count = 0;
    for (int i = 0; i < tree->n_nodes; i++) {
        int parent_index = (i - 1) / 2;
        // Include hash if node is complete and (it's root or parent is not complete)
        if (mark[i] && (i == 0 || !mark[parent_index])) {
            count++;
        }
    }

    if (count > 0) {
        qry.hashes = malloc(count * sizeof(char*));
        qry.len = count;
        int index = 0;

        for (int i = 0; i < tree->n_nodes; i++) {
            int parent_index = (i - 1) / 2;
            if (mark[i] && (i == 0 || !mark[parent_index])) {
                qry.hashes[index++] = strdup(tree->nodes[i].computed_hash);
            }
        }
    }

    free(mark);
    merkle_tree_destroy(tree);

    return qry;
}


/**
 * Retrieves all chunk hashes given a certain an ancestor hash (or itself)
 * Example: If the root hash was given, all chunk hashes will be outputted
 * 	If the root's left child hash was given, all chunks corresponding to
 * 	the first half of the file will be outputted
 * 	If the root's right child hash was given, all chunks corresponding to
 * 	the second half of the file will be outputted
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */


// retrieve chunks based on ancestor
struct bpkg_query bpkg_get_all_chunk_hashes_from_hash(struct bpkg_obj* bpkg, 
    char* hash) {
    bpkg_query qry;
    qry.len = 0;
    qry.hashes = NULL;
    // create tree to get all hashes
    merkle_tree* tree = create_merkle_tree(bpkg);
    int index = 0; // will store the index of where the hash exists in the tree
    int count = 0;
    //printf("this is the hash %s\n",hash);
    for(int i = 0 ; i < tree->n_nodes ; i++){ // find the node
        if(strcmp(tree->nodes[i].expected_hash,hash) == 0){ // found in tree
            index = i;                        
        }
    }
    //perform in order traversal to see how many nodes will be visited
    in_order_traversal(&tree->nodes[index], &count);
    qry.hashes = malloc(count * sizeof(char*));
    qry.len = count;
    int array_index = 0 ;
    in_order_with_query(&tree->nodes[index],&qry, &array_index);
    merkle_tree_destroy(tree);
    return qry;
    }
    

/**
 * Deallocates the query result after it has been constructed from
 * the relevant queries above.
 */
void bpkg_query_destroy(struct bpkg_query* qry) {
    if(qry != NULL){
        if(qry->len > 0){
            for(int i = 0; i < qry->len; i++){
                free(qry->hashes[i]);
            }   
        }
        // free the pointer
        if(qry->hashes != NULL){
            free(qry->hashes);
        }
    }
}

/**
 * Deallocates memory at the end of the program,
 * make sure it has been completely deallocated
 */
void bpkg_obj_destroy(struct bpkg_obj* obj) {
    //TODO: Deallocate here!
    //free the chunks first
    for(int i = 0 ; i < obj->n_chunks; i++){
        free(obj->chunks[i]);
    }
    //then finally free chunk pointer
    free(obj->chunks);
    //free the hashes 
    for(int i = 0 ; i < obj->n_hashes ; i++){
        free(obj->hashes[i]);
    }
    //finally free hash pointer
    free(obj->hashes);

    free(obj);

}


