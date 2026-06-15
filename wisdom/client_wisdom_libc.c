#include "dr_api.h"
//#include "drsyms.h"
#include "drmgr.h"
#include "drwrap.h"
#include <string.h>
#include <stdio.h>



void patch_gets(void *wrapcxt, DR_PARAM_OUT void **user_data) {
    // pre-function code: this will be executed before the original gets function is called
    dr_printf("[Patching gets...]\n");
    // Get the first argument of gets, which is the buffer "wis" where the input will be stored
    char *buffer = (char *) drwrap_get_arg(wrapcxt, 0);

    if (buffer != NULL) {
        // Read buffer from input stream (file descriptor 0) instead of using gets
        ssize_t bytes_read = dr_read_file(0, buffer, 511);
        // Null-terminate the buffer and remove the newline character if present, gets would have returned a string with a null terminator and no newline character
        if (bytes_read > 0) {
            if (buffer[bytes_read - 1] == '\n') {
                buffer[bytes_read - 1] = '\0';
            }
            else {
                // Null-terminate the buffer if no newline was found
                buffer[bytes_read] = '\0';
                //In case we have more input than the buffer can hold, we truncate it to avoid overflowing
                char temp;
                while (dr_read_file(0, &temp, 1) == 1){
                    if (temp == '\n') {
                        break;
                    }
                } 
            }

            // We skip the original gets function and set the return value to the buffer we just read, as gets would have done
            dr_printf("[Patching gets... Done]\n");
            drwrap_skip_call(wrapcxt, buffer, 0);
        }
        else {
            // If bytes read is 0 or negative, it means there was an error reading the input, we can set the return value to NULL to indicate an error
            dr_printf("[DR] Error reading input\n");
            drwrap_skip_call(wrapcxt, NULL, 0);
        }
    } 
    else {
            dr_printf("[DR] Error reading input\n");
            // Set return value to NULL on receiving a NULL buffer
            drwrap_skip_call(wrapcxt, NULL, 0);
    }
}    







void event_module_load_libc(void *drcontext, const module_data_t* info, bool loaded) {
    // Check if the loaded module is the wisdom library
    const char* module_name = dr_module_preferred_name(info);

    // If the module name is "libc.so.6", then we can patch it
    // Alternatively, strstr(module_name, "libc.so") if we don't know the exact version of libc 
    if (module_name != NULL && strcmp(module_name, "libc.so.6") == 0){

        dr_printf("Loaded libc\n");
        dr_printf("Patching gets...\n");

    // We are interested in patching the gets function, so we can check if the module contains it
        app_pc gets_addr = (app_pc) dr_get_proc_address(info->handle, "gets");

        if (gets_addr != NULL) {
            dr_printf("Found gets at address: %p\n", gets_addr);
            // Wrap the gets function, calling the patch_gets before executing gets
            drwrap_wrap(gets_addr, patch_gets, NULL);
        }
        else {
            dr_printf("Failed to find gets in libc\n");
        }     
        
    }
    else {
        // Error loading module or not the target module
        dr_printf("Loaded module: %s\n", module_name);
    }
}

void event_exit(void) {
    drmgr_exit();
    drwrap_exit();
   // drsyms_exit();
}

// Main function
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    // INitialize the symbol access library
   // drsyms_init();

    //Initialize the function wrapping and replacing extension
    drwrap_init();

    // Initialize the instrumentation manager
    drmgr_init();

    // Patch the wisdom library
    // check when a module is loaded if gets is present and patch it
    drmgr_register_module_load_event(event_module_load_libc);        

    // Register the exit event to clean up resources    
    dr_register_exit_event(event_exit);

    
}
