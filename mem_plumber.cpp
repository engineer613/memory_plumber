#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <execinfo.h>

#include <stdint.h>
#include <pthread.h>

#include <iostream>
#include <vector>
#include <atomic>
#include <cstring>
#include <regex>

#define MAX_ALLOCATIONS 10000
#define HASH_MAP_SIZE 4096 


// Define function pointers for functions with signature like malloc and free
typedef void* (*malloc_fptr)(size_t); 
typedef void (*free_fptr)(void*);

// Function pointers to store ptrs to actual (libc) functions
static malloc_fptr libcMalloc = nullptr; 
static free_fptr libcFree = nullptr;


// Application Memory Allocation Record. Each time memory's allocated, one of these is added to the hash map 
typedef struct alloc_mem {
  void* ptr;
  size_t size;
  struct alloc_mem* next; 
  bool in_use;
  void* stack[32];      // stack trace
  int stack_size;       // num frames
} AllocRecord;


static AllocRecord alloc_record_pool[MAX_ALLOCATIONS];  // Pre-allocate memory to keep track of allocations in the application
static AllocRecord* alloc_record_map[HASH_MAP_SIZE];  // Hash table to keep track of allocations. Maps pointer to AllocRecord*
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static int alloc_info_index = 0;
static int alloc_count = 0;

// Simple hash function that returns a key between 0 - 4095
static inline int hash_ptr(void* ptr) {
  uintptr_t addr = (uintptr_t)ptr;
  return (addr >> 3) & (HASH_MAP_SIZE - 1); // Equivalent to (addr/8) % 4095
}


// Prevent recursive calls from within custom malloc() and free() implementations
static std::atomic<bool> use_libc = true;


// Check if any memory hasn't been deallocated- if true, print out values and backtraces from when they were allocated
// Call when exiting
void check_for_leaks() {

  use_libc.store(true); // Printing backtraces is easier to do with C++ STL, which calls malloc() underneath.

  try{
    pthread_mutex_lock(&mtx);
    
    if(alloc_count > 0) {
        std::cout << "\n\n\nMEMORY LEAKS DETECTED:" << std::endl;
        for(int i = 0; i < HASH_MAP_SIZE; ++i) {
          AllocRecord* mem = alloc_record_map[i];

          if(mem && mem->in_use) {
            std::cout << "\n\n  Leaking " << mem->size << " bytes at " << mem->ptr << std::endl;

            // Print out backtrace 
            char** symbols = backtrace_symbols(mem->stack, mem->stack_size);

            if (symbols) {
              std::vector<std::string> trace;
              std::cout << "  Allocation Backtrace:" << std::endl;
              for (int i = 1; i < mem->stack_size; ++i) {
                trace.emplace_back(symbols[i]);
              }

              free(symbols);

              std::regex regex_pattern(R"(^([^\s(]+)\(([^)]+)\))");
              std::smatch match;
              for(const auto& frame : trace) {
                if( std::regex_search(frame, match, regex_pattern) ) {
                  std::string binary = match[1];
                  std::string offset = match[2];
                  std::string addr2line_cmd = "addr2line -e "  + binary + " " + offset;

                  char backtrace_buffer[128];
                  std::string backtrace_result;
                  if( unsetenv("LD_PRELOAD") == 0 ) {
                    FILE* pipe = popen(addr2line_cmd.c_str(), "r");

                    if(!pipe) {
                      std::cout << "[ERROR] addr2line command failed to run with popen()" << std::endl;
                      break; 
                    }
                    
                    while(fgets(backtrace_buffer, sizeof(backtrace_buffer), pipe) != nullptr) {
                      backtrace_result += backtrace_buffer;
                    }

                    if(backtrace_result.find('?') == std::string::npos)                    
                      std::cout << "    " << backtrace_result;
                  
                  }
                }
              }
            }
          }
        }

    } else {
        std::cout << "No Memory Leaks Detected!" << std::endl;
    }
    
    pthread_mutex_unlock(&mtx);

  } catch (...) {
      std::cout << "[ERROR] Crashed while running check_for_leaks()" << std::endl;
  }
}  


// Custom implementation of malloc()
extern "C" void* malloc(size_t size) {

  if(!libcMalloc) {
    // If it got here, then it's still initializing, so init function pointer with libc's malloc and call it
    libcMalloc = (malloc_fptr) dlsym(RTLD_NEXT, "malloc");
    return libcMalloc(size);
  }

  // If use_libc isn't set to true, call libc's orignal malloc()
  if (use_libc) {
    return libcMalloc(size);
  }

  // Any recursive calls to free after this should just call the libc version
  use_libc.store(true); 

  // Custom malloc() logic
  void* mem_ptr = libcMalloc(size);
  
  // Add new_alloc to hash table at the right location
  if(mem_ptr && alloc_info_index < MAX_ALLOCATIONS) {
    pthread_mutex_lock(&mtx);
    
    // Get an AllocRecord instance from preallocated memory
    AllocRecord* new_alloc = &alloc_record_pool[alloc_info_index++];
    new_alloc->ptr = mem_ptr;
    new_alloc->size = size;
    new_alloc->in_use = true;
    
    // Get backtrace
    new_alloc->stack_size = backtrace(new_alloc->stack, 32);
    
    // get hash key from the pointer address
    int key = hash_ptr(mem_ptr);

    // new_alloc should be inserted at the beginning of chain so it is at the head
    new_alloc->next = alloc_record_map[key]; // point new_alloc->next to old head 
    alloc_record_map[key] = new_alloc; // Make map[key] point to new head which is new_alloc
    
    alloc_count++;
    
    pthread_mutex_unlock(&mtx);
  }

  use_libc.store(false);
  return mem_ptr;  
}



// Custom implementation of free()
extern "C" void free(void* mem_ptr) {
  static free_fptr libcFree = nullptr; // Func pointer to store pointer to store libc free

  if(!libcFree) {
    libcFree = (free_fptr)dlsym(RTLD_NEXT, "free");
  } 

  if(use_libc) {
    return libcFree(mem_ptr);
  } 
  
  use_libc.store(true); // Any recursive calls to free after this should just call the libc version
  
  // Remove allocation record from chain in the hash table where it was inserted
  if(mem_ptr) {
    pthread_mutex_lock(&mtx);
    
    int key = hash_ptr(mem_ptr);
    
    AllocRecord** current = &alloc_record_map[key];
    AllocRecord* dealloc_mem = NULL;

    while(*current) {
      // If the pointer is found, remove from chain- this is similar to a linked list node deletion 
      if( ((*current)->ptr == mem_ptr) && (*current)->in_use) {
        // Save a pointer to the AllocRecord* instance that needs to be removed
        dealloc_mem = *current;

        // Connect nodes around dealloc_mem. current points to (prev_node_ptr->next)
        *current = (*current)->next; // Point prev node's next to current node's next

        // Mark dealloc_mem as not in use
        dealloc_mem->in_use = false;
        alloc_count--;
        break;
      }

      // Else keep looking
      current = &((*current)->next);
    }
    pthread_mutex_unlock(&mtx);
  }

  use_libc.store(false);
  libcFree(mem_ptr);
}



// this  runs the register_leak_checker function when this library is loaded BEFORE main() runs
__attribute__((constructor))
void register_leak_checker() {
  // Register check_for_leaks to run at exit with atexit()
  // atexit(F) runs F AFTER main() exits
  atexit(check_for_leaks);
  
  // Init is done- can switch to custom implementations of malloc() and free()
  use_libc.store(false);
}
