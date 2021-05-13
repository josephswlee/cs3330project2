#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

// Access hardware timestamp counter
#define RDTSC(cycles) __asm__ volatile ("rdtsc" : "=a" (cycles));

// Serialize execution
#define CPUID() asm volatile ("CPUID" : : : "%rax", "%rbx", "%rcx", "%rdx");

// Intrinsic CLFLUSH for FLUSH+RELOAD attack
#define CLFLUSH(address) _mm_clflush(address);

#define SAMPLES 50 // TODO: CONFIGURE THIS

#define L1_CACHE_SIZE (32*1024)
#define LINE_SIZE 64
#define ASSOCIATIVITY 8
#define L1_NUM_SETS (L1_CACHE_SIZE/(LINE_SIZE*ASSOCIATIVITY))
#define NUM_OFFSET_BITS 6
#define NUM_INDEX_BITS 6
#define NUM_OFF_IND_BITS (NUM_OFFSET_BITS + NUM_INDEX_BITS)

uint64_t eviction_counts[L1_NUM_SETS] = {0};
__attribute__ ((aligned (64))) uint64_t trojan_array[32*4096];
__attribute__ ((aligned (64))) uint64_t spy_array[4096];


/* TODO:
 * This function provides an eviction set address, given the
 * base address of a trojan/spy array, the required cache
 * set ID, and way ID.
 *
   The address returned leads to the base of an eviction set. 
   This address points to the address of the second 
   way within the set.

   The algorithm first gets the tag bits by taking the base 
   and shifting right by the number of index and offset bits.
   This is because after the index and offset bits, the tag is 
   "what's left" so shifting by this value alone should result 
   in the correct number of tag bits being extracted.
 
   Using the base address get tag bits. Tag is the "rest" of 
   the address after index and offset bits. So it shifts right
   until tag bits are all that's left (ex address is 01010101 
   and there are 2 index and two offset bits then tag is >> by 
   4 and results in 0101)

  It then gets the index bits by shifting by the number of 
  offset bits. When doing this, there are still tag bits to 
  the left of the index so masking by 0x3f will make sure 
  that only the index bits are extracted. 0x3f in binary is 
  111111 which will get the six rightmost bits after shifting 
  stored into inx_bits

  The if statement compares the index bits to the set number. 
  If the index is greater than the set, we can end up with a 
  base address outside of the allotted space in memory.Thus, 
  we add the number of sets in L1 which should put the address
  back in the correct space.

  The else statement is for when we are already going to have an 
  address that is in the proper space in memory. When the set number 
  we want is bigger than the index value there is no reason to add 
  L1 num sets because the eviction set address generated will be 
  greater than the base array's address.
  
  (referencing Layne's piazza post example:
  	address 1010 1011 1100 1101 (where index is 1100 or 12) 
  	if we wanted to access set 2 with offset 0,
  	the new address is 1010 1011 0010 0000.
  	This new address is lower than the base address and would 
  	result in us starting before the base address of the array
  	and altering random memory that we shouldn't, which can have
  	different consequences. To correct this, we add L1 num sets 
  	to the set we want to access to make sure the address starts 
  	in the space we want it to.)
 */
uint64_t* get_eviction_set_address(uint64_t *base, int set, int way)
{
    uint64_t tag_bits = (((uint64_t)base) >> NUM_OFF_IND_BITS);
    int idx_bits = (((uint64_t)base) >> NUM_OFFSET_BITS) & 0x3f;

    if (idx_bits > set) {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) +
                               (L1_NUM_SETS + set)) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way));
    } else {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) + set) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way));
    }
}

/* This function sets up a trojan/spy eviction set using the
 * function above.  The eviction set is essentially a linked
 * list that spans all ways of the conflicting cache set.
 *
 * i.e., way-0 -> way-1 -> ..... way-7 -> NULL
 *
 */
void setup(uint64_t *base, int assoc)
{
    uint64_t i, j;
    uint64_t *eviction_set_addr;

    // Prime the cache set by set (i.e., prime all lines in a set)
    for (i = 0; i < L1_NUM_SETS; i++) {
        eviction_set_addr = get_eviction_set_address(base, i, 0);
        for (j = 1; j < assoc; j++) {
            *eviction_set_addr = (uint64_t)get_eviction_set_address(base, i, j);
            eviction_set_addr = (uint64_t *)*eviction_set_addr;
        }
        *eviction_set_addr = 0;
    }
}

/* TODO:
 *
 * This function implements the trojan that sends a message
 * to the spy over the cache covert channel.  Note that the
 * message forgoes case sensitivity to maximize the covert
 * channel bandwidth.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */
void trojan(char byte)
{
    int set;
    uint64_t *eviction_set_addr;

    if (byte >= 'a' && byte <= 'z') {
        byte -= 32;
    }
    if (byte == 10 || byte == 13) { // encode a new line
        set = 63;
    } else if (byte >= 32 && byte < 96) {
        set = (byte - 32);
    } else {
        printf("pp trojan: unrecognized character %c\n", byte);
        exit(1);
    }
    
    /* TODO:
     * Your attack code goes in here.
     *
     */ 

    /*eviction_set_addr=(uint64_t*)get_eviction_set_address(trojan_array, set, 0);
    int i;
    for(i = 1; i < ASSOCIATIVITY; i++){
        *eviction_set_addr = (uint64_t)get_eviction_set_address(trojan_array, set, i);
        eviction_set_addr = (uint64_t *)(*eviction_set_addr);
    }
    eviction_set_addr = 0;*/





    eviction_set_addr=(uint64_t*)get_eviction_set_address(trojan_array, set, 0);
    while (eviction_set_addr != 0){
        eviction_set_addr = (uint64_t*) *eviction_set_addr;
    }



    CPUID();








    /*uint64_t i;
    for(i = 0; i < 32*4096; i++){
        if(trojan_array[i] >> NUM_OFFSET_BITS) & 0x3f == set){
            
        }
    }*/
}

/* TODO:
 *
 * This function implements the spy that receives a message
 * from the trojan over the cache covert channel.  Evictions
 * are timed using appropriate hardware timestamp counters
 * and recorded in the eviction_counts array.  In particular,
 * only record evictions to the set that incurred the maximum
 * penalty in terms of its access time.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */
char spy()
{
    int i, max_set;
    uint64_t *eviction_set_addr;
    int max_time = 0;
    int before;
    int after;
    // Probe the cache line by line and take measurements
    
    for (i = 0; i < L1_NUM_SETS; i++) {
        //max_set = 0;
        /* TODO:
         * Your attack code goes in here.
         *
         */  

        
        
        RDTSC(before);
        
        eviction_set_addr=(uint64_t*)get_eviction_set_address(spy_array, i, 0);
        
        while (eviction_set_addr != 0){
            CPUID();  
            eviction_set_addr = (uint64_t*) *eviction_set_addr;
            
        }
        
        RDTSC(after)
        if(max_time < after - before){
            max_set = i;
            max_time = after - before;
        }
    }
    eviction_counts[max_set]++;
}

int main()
{
    FILE *in, *out;
    in = fopen("transmitted-secret.txt", "r");
    out = fopen("received-secret.txt", "w");

    int j, k;
    int max_count, max_set;

    // TODO: CONFIGURE THIS -- currently, 32*assoc to force eviction out of L2
    setup(trojan_array, ASSOCIATIVITY*32);

    setup(spy_array, ASSOCIATIVITY);
    
    for (;;) {
        char msg = fgetc(in);
        if (msg == EOF) {
            break;
        }
        for (k = 0; k < SAMPLES; k++) {
          trojan(msg);
          //CPUID();
          spy();
        }
        for (j = 0; j < L1_NUM_SETS; j++) {
            if (eviction_counts[j] > max_count) {
                max_count = eviction_counts[j];
                max_set = j;
            }
            eviction_counts[j] = 0;
        }
        if (max_set >= 33 && max_set <= 59) {
            max_set += 32;
        } else if (max_set == 63) {
            max_set = -22;
        }
        fprintf(out, "%c", 32 + max_set);
        max_count = max_set = 0;
    }
    fclose(in);
    fclose(out);
}
