#Klib: a Generic Library in C

##<a name="overview"></a>Overview

Klib is a standalone and lightweight C library distributed under [MIT/X11
license][1]. Most components are independent of external libraries, except the
standard C library, and independent of each other. To use a component of this
library, you only need to copy a couple of files to your souce code tree
without worrying about library dependencies.

Klib strives for efficiency and a small memory footprint. Some components, such
as khash.h, kbtree.h, ksort.h and kvec.h, are among the most efficient
implementations of similar algorithms or data structures in all programming
languages, in terms of both speed and memory use.

####Common components

* khash.h: generic hash table based on [double hashing][2].
* kbtree.h: generic search tree based on [B-tree][3].
* ksort.h: generic sort, including [introsort][4], [merge sort][5], [heap sort][6], [comb sort][7], [Knuth shuffle][8] and the [k-small][9] algorithm.
* kseq.h: generic stream buffer and a [FASTA][10]/[FASTQ][11] format parser.
* kvec.h: generic dynamic array.
* klist.h: generic single-linked list and [memory pool][12].
* kstring.{h,c}: basic string library.
* kmath.{h,c}: numerical routines including [MT19937-64][13] [pseudorandom generator][14], basic [nonlinear programming][15] and a few special math functions.

####Components for more specific use cases

* ksa.c: constructing [suffix arrays][16] for strings with multiple sentinels, based on a revised [SAIS algorithm][17].
* knetfile.{h,c}: random access to remote files on HTTP or FTP.
* kopen.c: smart stream opening.
* khmm.{h,c}: basic [HMM][18] library.
* ksw.(h,c}: Striped [Smith-Waterman algorithm][19].
* knhx.{h,c}: [Newick tree format][20] parser.


##<a name="methodology"></a>Methodology

For the implementation of generic [containers][21], klib extensively uses C
marcos. To use these data structures, we usually need to instantiate methods by
expanding a long macro. This makes the source code look unusual or even ugly
and adds difficulty to debugging. Unfortunately, for efficient generic
programming in C where there is [template][22] in C++, using marcos is the only
solution. Only with marcos, we can write a generic container which, once
instantiated, compete with a type-specific container in efficiency. Some
generic libraries in C, such as [Glib][23], use the `void*` type to implement
containers. These implementations are usually slower and use more memory than
klib (see [this benchmark][31]).

To effectively use klib, it is important to understand how it achieves generic
programming. We will use the hash table library as an example:

    #include "khash.h"
    KHASH_MAP_INIT_INT(m32, char)        // instantiate structs and methods
    int main() {
        int ret, is_missing;
        khint_t k;
        khash_t(m32) *h = kh_init(m32);  // allocate a hash table
        k = kh_put(m32, h, 5, &ret);     // insert a key to the hash table
        if (!ret) kh_del(m32, h, k);
        kh_value(h, k) = 10;             // set the value
        k = kh_get(m32, h, 10);          // query the hash table
        is_missing = (k == kh_end(h));   // test if the key is present
        k = kh_get(m32, h, 5);
        kh_del(m32, h, k);               // remove a key-value pair
        for (k = kh_begin(h); k != kh_end(h); ++k)  // traverse
            if (kh_exist(h, k))          // test if a bucket contains data
    			kh_value(h, k) = 1;
        kh_destroy(m32, h);              // deallocate the hash table
        return 0;
    }

In this example, the second line instantiates a hash table with `unsigned` as
the key type and `char` as the value type. `m32` names such a type of hash table.
All types and functions associated with this name are macros, which will be
explained later. Macro `kh_init()` initiates a hash table and `kh_destroy()`
frees it. `kh_put()` inserts a key and returns the iterator (or the position)
in the hash table. `kh_get()` and `kh_del()` get a key and delete an element,
respectively. Macro `kh_exist()` tests if an iterator (or a position) is filled
with data.

An immediate question is this piece of code does not look like a valid C
program (e.g. lacking semicolon, assignment to an _apparent_ function call and
_apparent_ undefined `m32` 'variable'). To understand why the code is correct,
let's go a bit further into the source code of `khash.h`, whose skeleton looks
like:

    #define KHASH_INIT(name, SCOPE, key_t, val_t, is_map, _hashf, _hasheq) \
      typedef struct { \
        int n_buckets, size, n_occupied, upper_bound; \
        unsigned *flags; \
        key_t *keys; \
        val_t *vals; \
      } kh_##name##_t; \
      SCOPE inline kh_##name##_t *init_##name() { \
        return (kh_##name##_t*)calloc(1, sizeof(kh_##name##_t)); \
      } \
      SCOPE inline int get_##name(kh_##name##_t *h, key_t k) \
      ... \
      SCOPE inline void destroy_##name(kh_##name##_t *h) { \
        if (h) { \
          free(h->keys); free(h->flags); free(h->vals); free(h); \
        } \
      }
    
    #define _int_hf(key) (unsigned)(key)
    #define _int_heq(a, b) (a == b)
    #define khash_t(name) kh_##name##_t
    #define kh_value(h, k) ((h)->vals[k])
    #define kh_begin(h, k) 0
    #define kh_end(h) ((h)->n_buckets)
    #define kh_init(name) init_##name()
    #define kh_get(name, h, k) get_##name(h, k)
    #define kh_destroy(name, h) destroy_##name(h)
    ...
    #define KHASH_MAP_INIT_INT(name, val_t) \
    	KHASH_INIT(name, static, unsigned, val_t, is_map, _int_hf, _int_heq)

`KHASH_INIT()` is a huge marco defining all the structs and methods. When this
marco is called, all the code inside it will be inserted by the [C
preprocess][37] to the place where it is called. If the marco is called
multiple times, multiple copies of the code will be inserted. To avoid naming
conflict of hash tables with different key-value types, the library uses [token
concatenation][36], which is a preprocessor feature whereby we can substitute
part of a symbol based on the parameter of the marco. In the end, the C
preprocessor will generate the following code and feed it to the compiler
(macro `kh_exist(h,k)` is a little complex and not expanded for simplicity):

    typedef struct {
      int n_buckets, size, n_occupied, upper_bound;
      unsigned *flags;
      unsigned *keys;
      char *vals;
    } kh_m32_t;
    static inline kh_m32_t *init_m32() {
      return (kh_m32_t*)calloc(1, sizeof(kh_m32_t));
    }
    static inline int get_m32(kh_m32_t *h, unsigned k)
    ...
    static inline void destroy_m32(kh_m32_t *h) {
      if (h) {
        free(h->keys); free(h->flags); free(h->vals); free(h);
      }
    }

	int main() {
		int ret, is_missing;
		khint_t k;
		kh_m32_t *h = init_m32();
		k = put_m32(h, 5, &ret);
		if (!ret) del_m32(h, k);
		h->vals[k] = 10;
		k = get_m32(h, 10);
		is_missing = (k == h->n_buckets);
		k = get_m32(h, 5);
		del_m32(h, k);
		for (k = 0; k != h->n_buckets; ++k)
			if (kh_exist(h, k)) h->vals[k] = 1;
		destroy_m32(h);
		return 0;
	}

This is the C program we know.

From this example, we can see that marcos and the C preprocessor plays a key
role in klib. Klib is fast partly because the compiler knows the key-value
type at the compile time and is able to optimize the code to the same level
as type-specific code. A generic library writen with `void*` will not get such
performance boost.

Massively inserting code upon instantiation may remind us of C++'s slow
compiling speed and huge binary size when STL/boost is in use. Klib is much
better in this respect due to its small code size and component independency.
Inserting several hundreds lines of code won't make compiling obviously slower.

##<a name="resources"></a>Resources

* Library documentations, if present, are available in the header files. Examples
can be found in the [test/][24] directory.
* An **obsolete** documentation of the hash table library can be found at
[SourceForget][25]. This README is partly adapted from the old documentation.
* [Blog post][26] describing the hash table library.
* [Blog post][27] on why using `void*` for generic programming may be inefficient.
* [Blog post][28] on the generic stream buffer.
* [Blog post][29] evaluating the performance of `kvec.h`.
* [Blog post][30] arguing B-tree may be a better data structure than a binary search tree.
* [Blog post][31] evaluating the performance of `khash.h` and `kbtree.h` among many other implementations.
[An older version][33] of the benchmark is also available.
* [Blog post][34] benchmarking internal sorting algorithms and implementations.
* [Blog post][32] on the k-small algorithm.
* [Blog post][35] on the Hooke-Jeeve's algorithm for nonlinear programming.

[1]: http://en.wikipedia.org/wiki/MIT_License
[2]: http://en.wikipedia.org/wiki/Double_hashing
[3]: http://en.wikipedia.org/wiki/B-tree
[4]: http://en.wikipedia.org/wiki/Introsort
[5]: http://en.wikipedia.org/wiki/Merge_sort
[6]: http://en.wikipedia.org/wiki/Heapsort
[7]: http://en.wikipedia.org/wiki/Comb_sort
[8]: http://en.wikipedia.org/wiki/Fisher-Yates_shuffle
[9]: http://en.wikipedia.org/wiki/Selection_algorithm
[10]: http://en.wikipedia.org/wiki/FASTA_format
[11]: http://en.wikipedia.org/wiki/FASTQ_format
[12]: http://en.wikipedia.org/wiki/Memory_pool
[13]: http://en.wikipedia.org/wiki/Mersenne_twister
[14]: http://en.wikipedia.org/wiki/Pseudorandom_generator
[15]: http://en.wikipedia.org/wiki/Nonlinear_programming
[16]: http://en.wikipedia.org/wiki/Suffix_array
[17]: https://sites.google.com/site/yuta256/sais
[18]: http://en.wikipedia.org/wiki/Hidden_Markov_model
[19]: http://en.wikipedia.org/wiki/Smith-Waterman_algorithm
[20]: http://en.wikipedia.org/wiki/Newick_format
[21]: http://en.wikipedia.org/wiki/Container_(abstract_data_type)
[22]: http://en.wikipedia.org/wiki/Template_(C%2B%2B)
[23]: http://en.wikipedia.org/wiki/GLib
[24]: https://github.com/attractivechaos/klib/tree/master/test
[25]: http://klib.sourceforge.net/
[26]: http://attractivechaos.wordpress.com/2008/09/02/implementing-generic-hash-library-in-c/
[27]: http://attractivechaos.wordpress.com/2008/10/02/using-void-in-generic-c-programming-may-be-inefficient/
[28]: http://attractivechaos.wordpress.com/2008/10/11/a-generic-buffered-stream-wrapper/
[29]: http://attractivechaos.wordpress.com/2008/09/19/c-array-vs-c-vector/
[30]: http://attractivechaos.wordpress.com/2008/09/24/b-tree-vs-binary-search-tree/
[31]: http://attractivechaos.wordpress.com/2008/10/07/another-look-at-my-old-benchmark/
[32]: http://attractivechaos.wordpress.com/2008/09/13/calculating-median/
[33]: http://attractivechaos.wordpress.com/2008/08/28/comparison-of-hash-table-libraries/
[34]: http://attractivechaos.wordpress.com/2008/08/28/comparison-of-internal-sorting-algorithms/
[35]: http://attractivechaos.wordpress.com/2008/08/24/derivative-free-optimization-dfo/
[36]: http://en.wikipedia.org/wiki/C_preprocessor#Token_concatenation
[37]: http://en.wikipedia.org/wiki/C_preprocessor
