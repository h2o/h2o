#Klib: a Generic Library in C

##<a name="overview"></a>Overview

Klib is a standalone and lightweight C library distributed under [MIT/X11
license][1]. Most components are independent of external libraries, except the
standard C library, and independent of each other. To use a component of this
library, you only need to copy a couple of files to your souce code tree
without worrying about library dependencies.

Klib strives for efficiency and a small memory footprint. Some components, such
as khash.h, kbtree.h, ksort.h and kvec.h, are among the most efficient
implementations of similar algorithms or data structures, in terms of both
speed and memory use.

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


##<a name="philosophy"></a>Philosophy

For the implementation of generic [containers][21], klib extensively uses C
marcos. To use these data structures, you usually need to instantiate methods
by expanding a long macro. This makes the source code look unusual or even ugly
and adds difficulty to debugging. However, for efficient generic programming
in C where we do not have effective [template][22] syntax in C++, using marcos
is the only solution. Only with marcos, you can write a generic container
which, once instantiated, is able to achieve the same efficiency as a
type-specific container. Some generic libraries in C, such as [Glib][23],
use the `void*` type to implement containers. These implementations
are usually slower and use more memory than klib.


##<a name="resources"></a>Resources

* Library documentations, if present, are available in the header files. Examples
can be found in the [test/][24] directory.
* An **obsolete** documentation of the hash table library can be found at
[SourceForget][25].
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
