/*
 * Copyright (c) 2026 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <assert.h>
#include <stdlib.h>
#include "picotls.h"
#include "quicly/bplus_ranges.h"

#define FANOUT_BITS QUICLY_BPLUS_RANGES_FANOUT_BITS
#define FANOUT QUICLY_BPLUS_RANGES_FANOUT
/**
 * minimum number of entries in a node other than the root
 */
#define MIN_ENTRIES (FANOUT / 2)
/**
 * The number of ranges is capped so that the receive window can be maintained even in the worst case, where every one of the two
 * packets being sent are lost and each packet carries >= ~512 bytes of the stream (see https://github.com/h2o/quicly/issues/278).
 * The cap is at least MIN_MAX_RANGES so that streams with small windows carrying small frames can tolerate some loss, and at most
 * MAX_RANGES, which is what a window of 4GB permits.
 */
#define BYTES_PER_RANGE 1024
#define MIN_MAX_RANGES 63
#define MAX_RANGES (1 << 22)
/**
 * maximum height of the tree, which bounds the descent path kept on the stack; see `calc_max_ranges` for why it is sufficient
 */
#define MAX_HEIGHT 8

/**
 * One level of the path from the root to a range; a path is an array of these, indexed by the level.
 */
struct st_quicly_bplus_ranges_path_t {
    quicly_bplus_ranges_node_t *node;
    /**
     * index of the child being chosen for non-leaf nodes, or the index of the range for the leaf; for the leaf, -1 points to the
     * last range of the preceding leaf (or to the position before the first range of the first leaf)
     */
    int slot;
};

#define EMPTY_RANGE ((quicly_range_t){UINT64_MAX, UINT64_MAX})

static void init_leaf(quicly_bplus_ranges_node_t *node)
{
    for (int i = 0; i < FANOUT; ++i)
        node->ranges[i] = EMPTY_RANGE;
}

/**
 * Returns the number of ranges in the leaf whose start is <= x, which is also the index of the first range whose start is > x. As
 * the ranges are sorted and unused slots hold UINT64_MAX, the number is found by a binary search of fixed steps (8, 4, 2, 1),
 * accumulating the results of the comparisons without branching. The 16th slot is compared separately.
 */
static int leaf_count_le(const quicly_bplus_ranges_node_t *leaf, uint64_t x)
{
    PTLS_BUILD_ASSERT(PTLS_ELEMENTSOF(leaf->ranges) == 16);

    int n = (leaf->ranges[7].start <= x) << 3;
    n += (leaf->ranges[n + 3].start <= x) << 2;
    n += (leaf->ranges[n + 1].start <= x) << 1;
    n += leaf->ranges[n].start <= x;
    return n + (leaf->ranges[15].start <= x);
}

/**
 * Returns the number of keys in the non-leaf node that are <= x, which is the index of the child to descend into. As the first
 * child has no key, `keys[1]` to `keys[15]` are searched in the same way as `leaf_count_le`.
 */
static int keys_count_le(const quicly_bplus_ranges_node_t *node, uint64_t x)
{
    PTLS_BUILD_ASSERT(PTLS_ELEMENTSOF(node->keys) == 16);

    int n = ((node->keys[8] <= x) << 3) + 1;
    n += (node->keys[n + 3] <= x) << 2;
    n += (node->keys[n + 1] <= x) << 1;
    return n - 1 + (node->keys[n] <= x);
}

/**
 * Returns if the node has an entry at given index; as entries are packed, this tells if the node has more than `index` entries. For
 * non-leaf nodes, the entry is the child, which exists if its key is in use; `index` must therefore be non-zero.
 */
static int has_entry(const quicly_bplus_ranges_node_t *node, int is_leaf, int index)
{
    return is_leaf ? node->ranges[index].start != UINT64_MAX : node->keys[index] != UINT64_MAX;
}

/**
 * inserts a range at `pos` of a leaf that is not full, shifting the ranges up to the first unused slot
 */
static void insert_range_at(quicly_bplus_ranges_node_t *leaf, int pos, quicly_range_t range)
{
    for (;; ++pos) {
        quicly_range_t displaced = leaf->ranges[pos];
        leaf->ranges[pos] = range;
        if (displaced.start == UINT64_MAX)
            break;
        range = displaced;
    }
}

/**
 * removes the range at `pos` of a leaf, returning it
 */
static quicly_range_t remove_range_at(quicly_bplus_ranges_node_t *leaf, int pos)
{
    quicly_range_t removed = leaf->ranges[pos];
    for (; pos + 1 < FANOUT && leaf->ranges[pos + 1].start != UINT64_MAX; ++pos)
        leaf->ranges[pos] = leaf->ranges[pos + 1];
    leaf->ranges[pos] = EMPTY_RANGE;
    return removed;
}

/**
 * inserts a child and its key at `index` (which must be non-zero) of a non-leaf node that is not full, shifting the entries up to
 * the first unused slot
 */
static void insert_entry_at(quicly_bplus_ranges_node_t *node, int index, uint64_t key, quicly_bplus_ranges_node_t *child)
{
    for (;; ++index) {
        uint64_t displaced_key = node->keys[index];
        node->keys[index] = key;
        if (displaced_key == UINT64_MAX) {
            node->children[index] = child;
            break;
        }
        quicly_bplus_ranges_node_t *displaced_child = node->children[index];
        node->children[index] = child;
        key = displaced_key;
        child = displaced_child;
    }
}

/**
 * removes the child and its key at `index` (which must be non-zero) of a non-leaf node, returning the key
 */
static uint64_t remove_entry_at(quicly_bplus_ranges_node_t *node, int index)
{
    uint64_t removed = node->keys[index];
    for (; index + 1 < FANOUT && node->keys[index + 1] != UINT64_MAX; ++index) {
        node->keys[index] = node->keys[index + 1];
        node->children[index] = node->children[index + 1];
    }
    node->keys[index] = UINT64_MAX;
    return removed;
}

/**
 * returns if `ranges->last` points into the given leaf; `ranges->last` must be non-NULL
 */
static int holds_last(quicly_bplus_ranges_t *ranges, quicly_bplus_ranges_node_t *leaf)
{
    return (uintptr_t)ranges->last - (uintptr_t)leaf->ranges < sizeof(leaf->ranges);
}

static size_t calc_max_ranges(quicly_bplus_ranges_t *ranges, uint64_t max_committed)
{
    /* As nodes other than the root hold at least MIN_ENTRIES entries, a tree of MAX_HEIGHT holds at least
     * 2 * MIN_ENTRIES^(MAX_HEIGHT - 1) ranges. Ranges are inserted only while there are less than MAX_RANGES, therefore the tree
     * never grows beyond MAX_HEIGHT. */
    PTLS_BUILD_ASSERT(MAX_RANGES <= (uint64_t)2 << ((FANOUT_BITS - 1) * (MAX_HEIGHT - 1)));

    uint64_t first_end = ranges->num_ranges != 0 ? ranges->first.ranges[0].end : 0;
    assert(first_end <= max_committed);
    uint64_t max_ranges = (max_committed - first_end) / BYTES_PER_RANGE + 1;
    if (max_ranges < MIN_MAX_RANGES)
        max_ranges = MIN_MAX_RANGES;
    if (max_ranges > MAX_RANGES)
        max_ranges = MAX_RANGES;
    return (size_t)max_ranges;
}

/**
 * Sets `path` to the last range whose start is <= x. When no such range exists, the slot of the leaf (which is the first leaf) is
 * set to -1.
 */
static void descend(quicly_bplus_ranges_t *ranges, uint64_t x, struct st_quicly_bplus_ranges_path_t *path)
{
    quicly_bplus_ranges_node_t *node = ranges->root;
    size_t level;

    for (level = 0; level + 1 < ranges->height; ++level) {
        path[level].node = node;
        path[level].slot = keys_count_le(node, x);
        node = node->children[path[level].slot];
    }
    path[level].node = node;
    path[level].slot = leaf_count_le(node, x) - 1;
}

/**
 * updates the separator that refers to the smallest start found under `path[level].node`
 */
static void update_separator(struct st_quicly_bplus_ranges_path_t *path, size_t level, uint64_t new_min)
{
    while (level-- != 0) {
        if (path[level].slot != 0) {
            path[level].node->keys[path[level].slot] = new_min;
            return;
        }
    }
}

/**
 * Moves `path` to the last range of the leaf preceding the one it points to. The leaf being pointed to must not be the first.
 */
static void prev_leaf(quicly_bplus_ranges_t *ranges, struct st_quicly_bplus_ranges_path_t *path)
{
    size_t leaf_level = ranges->height - 1, level = leaf_level;

    /* go up to the lowest node where the path can step to the preceding child, then down along the last children */
    while (path[--level].slot == 0)
        ;
    quicly_bplus_ranges_node_t *node = path[level].node->children[--path[level].slot];
    while (++level < leaf_level) {
        path[level].node = node;
        path[level].slot = keys_count_le(node, UINT64_MAX - 1);
        node = node->children[path[level].slot];
    }
    path[leaf_level].node = node;
    path[leaf_level].slot = leaf_count_le(node, UINT64_MAX - 1) - 1;
}

/**
 * Splits a full node by moving its high half to `high`, returning the key that separates the two.
 */
static uint64_t split_node(quicly_bplus_ranges_t *ranges, quicly_bplus_ranges_node_t *node, quicly_bplus_ranges_node_t *high,
                           int is_leaf)
{
    if (is_leaf) {
        for (int i = 0; i < MIN_ENTRIES; ++i) {
            high->ranges[i] = node->ranges[MIN_ENTRIES + i];
            high->ranges[MIN_ENTRIES + i] = EMPTY_RANGE;
            node->ranges[MIN_ENTRIES + i] = EMPTY_RANGE;
        }
        /* if the node holds `last`, it is the last entry of the node, which is in the high half */
        if (holds_last(ranges, node))
            ranges->last = high->ranges + (ranges->last - node->ranges - MIN_ENTRIES);
        return high->ranges[0].start;
    } else {
        uint64_t sep = node->keys[MIN_ENTRIES];
        for (int i = 0; i < MIN_ENTRIES; ++i) {
            high->keys[i] = node->keys[MIN_ENTRIES + i];
            high->keys[MIN_ENTRIES + i] = UINT64_MAX;
            high->children[i] = node->children[MIN_ENTRIES + i];
            node->keys[MIN_ENTRIES + i] = UINT64_MAX;
        }
        return sep;
    }
}

/**
 * Inserts a range that does not overlap or touch any existing range right after the one pointed to by `path`, splitting full nodes
 * from the bottom up. The nodes being needed are allocated before anything is modified.
 */
static quicly_error_t insert_range(quicly_bplus_ranges_t *ranges, struct st_quicly_bplus_ranges_path_t *path, uint64_t start,
                                   uint64_t end)
{
    size_t leaf_level = ranges->height - 1, level, num_new_nodes = 0, new_node_index = 0;
    int pos = path[leaf_level].slot + 1;
    quicly_bplus_ranges_node_t *new_nodes[MAX_HEIGHT + 1];

    /* allocate a node for each of the leaf and its ancestors that are full, and one for the new root if all of them are full */
    for (level = ranges->height; level-- != 0 && has_entry(path[level].node, level == leaf_level, FANOUT - 1);)
        ++num_new_nodes;
    if (num_new_nodes == ranges->height) {
        assert(ranges->height < MAX_HEIGHT);
        ++num_new_nodes;
    }
    for (size_t i = 0; i < num_new_nodes; ++i) {
        if ((new_nodes[i] = malloc(sizeof(*new_nodes[i]))) == NULL) {
            while (i-- != 0)
                free(new_nodes[i]);
            return PTLS_ERROR_NO_MEMORY;
        }
    }

    /* insert to leaf, splitting it if full; when inserting at the split point, the range goes to the low half */
    quicly_bplus_ranges_node_t *node = path[leaf_level].node, *high = NULL;
    uint64_t sep = 0;
    if (num_new_nodes != 0) {
        high = new_nodes[new_node_index++];
        sep = split_node(ranges, node, high, 1);
        if (pos > MIN_ENTRIES) {
            node = high;
            pos -= MIN_ENTRIES;
        }
    }
    insert_range_at(node, pos, (quicly_range_t){start, end});
    if (ranges->last == NULL) {
        ranges->last = node->ranges + pos;
    } else if (holds_last(ranges, node)) {
        ++ranges->last;
    }
    ++ranges->num_ranges;

    /* insert the high half of the split node to the parent, splitting the parent if full */
    for (level = leaf_level; high != NULL; --level) {
        if (level == 0) {
            quicly_bplus_ranges_node_t *root = new_nodes[new_node_index++];
            root->keys[1] = sep;
            for (int i = 2; i < FANOUT; ++i)
                root->keys[i] = UINT64_MAX;
            root->children[0] = ranges->root;
            root->children[1] = high;
            ranges->root = root;
            ++ranges->height;
            break;
        }
        quicly_bplus_ranges_node_t *parent = path[level - 1].node, *child = high;
        int slot = path[level - 1].slot;
        uint64_t child_sep = sep;
        high = NULL;
        if (has_entry(parent, 0, FANOUT - 1)) {
            high = new_nodes[new_node_index++];
            sep = split_node(ranges, parent, high, 0);
            if (slot >= MIN_ENTRIES) {
                parent = high;
                slot -= MIN_ENTRIES;
            }
        }
        insert_entry_at(parent, slot + 1, child_sep, child);
    }

    assert(new_node_index == num_new_nodes);
    return 0;
}

/**
 * Removes the range pointed to by `path`, rebalancing the tree. `path` is updated to point to the range that preceded the removed
 * one, as rebalancing might move it. When two nodes are merged, the high one is freed; therefore `first` is never freed.
 */
static void delete_range(quicly_bplus_ranges_t *ranges, struct st_quicly_bplus_ranges_path_t *path)
{
    size_t level = ranges->height - 1;
    quicly_bplus_ranges_node_t *node = path[level].node;

    /* remove from leaf */
    remove_range_at(node, path[level].slot);
    if (holds_last(ranges, node))
        --ranges->last;
    --ranges->num_ranges;
    if (path[level].slot == 0)
        update_separator(path, level, node->ranges[0].start);
    --path[level].slot;

    /* Rebalance, while `node` has MIN_ENTRIES - 1 entries. The sibling is the high one unless `node` is the last child; as the
     * sibling has at least MIN_ENTRIES entries, it is merged if it has exactly that many, otherwise an entry is borrowed. The slot
     * of `path` is updated when the entries of `node` move. */
    for (; level != 0 && !has_entry(node, level == ranges->height - 1, MIN_ENTRIES - 1); --level) {
        int is_leaf = level == ranges->height - 1;
        quicly_bplus_ranges_node_t *parent = path[level - 1].node, *low, *high;
        int slot = path[level - 1].slot, num_low, sep;
        if (slot + 1 < FANOUT && has_entry(parent, 0, slot + 1)) {
            sep = slot + 1;
            low = node;
            high = parent->children[sep];
            num_low = MIN_ENTRIES - 1;
            if (has_entry(high, is_leaf, MIN_ENTRIES)) {
                /* borrow the first entry of `high` */
                if (is_leaf) {
                    low->ranges[num_low] = remove_range_at(high, 0);
                    parent->keys[sep] = high->ranges[0].start;
                    if (holds_last(ranges, high))
                        --ranges->last;
                } else {
                    low->keys[num_low] = parent->keys[sep];
                    low->children[num_low] = high->children[0];
                    parent->keys[sep] = high->keys[1];
                    high->children[0] = high->children[1];
                    remove_entry_at(high, 1);
                }
                break;
            }
        } else {
            sep = slot;
            low = parent->children[sep - 1];
            high = node;
            num_low = MIN_ENTRIES;
            if (has_entry(low, is_leaf, MIN_ENTRIES)) {
                /* borrow the last entry of `low` */
                num_low = is_leaf ? leaf_count_le(low, UINT64_MAX - 1) : keys_count_le(low, UINT64_MAX - 1) + 1;
                if (is_leaf) {
                    insert_range_at(high, 0, remove_range_at(low, num_low - 1));
                    parent->keys[sep] = high->ranges[0].start;
                    if (holds_last(ranges, high))
                        ++ranges->last;
                } else {
                    insert_entry_at(high, 1, parent->keys[sep], high->children[0]);
                    high->children[0] = low->children[num_low - 1];
                    parent->keys[sep] = remove_entry_at(low, num_low - 1);
                }
                ++path[level].slot;
                break;
            }
        }
        /* merge `high` into `low`; the two hold 2 * MIN_ENTRIES - 1 entries in total */
        int num_high = 2 * MIN_ENTRIES - 1 - num_low;
        if (is_leaf) {
            for (int i = 0; i < num_high; ++i)
                low->ranges[num_low + i] = high->ranges[i];
            if (holds_last(ranges, high))
                ranges->last = low->ranges + num_low + (ranges->last - high->ranges);
        } else {
            low->keys[num_low] = parent->keys[sep];
            low->children[num_low] = high->children[0];
            for (int i = 1; i < num_high; ++i) {
                low->keys[num_low + i] = high->keys[i];
                low->children[num_low + i] = high->children[i];
            }
        }
        free(high);
        remove_entry_at(parent, sep);
        if (node == high) {
            path[level].node = low;
            path[level].slot += num_low;
            path[level - 1].slot = sep - 1;
        }
        node = parent;
    }

    /* shrink the tree if the root has only one child */
    if (ranges->height > 1 && !has_entry(ranges->root, 0, 1)) {
        quicly_bplus_ranges_node_t *old_root = ranges->root;
        ranges->root = old_root->children[0];
        --ranges->height;
        free(old_root);
        for (level = 0; level < ranges->height; ++level)
            path[level] = path[level + 1];
    }
}

/**
 * frees the descendants of a non-leaf node, except for `first` which is not allocated
 */
static void free_children(quicly_bplus_ranges_t *ranges, quicly_bplus_ranges_node_t *node, size_t height)
{
    int num_children = keys_count_le(node, UINT64_MAX - 1) + 1;

    for (int i = 0; i < num_children; ++i) {
        quicly_bplus_ranges_node_t *child = node->children[i];
        if (height > 2)
            free_children(ranges, child, height - 1);
        if (child != &ranges->first)
            free(child);
    }
}

void quicly_bplus_ranges_clear(quicly_bplus_ranges_t *ranges)
{
    if (ranges->height > 1) {
        free_children(ranges, ranges->root, ranges->height);
        free(ranges->root);
    }
    init_leaf(&ranges->first);
    ranges->num_ranges = 0;
    ranges->height = 1;
    ranges->root = &ranges->first;
    ranges->last = NULL;
}

quicly_error_t quicly_bplus_ranges_add(quicly_bplus_ranges_t *ranges, uint64_t start, uint64_t end, uint64_t max_committed)
{
    struct st_quicly_bplus_ranges_path_t path[MAX_HEIGHT];

    assert(start <= end);

    if (start == end)
        return 0;

    /* fast path; when the range starts within or right after the last range, only the last range can be touched */
    if (ranges->last != NULL && ranges->last->start <= start && start <= ranges->last->end) {
        if (ranges->last->end < end)
            ranges->last->end = end;
        return 0;
    }

    /* find the last range whose start is <= end */
    descend(ranges, end, path);
    struct st_quicly_bplus_ranges_path_t *leaf = path + ranges->height - 1;

    /* insert if the range does not overlap or touch any of the existing ranges */
    if (leaf->slot < 0 || leaf->node->ranges[leaf->slot].end < start) {
        if (ranges->num_ranges >= calc_max_ranges(ranges, max_committed))
            return QUICLY_ERROR_STATE_EXHAUSTION;
        return insert_range(ranges, path, start, end);
    }

    /* Merge, starting from the last range that touches. The range is extended, then merged into its predecessor while the
     * predecessor touches. When the range is the first one of a leaf, the predecessor is found by walking `path` to the preceding
     * leaf. */
    quicly_range_t *r = leaf->node->ranges + leaf->slot;
    if (r->end < end)
        r->end = end;
    while (start < r->start) {
        quicly_range_t *pred;
        if (leaf->slot != 0) {
            pred = r - 1;
        } else if (leaf->node == &ranges->first) {
            break;
        } else {
            struct st_quicly_bplus_ranges_path_t pred_path[MAX_HEIGHT];
            for (size_t level = 0; level < ranges->height; ++level)
                pred_path[level] = path[level];
            prev_leaf(ranges, pred_path);
            pred = pred_path[ranges->height - 1].node->ranges + pred_path[ranges->height - 1].slot;
        }
        if (pred->end < start)
            break;
        uint64_t pred_start = pred->start;
        pred->end = r->end;
        delete_range(ranges, path);
        if (pred_start <= start)
            return 0;
        /* more ranges might touch; continue with the predecessor, which `delete_range` has tracked */
        leaf = path + ranges->height - 1;
        if (leaf->slot < 0)
            prev_leaf(ranges, path);
        r = leaf->node->ranges + leaf->slot;
    }
    if (start < r->start) {
        r->start = start;
        if (leaf->slot == 0)
            update_separator(path, ranges->height - 1, start);
    }

    return 0;
}
