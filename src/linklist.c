#include "h2o.h"

void h2o_linklist_merge(h2o_linklist_t *head, h2o_linklist_t **added)
{
    if (*added != NULL) {
        if (head != NULL) {
            h2o_linklist_t *tail_of_head = head->prev, *tail_of_added = (*added)->prev;
            head->prev = tail_of_added->next;
            tail_of_added->next = head;
            tail_of_head->next = *added;
            (*added)->prev = tail_of_head;
        } else {
            head = *added;
        }
        *added = NULL;
    }
}
