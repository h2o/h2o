#include "h2o.h"
#include "h2o/configurator.h"

#include <net/if.h>

static int on_busy_poll_map(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (node->type != YOML_TYPE_MAPPING) {
        h2o_configurator_errprintf(cmd, node, "busy-poll-map not a mapping\n");
        return -1;
    }

    yoml_t **if_node = NULL;
    if (h2o_configurator_parse_mapping(cmd, node, "interfaces:a", NULL, &if_node) != 0) {
        return -1;
    }

    if ((*if_node)->type != YOML_TYPE_SEQUENCE) {
        h2o_configurator_errprintf(cmd, *if_node, "busy-poll-map interface map not a sequence\n");
        return -1;
    }

    /* create enough nic_to_cpu_map entries for all the NICs in the config */
    size_t nic_count = (*if_node)->data.sequence.size;

    /* there should be more than 0 nics specified but less than 32 (an
     * arbitrary number - I can't imagine having more than 32 NICs on a
     * machine).
     */
    if (nic_count < 1 || nic_count > 32) {
        h2o_configurator_errprintf(cmd, *if_node, "number of interfaces should be between 1-32\n");
        return -1;
    }
    ctx->globalconf->bp.nic_count = nic_count;
    h2o_busypoll_nic_vector_t *nic_to_cpu_map = &ctx->globalconf->bp.nic_to_cpu_map;

    h2o_vector_reserve(NULL, nic_to_cpu_map, nic_count);

    /* now gather the actual values from the config file */
    for (int i = 0; i != (*if_node)->data.sequence.size; ++i) {
        yoml_t *cur_node = (*if_node)->data.sequence.elements[i];
        yoml_t **index_node = NULL, **cpus_node = NULL, **options_node = NULL;
        if (h2o_configurator_parse_mapping(cmd, cur_node, "ifindex:s,cpus:a,options:m", NULL, &index_node, &cpus_node,
                                           &options_node) != 0) {
            h2o_configurator_errprintf(cmd, *if_node, "busy-poll-map interface block at index %d is invalid\n", i);
            continue;
        }
        h2o_configurator_scanf(cmd, *index_node, "%zu", &nic_to_cpu_map->entries[i].ifindex);

        char iface[IF_NAMESIZE] = {0};
        if (!if_indextoname(nic_to_cpu_map->entries[i].ifindex, iface)) {
            h2o_configurator_errprintf(cmd, *if_node, "busy-poll-map interface index %zu is invalid\n",
                                       nic_to_cpu_map->entries[i].ifindex);
            continue;
        }
        nic_to_cpu_map->entries[i].iface = h2o_strdup(NULL, iface, SIZE_MAX);

        pthread_mutex_init(&nic_to_cpu_map->entries[i].mutex, NULL);
        nic_to_cpu_map->entries[i].cpu_count = 0;
        CPU_ZERO(&nic_to_cpu_map->entries[i].cpu_map);
        for (int j = 0; j < (*cpus_node)->data.sequence.size; j++) {
            yoml_t *cpu_node = (*cpus_node)->data.sequence.elements[j];
            if (cpu_node->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, cpu_node, "cpu specified for iface %s is not a scalar\n",
                                           nic_to_cpu_map->entries[i].iface.base);
                return -1;
            }
            unsigned cpu_num;
            if (h2o_configurator_scanf(cmd, cpu_node, "%u", &cpu_num) == 0)
                CPU_SET(cpu_num, &nic_to_cpu_map->entries[i].cpu_map);
        }
        nic_to_cpu_map->entries[i].cpu_count = CPU_COUNT(&nic_to_cpu_map->entries[i].cpu_map);

        yoml_t **mode_node = NULL, **gro_node = NULL, **irq_node = NULL, **st_node = NULL;
        if (h2o_configurator_parse_mapping(cmd, *options_node, "mode:s", "gro-flush-timeout:s,defer-hard-irqs:s,suspend-timeout:s",
                                           &mode_node, &gro_node, &irq_node, &st_node) != 0) {
            h2o_configurator_errprintf(cmd, *if_node, "busy-poll-map interface block at index %d has invalid options\n", i);
            continue;
        }
        switch (h2o_configurator_get_one_of(cmd, *mode_node, "OFF,SUSPEND,BUSYPOLL")) {
        case 0:
            nic_to_cpu_map->entries[i].mode = BP_MODE_OFF;
            break;
        case 1:
            nic_to_cpu_map->entries[i].mode = BP_MODE_SUSPEND;
            break;
        case 2:
            nic_to_cpu_map->entries[i].mode = BP_MODE_BUSYPOLL;
            break;
        default:
            return -1;
        }

#ifndef H2O_HAS_YNL_H
        if (nic_to_cpu_map->entries[i].mode == BP_MODE_SUSPEND || nic_to_cpu_map->entries[i].mode == BP_MODE_BUSYPOLL) {
            h2o_configurator_errprintf(cmd, node, "libynl is not available and required to busypoll");
            return -1;
        }
#endif

        nic_to_cpu_map->entries[i].options.gro_flush_timeout = 0;
        nic_to_cpu_map->entries[i].options.defer_hard_irqs = 0;
        nic_to_cpu_map->entries[i].options.suspend_timeout = 0;
        if (gro_node) {
            h2o_configurator_scanf(cmd, *gro_node, "%zu", &nic_to_cpu_map->entries[i].options.gro_flush_timeout);
        }
        if (irq_node) {
            h2o_configurator_scanf(cmd, *irq_node, "%zu", &nic_to_cpu_map->entries[i].options.defer_hard_irqs);
        }
        if (st_node && nic_to_cpu_map->entries[i].mode == BP_MODE_SUSPEND) {
            h2o_configurator_scanf(cmd, *st_node, "%zu", &nic_to_cpu_map->entries[i].options.suspend_timeout);
        }

        fprintf(stderr, " ifindex %zu has %zd cpus\n", nic_to_cpu_map->entries[i].ifindex, nic_to_cpu_map->entries[i].cpu_count);
    }

    /* setup queues */
    for (int i = 0; i != nic_count; ++i) {
        h2o_busypoll_set_opts(nic_to_cpu_map->entries[i].ifindex, nic_to_cpu_map->entries[i].options.defer_hard_irqs,
                              nic_to_cpu_map->entries[i].options.gro_flush_timeout,
                              nic_to_cpu_map->entries[i].options.suspend_timeout);
    }

    return 0;
}

void h2o_busypoll_register_configurator(h2o_globalconf_t *conf)
{
    struct st_h2o_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    h2o_configurator_define_command(c, "busy-poll-map", H2O_CONFIGURATOR_FLAG_GLOBAL, on_busy_poll_map);
}

