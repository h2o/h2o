
static int on_epoll_nonblock(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
#if H2O_USE_EPOLL_BUSYPOLL
    int nonblock_mode = 0;
    if ((nonblock_mode = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;

    conf.bp.epoll_nonblock = nonblock_mode;
    return 0;
#else
    h2o_configurator_errprintf(cmd, node, "support for epoll busypolling is not available");
    return -1;
#endif
}

static int on_epoll_prefer_bp(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
#if H2O_USE_EPOLL_BUSYPOLL
    int prefer = 0;
    if ((prefer = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;

    conf.bp.epoll_bp_prefer = prefer == 1;
    return 0;
#else
    h2o_configurator_errprintf(cmd, node, "support for epoll busypolling is not available");
    return -1;
#endif
}

static int on_busy_poll_budget(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
#if H2O_USE_EPOLL_BUSYPOLL
    if (h2o_configurator_scanf(cmd, node, "%" PRIu64, &conf.bp.epoll_bp_budget) != 0) {
        return -1;
    }

    return 0;
#else
    h2o_configurator_errprintf(cmd, node, "support for epoll busypolling is not available");
    return -1;
#endif
}

static int on_busy_poll_usecs(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
#if H2O_USE_EPOLL_BUSYPOLL
    if (h2o_configurator_scanf(cmd, node, "%" PRIu64, &conf.bp.epoll_bp_usecs) != 0)
        return -1;

    return 0;
#else
    h2o_configurator_errprintf(cmd, node, "support for epoll busypolling is not available");
    return -1;
#endif
}

static int on_busy_poll_map(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
#if H2O_USE_EPOLL_BUSYPOLL
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
    conf.bp.nic_count = nic_count;
    h2o_busypoll_nic_vector_t *nic_to_cpu_map = &conf.bp.nic_to_cpu_map;

    h2o_vector_reserve(NULL, nic_to_cpu_map, nic_count);

    /* now gather the actual values from the config file */
    for (int i = 0; i != nic_count; ++i) {
        yoml_t *cur_node = (*if_node)->data.sequence.elements[i];
        yoml_t **index_node = NULL, **cpus_node = NULL, **options_node = NULL;
        struct busypoll_nic_t *nic = &nic_to_cpu_map->entries[i];
        memset(nic, 0, sizeof(*nic));
        if (h2o_configurator_parse_mapping(cmd, cur_node, "ifindex:s,cpus:a,options:m", NULL, &index_node, &cpus_node,
                                           &options_node) != 0) {
            h2o_configurator_errprintf(cmd, *if_node, "busy-poll-map interface block at index %d is invalid\n", i);
            return -1;
        }
        h2o_configurator_scanf(cmd, *index_node, "%zu", &nic->ifindex);

        char iface[IF_NAMESIZE] = {0};
        if (!if_indextoname(nic->ifindex, iface)) {
            h2o_configurator_errprintf(cmd, *if_node, "busy-poll-map interface index %zu is invalid\n", nic->ifindex);
            return -1;
        }
        nic->iface = h2o_strdup(NULL, iface, SIZE_MAX);

        pthread_mutex_init(&nic->mutex, NULL);
        nic->cpu_count = 0;
        CPU_ZERO(&nic->cpu_map);
        for (int j = 0; j < (*cpus_node)->data.sequence.size; j++) {
            yoml_t *cpu_node = (*cpus_node)->data.sequence.elements[j];
            if (cpu_node->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, cpu_node, "cpu specified for iface %s is not a scalar\n", nic->iface.base);
                return -1;
            }
            unsigned cpu_num;
            if (h2o_configurator_scanf(cmd, cpu_node, "%u", &cpu_num) == 0)
                CPU_SET(cpu_num, &nic->cpu_map);
        }
        nic->cpu_count = CPU_COUNT(&nic->cpu_map);
        h2o_vector_reserve(NULL, &nic->napi_ids, nic->cpu_count);
        for (int j = 0; j < nic->cpu_count; j++) {
            nic->napi_ids.entries[j] = 0;
        }
        nic->napi_ids.size = nic->cpu_count;

        yoml_t **mode_node = NULL, **gro_node = NULL, **irq_node = NULL, **st_node = NULL;
        if (h2o_configurator_parse_mapping(cmd, *options_node, "mode:s", "gro-flush-timeout:s,defer-hard-irqs:s,suspend-timeout:s",
                                           &mode_node, &gro_node, &irq_node, &st_node) != 0) {
            h2o_configurator_errprintf(cmd, *if_node, "busy-poll-map interface block at index %d has invalid options\n", i);
            return -1;
        }
        switch (h2o_configurator_get_one_of(cmd, *mode_node, "OFF,SUSPEND,BUSYPOLL")) {
        case 0:
            nic->mode = BP_MODE_OFF;
            break;
        case 1:
            nic->mode = BP_MODE_SUSPEND;
            break;
        case 2:
            nic->mode = BP_MODE_BUSYPOLL;
            break;
        default:
            return -1;
        }

        nic->options.gro_flush_timeout = 0;
        nic->options.defer_hard_irqs = 0;
        nic->options.suspend_timeout = 0;
        if (gro_node) {
            h2o_configurator_scanf(cmd, *gro_node, "%zu", &nic->options.gro_flush_timeout);
        }
        if (irq_node) {
            h2o_configurator_scanf(cmd, *irq_node, "%zu", &nic->options.defer_hard_irqs);
        }
        if (st_node && nic->mode == BP_MODE_SUSPEND) {
            h2o_configurator_scanf(cmd, *st_node, "%zu", &nic->options.suspend_timeout);
        }

        fprintf(stderr, " ifindex %zu has %zd cpus\n", nic->ifindex, nic->cpu_count);
    }

    /* setup queues */
    for (int i = 0; i != nic_count; ++i) {
        struct busypoll_nic_t *nic = &nic_to_cpu_map->entries[i];
        if (nic->mode != BP_MODE_OFF) {
            h2o_busypoll_set_opts(nic);
        }
    }

    return 0;
#else
    h2o_configurator_errprintf(cmd, node, "support for epoll busypolling is not available");
    return -1;
#endif
}

