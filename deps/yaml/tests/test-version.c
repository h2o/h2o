#include <yaml.h>

#include <stdlib.h>
#include <stdio.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

int
main(void)
{
    int major = -1;
    int minor = -1;
    int patch = -1;
    char buf[64];

    yaml_get_version(&major, &minor, &patch);
    sprintf(buf, "%d.%d.%d", major, minor, patch);
    assert(strcmp(buf, yaml_get_version_string()) == 0);

    /* Print structure sizes. */
    printf("sizeof(token) = %d\n", sizeof(yaml_token_t));
    printf("sizeof(event) = %d\n", sizeof(yaml_event_t));
    printf("sizeof(parser) = %d\n", sizeof(yaml_parser_t));

    return 0;
}
