#include <stdio.h>
#include <string.h>

#include "mac_vendor.h"
#include "oui_array.h"

#define PREFIX_LEN 8 /* First three octets and to colons */
#define PREFIX_FMT "%02X:%02X:%02X"
#define PREFIX_ARGS(_x) _x[0], _x[1], _x[2]
#define PREFIX_BROADCAST "00:00:00"

#define ARRAY_SIZE(_x) (sizeof(_x) / sizeof(_x[0]))

#define INDEX_MAC 0
#define INDEX_VENDOR 1

static const char *
search_oui_for_vendor(const char *prefix)
{
    size_t l = 0;
    size_t r = ARRAY_SIZE(oui_array);

    /*
     * We can use binary search since MACs in oui_array are sorted
     * lexicographically
     */
    while (r - l > 1)
    {
        size_t m = (r + l) / 2;
        int cmp_res = strcmp(oui_array[m][INDEX_MAC], prefix);

        if (cmp_res < 0)
            l = m;
        else if (cmp_res > 0)
            r = m;
        else
            return oui_array[m][INDEX_VENDOR];
    }

    return "Vendor not found";
}

const char *
get_vendor_by_mac(uint8_t *mac)
{
    char prefix[PREFIX_LEN + 1]; /* +1 for '\0' */

    snprintf(prefix, PREFIX_LEN, PREFIX_FMT, PREFIX_ARGS(mac));

    if (strcmp(prefix, PREFIX_BROADCAST) == 0)
        return "Broadcast";
    else
        return search_oui_for_vendor(prefix);
}
