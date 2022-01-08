#! /bin/bash
# Generate a header file with an array of pairs {"MAC", "Vendor"} to be used
# for quicker vendor search in arpsniffer.

HEADER_FILE=oui_array.h
OUI_FILE=oui.txt

echo "const char *oui_array[][2] = {" > ${HEADER_FILE}

# Remove comments and empty lines
sed '/^#.*/d; /^$/d' ${OUI_FILE} |
# \042 is a quote symbol
awk '{ print "{\042"$1"\042, \042"$2"\042}," }' >> ${HEADER_FILE}

echo "};" >> ${HEADER_FILE}
