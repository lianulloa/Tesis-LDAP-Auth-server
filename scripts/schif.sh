#!/bin/bash
# Version 1.0

# if  [ −z "$1" ]; then
# 	echo usage: $0 schema_name schema
# 	exit
# fi

touch $1".ldif"
echo "dn: cn=$1,cn=schema,cn=config" > $1".ldif"
echo "objectClass: olcSchemaConfig" >> $1".ldif"
echo "cn: $1" >> $1".ldif"


sed -re '/^\s*$/d' $2 >> $1".ldif"
sed -i -re 's/attributetype/olcAttributeTypes:/' $1".ldif"
sed -i -re 's/objectclass/olcObjectClasses:/' $1."ldif"
sed -i -re 's/\t/  /' $1."ldif"

exit
