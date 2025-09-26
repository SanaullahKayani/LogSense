file="../output/nexus"
if [ -e $file ]
then
  echo "$file exists"
else
  mkdir -p $file
fi

file="../output/nexus/bert"
if [ -e $file ]
then
  echo "$file exists"
else
  mkdir -p $file
fi