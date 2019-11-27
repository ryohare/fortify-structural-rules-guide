# Custom Structural Based Rules Development
Structural and characterization rules utilize Fortify's query language for matching specific coding patterns in the AST. This post will work through methodology to develop these types of rules.

# Getting the Structural Tree
The first step in writing structural rules (usually) will be to get a dump of the structural tree to see what nodes we have to work with. This dump will be targetted to a specific line of code where the signature is to be written. Once found, the line number should be updated in the DumpLine.xml rules file. Once done, a fortify scan can be performed with a specific hidden flag enabled which will dump the structural tree at the specified location. The code below shows who to do this.

```bash
# make a sample application - PoC only
echo "int main(){ printf(\"stuff\"); return 0;}" > test.c

# translate the code
sourceanalyzer -b test gcc test.c -c

# insert the line into the dump rule file
sed -i 's/LINE_NUMBER/1/g' DumpLine.xml

# dump the line
sourceanalyzer -b terst

```