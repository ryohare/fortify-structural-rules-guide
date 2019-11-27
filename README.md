# Custom Structural Based Rules Development
Structural and characterization rules utilize Fortify's query language for matching specific coding patterns in the AST. This post will work through methodology to develop these types of rules.

# Getting the Structural Tree
The first step in writing structural rules (usually) will be to get a dump of the structural tree to see what nodes we have to work with. This dump will be targetted to a specific line of code where the signature is to be written. Once found, the line number should be updated in the DumpLine.xml rules file. Once done, a fortify scan can be performed with a specific hidden flag enabled which will dump the structural tree at the specified location. **Multithreaded analysis must be disabled for this approach to work.** The code below shows who to do this.

```bash
# make a sample application - PoC only
echo "int main(){ printf(\"stuff\"); return 0;}" > test.c

# translate the code
sourceanalyzer -b test gcc test.c -c

# insert the line (1) into the dump rule file
# linux
cp DumpLine.xml DumpLine_1.xml
sed -i 's/LINE_NUMBER/1/g' DumpLine_1.xml

#mac
sed -i '' 's/LINE_NUMBER/1/g' DumpLine_1.xml

# dump the line
sourceanalyzer -b test -scan -no-default-rules -rules DumpLine_1.xml -D com.fortify.sca.MultithreadedAnalysis=false -Ddebug.dump-structural-tree 2> tree.tree 1>/dev/null
```

The above will result in the the creation of a structural tree file named tree.tree which will have all the structural tree primary nodes which occur at this line number. Remember, all these nodes are releated through the tree and from any individual node, one can traverse branches of the tree to reach any other node. **It is recommened to view the structural tree in VCCode because it will allow you to collapse nodes for quick browsing.**

# Building a Rule
Usually, the best way to develop a rule is to take the action or pivot being performed and relate other nodes on the tree. When the pivot is a `VariableAssignment` (`va`) the goal usually is to relate the left hand side (lhs) or source with a right hand side (rhs) or sink. With `FunctionCall` (`fa`) the goal usually is to relate arguments `fc.arguments[]` to either the object the function call is invoked on `fc.instance` or the function or class which invokes it `fc.encosingClass.name`, `fc.enclosingFunction` or object which it is being returned to `fc.enclosingStatement.lhs`.

Its worth noting that not all nodes are polymorphic and though they appear to be a descendent node on the dumped structural tree, fortify's strutural rule frontend will not accept the decendent node type in the rule. This sometimes happens when using a `AssignmentStatement` as a pivot. In such cases, it is usually advised to then start at the lowest branch of the AST at this line number and climb the tree to the pivot then back down the otherside.

# Real World Example
Lets develop some structural rules (and characterization rules) for a real application. This application sends a response to a receiver when run. It has a member `GetPrivateData()` which returns data which whould never leave the system. It also has a `SendResponse()` function which will send developer specified data to the receiver. Data is send in the structure `Response`. As part of the security model with this application, private data should never leave the system so there should never be data derived from `GetPrivateData` loaded into a `Response` object then sent via `SendResponse`. This sequence will cause a privacy violation in the system under question. The developer has implemented the code below.

```c++ {.lineNo}}
#include<iostream>
#include<cstring>

using namespace std;

class Response {
    public:
        std::string data;
};

// Get Private Data
extern std::string GetPrivateData();

// Send a response
extern void SendResponse(Response);

int main(){
    auto r = Response();
    r.data = GetPrivateData();
    SendResponse(r);
    return 0;
}
```
Cursory review by hand will find the obvious violation however we need to scale this for all developers now and there is only one of us!.
## Step 0 - Translate the code
Translate the code so we have the NSTs required to perform the scans and build the rule.
```bash
sourceanalyzer -b example g++ -c -std=c++11 example.cpp
```

## Step 1 - Identify start point
Looking a the code of main, no specific line of the code is a violation however the order of events and flow of data faciliates the violation. We can identify a start point here as being the call to `GetPrivateData()`. `GetPrivateData()` is AST type `FunctionCall` so now we know what node to look for. Now we need to grap this line number and dump the structural tree at this location and locate the `FunctionCall` node corresponding with `GetPrivateData()`.

**Get the tree**
```bash
# insert the line (1) into the dump rule file
# linux
LINE_NUM=19
cp DumpLine.xml DumpLine_$LINE_NUM.xml
sed -i "s/LINE_NUMBER/${LINE_NUM}/g" DumpLine_$LINE_NUM.xml

#mac
sed -i '' "s/LINE_NUMBER/${LINE_NUM}/g" DumpLine_$LINE_NUM.xml

# dump the line
sourceanalyzer -b example -scan -no-default-rules -rules DumpLine_$LINE_NUM.xml -D com.fortify.sca.MultithreadedAnalysis=false -Ddebug.dump-structural-tree 2> $LINE_NUM.tree 1>/dev/null
```

**Create the function call structural rule**
Save the rule file to example.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<RulePack xmlns="xmlns://www.fortifysoftware.com/schema/rules"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="RulePack">
    <RulePackID>4AEF134A-4C99-4431-A897-6F6663203903</RulePackID>
    <SKU>SKU-4AEF134A-4C99-4431-A897-6F6663203903</SKU>
    <Name><![CDATA[DumpLine.xml]]></Name>
    <Version>1.0</Version>
    <Description><![CDATA[Description for DumpLine.xml]]></Description>
    <Rules version="19.10">
        <RuleDefinitions>
            <StructuralRule formatVersion="19.10" language="cpp">
                <RuleID>224166A0-3461-4661-969E-918ED309AE34</RuleID>
                <VulnKingdom>PRIVATE</VulnKingdom>
                <VulnCategory>PRIVATE</VulnCategory>
                <VulnSubcategory>PRIVATE</VulnSubcategory>
                <DefaultSeverity>5.0</DefaultSeverity>
                <Description></Description>
                <Predicate><![CDATA[
                    FunctionCall fc:
                        fc.name contains "GetPrivateData"
                ]]></Predicate>
            </StructuralRule>
        </RuleDefinitions>
    </Rules>
</RulePack>
```
**Scan with the rule and see that we correctly find the node**
```bash
sourceanalyzer -b example -scan -no-default-rules -rules example.xml

[/Users/roha0001/workspace/fortify-customrules]

[A860ABD201362AF2DDB6A57D8BDA7FAE : critical : PRIVATE : PRIVATE : structural ]
    example.cpp(19)
```

This point point, we've found our start point.

## Step 2 - Relate to Another Node
With a start point, we can now start mapping relations to other nodes in the AST. One approach would be to say, any time private data is assigned to a Response object, a finding should be raised. In this case, we will attempt to relate the `FunctionCall` event to the `AssignmentStatement` where the rhs is type `Request`.