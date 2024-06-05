/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "options.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "printc.hh"

namespace ghidra {

ElementId ELEM_ALIASBLOCK = ElementId("aliasblock",174);
ElementId ELEM_ALLOWCONTEXTSET = ElementId("allowcontextset",175);
ElementId ELEM_ANALYZEFORLOOPS = ElementId("analyzeforloops",176);
ElementId ELEM_COMMENTHEADER = ElementId("commentheader",177);
ElementId ELEM_COMMENTINDENT = ElementId("commentindent",178);
ElementId ELEM_COMMENTINSTRUCTION = ElementId("commentinstruction",179);
ElementId ELEM_COMMENTSTYLE = ElementId("commentstyle",180);
ElementId ELEM_CONVENTIONPRINTING = ElementId("conventionprinting",181);
ElementId ELEM_CURRENTACTION = ElementId("currentaction",182);
ElementId ELEM_DEFAULTPROTOTYPE = ElementId("defaultprototype",183);
ElementId ELEM_ERRORREINTERPRETED = ElementId("errorreinterpreted",184);
ElementId ELEM_ERRORTOOMANYINSTRUCTIONS = ElementId("errortoomanyinstructions",185);
ElementId ELEM_ERRORUNIMPLEMENTED = ElementId("errorunimplemented",186);
ElementId ELEM_EXTRAPOP = ElementId("extrapop",187);
ElementId ELEM_IGNOREUNIMPLEMENTED = ElementId("ignoreunimplemented",188);
ElementId ELEM_INDENTINCREMENT = ElementId("indentincrement",189);
ElementId ELEM_INFERCONSTPTR = ElementId("inferconstptr",190);
ElementId ELEM_INLINE = ElementId("inline",191);
ElementId ELEM_INPLACEOPS = ElementId("inplaceops",192);
ElementId ELEM_INTEGERFORMAT = ElementId("integerformat",193);
ElementId ELEM_JUMPLOAD = ElementId("jumpload",194);
ElementId ELEM_MAXINSTRUCTION = ElementId("maxinstruction",195);
ElementId ELEM_MAXLINEWIDTH = ElementId("maxlinewidth",196);
ElementId ELEM_NAMESPACESTRATEGY = ElementId("namespacestrategy",197);
ElementId ELEM_NOCASTPRINTING = ElementId("nocastprinting",198);
ElementId ELEM_NORETURN = ElementId("noreturn",199);
ElementId ELEM_NULLPRINTING = ElementId("nullprinting",200);
ElementId ELEM_OPTIONSLIST = ElementId("optionslist",201);
ElementId ELEM_PARAM1 = ElementId("param1",202);
ElementId ELEM_PARAM2 = ElementId("param2",203);
ElementId ELEM_PARAM3 = ElementId("param3",204);
ElementId ELEM_PROTOEVAL = ElementId("protoeval",205);
ElementId ELEM_SETACTION = ElementId("setaction",206);
ElementId ELEM_SETLANGUAGE = ElementId("setlanguage",207);
ElementId ELEM_SPLITDATATYPE = ElementId("splitdatatype",270);
ElementId ELEM_STRUCTALIGN = ElementId("structalign",208);
ElementId ELEM_TOGGLERULE = ElementId("togglerule",209);
ElementId ELEM_WARNING = ElementId("warning",210);
ElementId ELEM_JUMPTABLEMAX = ElementId("jumptablemax",271);
ElementId ELEM_NANIGNORE = ElementId("nanignore",272);
ElementId ELEM_BRACEFORMAT = ElementId("braceformat",284);

/// If the parameter is "on" return \b true, if "off" return \b false.
/// Any other value causes an exception.
/// \param p is the parameter
/// \return the parsed boolean value
bool ArchOption::onOrOff(const string &p)

{
  if (p.size()==0)
    return true;
  if (p == "on")
    return true;
  if (p == "off")
    return false;
  throw ParseError("Must specify toggle value, on/off");
}

/// To facilitate command parsing, enter the new ArchOption instance into
/// the map based on its name
/// \param option is the new ArchOption instance
void OptionDatabase::registerOption(ArchOption *option)

{
  uint4 id = ElementId::find(option->getName(),0);	// Option name must match a known element name
  optionmap[id] = option;
}

/// Register all possible ArchOption objects with this database and set-up the parsing map.
/// \param g is the Architecture owning \b this database
OptionDatabase::OptionDatabase(Architecture *g)

{
  glb = g;
  registerOption(new OptionExtraPop());
  registerOption(new OptionReadOnly());
  registerOption(new OptionIgnoreUnimplemented());
  registerOption(new OptionErrorUnimplemented());
  registerOption(new OptionErrorReinterpreted());
  registerOption(new OptionErrorTooManyInstructions());
  registerOption(new OptionDefaultPrototype());
  registerOption(new OptionInferConstPtr());
  registerOption(new OptionForLoops());
  registerOption(new OptionInline());
  registerOption(new OptionNoReturn());
  registerOption(new OptionProtoEval());
  registerOption(new OptionWarning());
  registerOption(new OptionNullPrinting());
  registerOption(new OptionInPlaceOps());
  registerOption(new OptionConventionPrinting());
  registerOption(new OptionNoCastPrinting());
  registerOption(new OptionMaxLineWidth());
  registerOption(new OptionIndentIncrement());
  registerOption(new OptionCommentIndent());
  registerOption(new OptionCommentStyle());
  registerOption(new OptionCommentHeader());
  registerOption(new OptionCommentInstruction());
  registerOption(new OptionIntegerFormat());
  registerOption(new OptionBraceFormat());
  registerOption(new OptionCurrentAction());
  registerOption(new OptionAllowContextSet());
  registerOption(new OptionSetAction());
  registerOption(new OptionSetLanguage());
  registerOption(new OptionJumpTableMax());
  registerOption(new OptionJumpLoad());
  registerOption(new OptionToggleRule());
  registerOption(new OptionAliasBlock());
  registerOption(new OptionMaxInstruction());
  registerOption(new OptionNamespaceStrategy());
  registerOption(new OptionSplitDatatypes());
  registerOption(new OptionNanIgnore());
}

OptionDatabase::~OptionDatabase(void)

{
  map<uint4,ArchOption *>::iterator iter;
  for(iter=optionmap.begin();iter!=optionmap.end();++iter)
    delete (*iter).second;
}

/// Perform an \e option \e command directly, given its id and optional parameters
/// \param nameId is the id of the option
/// \param p1 is the first optional parameter
/// \param p2 is the second optional parameter
/// \param p3 is the third optional parameter
/// \return the confirmation/failure method after trying to apply the option
string OptionDatabase::set(uint4 nameId,const string &p1,const string &p2,const string &p3)

{
  map<uint4,ArchOption *>::const_iterator iter;
  iter = optionmap.find(nameId);
  if (iter == optionmap.end())
    throw ParseError("Unknown option");
  ArchOption *opt = (*iter).second;
  return opt->apply(glb,p1,p2,p3);
}

/// Scan the name and optional parameters and call method set()
/// \param decoder is the stream decoder
void OptionDatabase::decodeOne(Decoder &decoder)

{
  string p1,p2,p3;

  uint4 elemId = decoder.openElement();
  uint4 subId = decoder.openElement();
  if (subId == ELEM_PARAM1) {
    p1 = decoder.readString(ATTRIB_CONTENT);
    decoder.closeElement(subId);
    subId = decoder.openElement();
    if (subId == ELEM_PARAM2) {
      p2 = decoder.readString(ATTRIB_CONTENT);
      decoder.closeElement(subId);
      subId = decoder.openElement();
      if (subId == ELEM_PARAM3) {
	p3 = decoder.readString(ATTRIB_CONTENT);
	decoder.closeElement(subId);
      }
    }
  }
  else if (subId == 0)
    p1 = decoder.readString(ATTRIB_CONTENT);	// If no children, content is param 1
  decoder.closeElement(elemId);
  set(elemId,p1,p2,p3);
}

/// Parse an \<optionslist> element, treating each child as an \e option \e command.
/// \param decoder is the stream decoder
void OptionDatabase::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_OPTIONSLIST);

  while(decoder.peekElement() != 0)
    decodeOne(decoder);
  decoder.closeElement(elemId);
}

/// \class OptionExtraPop
/// \brief Set the \b extrapop parameter used by the (default) prototype model.
///
/// The \b extrapop for a function is the number of bytes popped from the stack that
/// a calling function can assume when this function is called.
///
/// The first parameter is the integer value to use as the \e extrapop, or the special
/// value "unknown" which triggers the \e extrapop recovery analysis.
///
/// The second parameter, if present, indicates a specific function to modify. Otherwise,
/// the default prototype model is modified.
string OptionExtraPop::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  int4 expop = -300;
  string res;
  if (p1 == "unknown")
    expop = ProtoModel::extrapop_unknown;
  else {
    istringstream s1(p1);
    s1.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
    s1 >> expop;
  }
  if (expop == -300)
    throw ParseError("Bad extrapop adjustment parameter");
  if (p2.size() != 0) {
    Funcdata *fd;
    fd = glb->symboltab->getGlobalScope()->queryFunction( p2 );
    if (fd == (Funcdata *)0)
      throw RecovError("Unknown function name: "+p2);
    fd->getFuncProto().setExtraPop(expop);
    res = "ExtraPop set for function "+p2;
  }
  else {
    glb->defaultfp->setExtraPop(expop);
    if (glb->evalfp_current != (ProtoModel *)0)
      glb->evalfp_current->setExtraPop(expop);
    if (glb->evalfp_called != (ProtoModel *)0)
      glb->evalfp_called->setExtraPop(expop);
    res = "Global extrapop set";
  }
  return res;
}

/// \class OptionReadOnly
/// \brief Toggle whether read-only memory locations have their value propagated
///
/// Setting this to "on", causes the decompiler to treat read-only memory locations as
/// constants that can be propagated.
string OptionReadOnly::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size()==0)
    throw ParseError("Read-only option must be set \"on\" or \"off\"");
  glb->readonlypropagate = onOrOff(p1);
  if (glb->readonlypropagate)
    return "Read-only memory locations now propagate as constants";
  return "Read-only memory locations now do not propagate";
}

/// \class OptionDefaultPrototype
/// \brief Set the default prototype model for analyzing unknown functions
///
/// The first parameter must give the name of a registered prototype model.
string OptionDefaultPrototype::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  ProtoModel *model = glb->getModel(p1);
  if (model == (ProtoModel *)0)
    throw LowlevelError("Unknown prototype model :" + p1);
  glb->setDefaultModel(model);
  return "Set default prototype to "+p1;
}

/// \class OptionInferConstPtr
/// \brief Toggle whether the decompiler attempts to infer constant pointers
///
/// Setting the first parameter to "on" causes the decompiler to check if unknown
/// constants look like a reference to a known symbol's location.
string OptionInferConstPtr::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Constant pointers are now inferred";
    glb->infer_pointers = true;
  }
  else {
    res = "Constant pointers must now be set explicitly";
    glb->infer_pointers = false;
  }
  return res;
}

/// \class OptionForLoops
/// \brief Toggle whether the decompiler attempts to recover \e for-loop variables
///
/// Setting the first parameter to "on" causes the decompiler to search for a suitable loop variable
/// controlling iteration of a \e while-do block.  The \e for-loop displays the following on a single line:
///    - loop variable initializer (optional)
///    - loop condition
///    - loop variable incrementer
///
string OptionForLoops::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  glb->analyze_for_loops = onOrOff(p1);

  string res = "Recovery of for-loops is " + p1;
  return res;
}

/// \class OptionInline
/// \brief Mark/unmark a specific function as \e inline
///
/// The first parameter gives the symbol name of a function. The second parameter is
/// true" to set the \e inline property, "false" to clear.
string OptionInline::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  Funcdata *infd = glb->symboltab->getGlobalScope()->queryFunction( p1 );
  if (infd == (Funcdata *)0)
    throw RecovError("Unknown function name: "+p1);
  bool val;
  if (p2.size()==0)
    val = true;
  else
    val = (p2 == "true");
  infd->getFuncProto().setInline(val);
  string prop;
  if (val)
    prop = "true";
  else
    prop = "false";
  string res = "Inline property for function "+p1+" = "+prop;
  return res;
}

/// \class OptionNoReturn
/// \brief Mark/unmark a specific function with the \e noreturn property
///
/// The first parameter is the symbol name of the function. The second parameter
/// is "true" to enable the \e noreturn property, "false" to disable.
string OptionNoReturn::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  Funcdata *infd = glb->symboltab->getGlobalScope()->queryFunction( p1 );
  if (infd == (Funcdata *)0)
    throw RecovError("Unknown function name: "+p1);
  bool val;
  if (p2.size()==0)
    val = true;
  else
    val = (p2 == "true");
  infd->getFuncProto().setNoReturn(val);
  string prop;
  if (val)
    prop = "true";
  else
    prop = "false";
  string res = "No return property for function "+p1+" = "+prop;
  return res;
}

/// \class OptionWarning
/// \brief Toggle whether a warning should be issued if a specific action/rule is applied.
///
/// The first parameter gives the name of the Action or RuleAction.  The second parameter
/// is "on" to turn on warnings, "off" to turn them off.
string OptionWarning::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size()==0)
    throw ParseError("No action/rule specified");
  bool val;
  if (p2.size()==0)
    val = true;
  else
    val = onOrOff(p2);
  bool res = glb->allacts.getCurrent()->setWarning(val,p1);
  if (!res)
    throw RecovError("Bad action/rule specifier: "+p1);
  string prop;
  prop = val ? "on" : "off";
  return "Warnings for "+p1+" turned "+prop;
}

/// \class OptionNullPrinting
/// \brief Toggle whether null pointers should be printed as the string "NULL"
string OptionNullPrinting::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  if (glb->print->getName() != "c-language")
    return "Only c-language accepts the null printing option";
  PrintC *lng = (PrintC *)glb->print;
  lng->setNULLPrinting(val);
  string prop;
  prop = val ? "on" : "off";
  return "Null printing turned "+prop;
}

/// \class OptionInPlaceOps
/// \brief Toggle whether \e in-place operators (+=, *=, &=, etc.) are emitted by the decompiler
string OptionInPlaceOps::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  if (glb->print->getName() != "c-language")
    return "Can only set inplace operators for C language";
  PrintC *lng = (PrintC *)glb->print;
  lng->setInplaceOps(val);
  string prop;
  prop = val ? "on" : "off";
  return "Inplace operators turned "+prop;
}

/// \class OptionConventionPrinting
/// \brief Toggle whether the \e calling \e convention is printed when emitting function prototypes
string OptionConventionPrinting::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  if (glb->print->getName() != "c-language")
    return "Can only set convention printing for C language";
  PrintC *lng = (PrintC *)glb->print;
  lng->setConvention(val);
  string prop;
  prop = val ? "on" : "off";
  return "Convention printing turned "+prop;
}

/// \class OptionNoCastPrinting
/// \brief Toggle whether \e cast syntax is emitted by the decompiler or stripped
string OptionNoCastPrinting::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  PrintC *lng = dynamic_cast<PrintC *>(glb->print);
  if (lng == (PrintC *)0)
    return "Can only set no cast printing for C language";
  lng->setNoCastPrinting(val);
  string prop;
  prop = val ? "on" : "off";
  return "No cast printing turned "+prop;
}

/// \class OptionHideExtensions
/// \brief Toggle whether implied extensions (ZEXT or SEXT) are printed
string OptionHideExtensions::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);
  PrintC *lng = dynamic_cast<PrintC *>(glb->print);
  if (lng == (PrintC *)0)
    return "Can only toggle extension hiding for C language";
  lng->setHideImpliedExts(val);
  string prop;
  prop = val ? "on" : "off";
  return "Implied extension hiding turned "+prop;
}

/// \class OptionMaxLineWidth
/// \brief Set the maximum number of characters per decompiled line
///
/// The first parameter is an integer value passed to the pretty printer as the maximum
/// number of characters to emit in a single line before wrapping.
string OptionMaxLineWidth::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  istringstream s(p1);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  int4 val = -1;
  s >> val;
  if (val==-1)
    throw ParseError("Must specify integer linewidth");
  glb->print->setMaxLineSize(val);
  return "Maximum line width set to "+p1;
}

/// \class OptionIndentIncrement
/// \brief Set the number of characters to indent per nested scope.
///
/// The first parameter is the integer value specifying how many characters to indent.
string OptionIndentIncrement::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  istringstream s(p1);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  int4 val = -1;
  s >> val;
  if (val==-1)
    throw ParseError("Must specify integer increment");
  glb->print->setIndentIncrement(val);
  return "Characters per indent level set to "+p1;
}

/// \class OptionCommentIndent
/// \brief How many characters to indent comment lines.
///
/// The first parameter gives the integer value.  Comment lines are indented this much independent
/// of the associated code's nesting depth.
string OptionCommentIndent::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  istringstream s(p1);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  int4 val = -1;
  s >> val;
  if (val==-1)
    throw ParseError("Must specify integer comment indent");
  glb->print->setLineCommentIndent(val);
  return "Comment indent set to "+p1;
}

/// \class OptionCommentStyle
/// \brief Set the style of comment emitted by the decompiler
///
/// The first parameter is either "c", "cplusplus", a string starting with "/*", or a string starting with "//"
string OptionCommentStyle::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  glb->print->setCommentStyle(p1);
  return "Comment style set to "+p1;
}

/// \class OptionCommentHeader
/// \brief Toggle whether different comment \e types are emitted by the decompiler in the header for a function
///
/// The first parameter specifies the comment type: "header" and "warningheader"
/// The second parameter is the toggle value "on" or "off".
string OptionCommentHeader::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool toggle = onOrOff(p2);
  uint4 flags = glb->print->getHeaderComment();
  uint4 val = Comment::encodeCommentType(p1);
  if (toggle)
    flags |= val;
  else
    flags &= ~val;
  glb->print->setHeaderComment(flags);
  string prop;
  prop = toggle ? "on" : "off";
  return "Header comment type "+p1+" turned "+prop;
}

/// \class OptionCommentInstruction
/// \brief Toggle whether different comment \e types are emitted by the decompiler in the body of a function
///
/// The first parameter specifies the comment type: "warning", "user1", "user2", etc.
/// The second parameter is the toggle value "on" or "off".
string OptionCommentInstruction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool toggle = onOrOff(p2);
  uint4 flags = glb->print->getInstructionComment();
  uint4 val = Comment::encodeCommentType(p1);
  if (toggle)
    flags |= val;
  else
    flags &= ~val;
  glb->print->setInstructionComment(flags);
  string prop;
  prop = toggle ? "on" : "off";
  return "Instruction comment type "+p1+" turned "+prop;
}

/// \class OptionIntegerFormat
/// \brief Set the formatting strategy used by the decompiler to emit integers
///
/// The first parameter is the strategy name: "hex", "dec", or "best"
string OptionIntegerFormat::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  glb->print->setIntegerFormat(p1);
  return "Integer format set to "+p1;
}

/// \class OptionBraceFormat
/// \brief Set the brace formatting strategy for various types of code block
///
/// The first parameter is the strategy name:
///   - \b same  - For an opening brace on the same line
///   - \b next  - For an opening brace on the next line
///   - \b skip  - For an opening brace after a blank line
///
/// The second parameter is the type of code block:
///   - \b function - For the main function body
///   - \b ifelse   - For if/else blocks
///   - \b loop     - For do/while/for loop blocks
///   - \b switch   - For a switch block
string OptionBraceFormat::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  PrintC *lng = dynamic_cast<PrintC *>(glb->print);
  if (lng == (PrintC *)0)
    return "Can only set brace formatting for C language";
  Emit::brace_style style;
  if (p2 == "same")
    style = Emit::same_line;
  else if (p2 == "next")
    style = Emit::next_line;
  else if (p2 == "skip")
    style = Emit::skip_line;
  else
    throw ParseError("Unknown brace style: "+p2);
  if (p1 == "function")
    lng->setBraceFormatFunction(style);
  else if (p1 == "ifelse")
    lng->setBraceFormatIfElse(style);
  else if (p1 == "loop")
    lng->setBraceFormatLoop(style);
  else if (p1 == "switch")
    lng->setBraceFormatSwitch(style);
  else
    throw ParseError("Unknown brace format category: "+p1);
  return "Brace formatting for " + p1 + " set to " + p2;
}

/// \class OptionSetAction
/// \brief Establish a new root Action for the decompiler
///
/// The first parameter specifies the name of the root Action. If a second parameter
/// is given, it specifies the name of a new root Action, which  is created by copying the
/// Action specified with the first parameter.  In this case, the current root Action is
/// set to the new copy, which can then by modified
string OptionSetAction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size()==0)
    throw ParseError("Must specify preexisting action");

  if (p2.size() != 0) {
    glb->allacts.cloneGroup(p1,p2);
    glb->allacts.setCurrent(p2);
    return "Created "+p2+" by cloning "+p1+" and made it current";
  }
  glb->allacts.setCurrent(p1);
  return "Set current action to "+p1;
}

/// \class OptionCurrentAction
/// \brief Toggle a sub-group of actions within a root Action
///
/// If two parameters are given, the first indicates the name of the sub-group, and the second is
/// the toggle value, "on" or "off". The change is applied to the current root Action.
///
/// If three parameters are given, the first indicates the root Action (which will be set as current)
/// to modify. The second and third parameters give the name of the sub-group and the toggle value.
string OptionCurrentAction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if ((p1.size()==0)||(p2.size()==0))
    throw ParseError("Must specify subaction, on/off");
  bool val;
  string res = "Toggled ";

  if (p3.size() != 0) {
    glb->allacts.setCurrent(p1);
    val = onOrOff(p3);
    glb->allacts.toggleAction(p1,p2,val);
    res += p2 + " in action "+p1;
  }
  else {
    val = onOrOff(p2);
    glb->allacts.toggleAction(glb->allacts.getCurrentName(),p1,val);
    res += p1 + " in action "+glb->allacts.getCurrentName();
  }

  return res;
}

/// \class OptionAllowContextSet
/// \brief Toggle whether the disassembly engine is allowed to modify context
///
/// If the first parameter is "on", disassembly can make changes to context
string OptionAllowContextSet::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string prop = val ? "on" : "off";
  string res = "Toggled allowcontextset to "+prop;
  glb->translate->allowContextSet(val);

  return res;
}

/// \class OptionIgnoreUnimplemented
/// \brief Toggle whether unimplemented instructions are treated as a \e no-operation
///
/// If the first parameter is "on", unimplemented instructions are ignored, otherwise
/// they are treated as an artificial \e halt in the control flow.
string OptionIgnoreUnimplemented::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Unimplemented instructions are now ignored (treated as nop)";
    glb->flowoptions |= FlowInfo::ignore_unimplemented;
  }
  else {
    res = "Unimplemented instructions now generate warnings";
    glb->flowoptions &= ~((uint4)FlowInfo::ignore_unimplemented);
  }

  return res;
}

/// \class OptionErrorUnimplemented
/// \brief Toggle whether unimplemented  instructions are treated as a fatal error.
///
/// If the first parameter is "on", decompilation of functions with unimplemented instructions
/// will terminate with a fatal error message. Otherwise, warning comments will be generated.
string OptionErrorUnimplemented::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Unimplemented instructions are now a fatal error";
    glb->flowoptions |= FlowInfo::error_unimplemented;
  }
  else {
    res = "Unimplemented instructions now NOT a fatal error";
    glb->flowoptions &= ~((uint4)FlowInfo::error_unimplemented);
  }

  return res;
}

/// \class OptionErrorReinterpreted
/// \brief Toggle whether off-cut reinterpretation of an instruction is a fatal error
///
/// If the first parameter is "on", interpreting the same code bytes at two or more different
/// \e cuts, during disassembly, is considered a fatal error.
string OptionErrorReinterpreted::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Instruction reinterpretation is now a fatal error";
    glb->flowoptions |= FlowInfo::error_reinterpreted;
  }
  else {
    res = "Instruction reinterpretation is now NOT a fatal error";
    glb->flowoptions &= ~((uint4)FlowInfo::error_reinterpreted);
  }

  return res;
}
/// \class OptionErrorTooManyInstructions
/// \brief Toggle whether too many instructions in one function body is considered a fatal error.
///
/// If the first parameter is "on" and the number of instructions in a single function body exceeds
/// the threshold, then decompilation will halt for that function with a fatal error. Otherwise,
/// artificial halts are generated to prevent control-flow into further instructions.
string OptionErrorTooManyInstructions::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Too many instructions are now a fatal error";
    glb->flowoptions |= FlowInfo::error_toomanyinstructions;
  }
  else {
    res = "Too many instructions are now NOT a fatal error";
    glb->flowoptions &= ~((uint4)FlowInfo::error_toomanyinstructions);
  }

  return res;
}

/// \class OptionProtoEval
/// \brief Set the prototype model to use when evaluating the parameters of the \e current function
///
/// The first parameter gives the name of the prototype model. The string "default" can be given
/// to refer to the format \e default model for the architecture. The specified model is used to
/// evaluate parameters of the function actively being decompiled, which may be distinct from the
/// model used to evaluate sub-functions.
string OptionProtoEval::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  ProtoModel *model = (ProtoModel *)0;
  
  if (p1.size()==0)
    throw ParseError("Must specify prototype model");

  if (p1 == "default")
    model = glb->defaultfp;
  else {
    model = glb->getModel(p1);
    if (model == (ProtoModel *)0)
      throw ParseError("Unknown prototype model: "+p1);
  }
  string res = "Set current evaluation to " + p1;
  glb->evalfp_current = model;
  return res;
}

/// \class OptionSetLanguage
/// \brief Set the current language emitted by the decompiler
///
/// The first specifies the name of the language to emit: "c-language", "java-language", etc.
string OptionSetLanguage::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  string res;

  glb->setPrintLanguage(p1);
  res = "Decompiler produces "+p1;
  return res;
}

/// \class OptionJumpTableMax
/// \brief Set the maximum number of entries that can be recovered for a single jump table
///
/// This option is an unsigned integer value used during analysis of jump tables.  It serves as a
/// sanity check that the recovered number of entries for a jump table is reasonable and
/// also acts as a resource limit on the number of destination addresses that analysis will attempt
/// to follow from a single indirect jump.
string OptionJumpTableMax::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  istringstream s(p1);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  uint4 val = 0;
  s >> val;
  if (val==0)
    throw ParseError("Must specify integer maximum");
  glb->max_jumptable_size = val;
  return "Maximum jumptable size set to "+p1;
}

/// \class OptionJumpLoad
/// \brief Toggle whether the decompiler should try to recover the table used to evaluate a switch
///
/// If the first parameter is "on", the decompiler will record the memory locations with constant values
/// that were accessed as part of the jump-table so that they can be formally labeled.
string OptionJumpLoad::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool val = onOrOff(p1);

  string res;
  if (val) {
    res = "Jumptable analysis will record loads required to calculate jump address";
    glb->flowoptions |= FlowInfo::record_jumploads;
  }
  else {
    res = "Jumptable analysis will NOT record loads";
    glb->flowoptions &= ~((uint4)FlowInfo::record_jumploads);
  }
  return res;
}

/// \class OptionToggleRule
/// \brief Toggle whether a specific Rule is applied in the current Action
///
/// The first parameter must be a name \e path describing the unique Rule instance
/// to be toggled.  The second parameter is "on" to \e enable the Rule, "off" to \e disable.
string OptionToggleRule::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size() == 0)
    throw ParseError("Must specify rule path");
  if (p2.size() == 0)
    throw ParseError("Must specify on/off");
  bool val = onOrOff(p2);

  Action *root = glb->allacts.getCurrent();
  if (root == (Action *)0)
    throw LowlevelError("Missing current action");
  string res;
  if (!val) {
    if (root->disableRule(p1))
      res = "Successfully disabled";
    else
      res = "Failed to disable";
    res += " rule";
  }
  else {
    if (root->enableRule(p1))
      res = "Successfully enabled";
    else
      res = "Failed to enable";
    res += " rule";
  }
  return res;
}

/// \class OptionAliasBlock
/// \brief Set how locked data-types on the stack affect alias heuristics
///
/// Stack analysis uses the following simple heuristic: a pointer is unlikely to reference (alias)
/// a stack location if there is a locked data-type between the pointer base and the location.
/// This option determines what kind of locked data-types \b block aliases in this way.
///   - none - no data-types will block an alias
///   - struct - only structure data-types will block an alias
///   - array - array data-types (and structure data-types) will block an alias
///   - all - all locked data-types will block an alias
string OptionAliasBlock::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size() == 0)
    throw ParseError("Must specify alias block level");
  int4 oldVal = glb->alias_block_level;
  if (p1 == "none")
    glb->alias_block_level = 0;
  else if (p1 == "struct")
    glb->alias_block_level = 1;
  else if (p1 == "array")
    glb->alias_block_level = 2;		// The default. Let structs and arrays block aliases
  else if (p1 == "all")
    glb->alias_block_level = 3;
  else
    throw ParseError("Unknown alias block level: "+p1);
  if (oldVal == glb->alias_block_level)
    return "Alias block level unchanged";
  return "Alias block level set to " + p1;
}

/// \class OptionMaxInstruction
/// \brief Maximum number of instructions that can be processed in a single function
///
/// The first parameter is an integer specifying the maximum.
string OptionMaxInstruction::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  if (p1.size() == 0)
    throw ParseError("Must specify number of instructions");

  int4 newMax = -1;
  istringstream s1(p1);
  s1.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  s1 >> newMax;
  if (newMax < 0)
    throw ParseError("Bad maxinstruction parameter");
  glb->max_instructions = newMax;
  return "Maximum instructions per function set";
}

/// \class OptionNamespaceStrategy
/// \brief How should namespace tokens be displayed
///
/// The first parameter gives the strategy identifier, mapping to PrintLanguage::namespace_strategy.
string OptionNamespaceStrategy::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  PrintLanguage::namespace_strategy strategy;
  if (p1 == "minimal")
    strategy = PrintLanguage::MINIMAL_NAMESPACES;
  else if (p1 == "all")
    strategy = PrintLanguage::ALL_NAMESPACES;
  else if (p1 == "none")
    strategy = PrintLanguage::NO_NAMESPACES;
  else
    throw ParseError("Must specify a valid strategy");
  glb->print->setNamespaceStrategy(strategy);
  return "Namespace strategy set";
}

/// Possible value are:
///   - (empty string) = 0
///   - "struct"       = 1
///   - "array"        = 2
///   - "pointer"     = 4
///
/// \param val is the option string
/// \return the corresponding configuration bit
uint4 OptionSplitDatatypes::getOptionBit(const string &val)

{
  if (val.size() == 0) return 0;
  if (val == "struct") return option_struct;
  if (val == "array") return option_array;
  if (val == "pointer") return option_pointer;
  throw LowlevelError("Unknown data-type split option: "+val);
}

/// \class OptionSplitDatatypes
/// \brief Control which data-type assignments are split into multiple COPY/LOAD/STORE operations
///
/// Any combination of the three options can be given:
///   - "struct"  = Divide structure data-types into separate field assignments
///   - "array"   = Divide array data-types into separate element assignments
///   - "pointer" = Divide assignments, via LOAD/STORE, through pointers
string OptionSplitDatatypes::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  uint4 oldConfig = glb->split_datatype_config;
  glb->split_datatype_config = getOptionBit(p1);
  glb->split_datatype_config |= getOptionBit(p2);
  glb->split_datatype_config |= getOptionBit(p3);

  if ((glb->split_datatype_config & (option_struct | option_array)) == 0) {
    glb->allacts.toggleAction(glb->allacts.getCurrentName(),"splitcopy",false);
    glb->allacts.toggleAction(glb->allacts.getCurrentName(),"splitpointer",false);
  }
  else {
    bool pointers = (glb->split_datatype_config & option_pointer) != 0;
    glb->allacts.toggleAction(glb->allacts.getCurrentName(),"splitcopy",true);
    glb->allacts.toggleAction(glb->allacts.getCurrentName(),"splitpointer",pointers);
  }

  if (oldConfig == glb->split_datatype_config)
    return "Split data-type configuration unchanged";
  return "Split data-type configuration set";
}

/// \class OptionNanIgnore
/// \brief Which Not a Number (NaN) operations should be ignored
///
/// The option controls which p-code NaN operations are replaced with a \b false constant, assuming
/// the input is a valid floating-point value.
///   - "none"  = No operations are replaced
///   - "compare" = Replace NaN operations associated with floating-poing comparisons
///   - "all" = Replace all NaN operations
string OptionNanIgnore::apply(Architecture *glb,const string &p1,const string &p2,const string &p3) const

{
  bool oldIgnoreAll = glb->nan_ignore_all;
  bool oldIgnoreCompare = glb->nan_ignore_compare;

  if (p1 == "none") {			// Don't ignore any NaN operation
    glb->nan_ignore_all = false;
    glb->nan_ignore_compare = false;
  }
  else if (p1 == "compare") {		// Ignore only NaN operations protecting floating-point comparisons
    glb->nan_ignore_all = false;
    glb->nan_ignore_compare = true;
  }
  else if (p1 == "all") {		// Ignore all NaN operations
    glb->nan_ignore_all = true;
    glb->nan_ignore_compare = true;
  }
  else {
    throw LowlevelError("Unknown nanignore option: "+p1);
  }
  Action *root = glb->allacts.getCurrent();
  if (!glb->nan_ignore_all && !glb->nan_ignore_compare) {
    root->disableRule("ignorenan");
  }
  else {
    root->enableRule("ignorenan");
  }
  if (oldIgnoreAll == glb->nan_ignore_all && oldIgnoreCompare == glb->nan_ignore_compare)
    return "NaN ignore configuration unchanged";
  return "Nan ignore configuration set to: " + p1;
}

} // End namespace ghidra
